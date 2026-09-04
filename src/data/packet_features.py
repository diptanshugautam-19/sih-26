"""
src/data/packet_features.py

STAGE 1 (packet-level): Scapy-based extraction.

Responsibility boundary (READ THIS BEFORE EDITING):
    This module extracts RAW PER-PACKET fields only. It does NOT:
        - bucket packets into time windows       (that's windowing.py)
        - aggregate per-flow statistics           (that's flow_features.py / windowing.py)
        - decide window size or stride            (that's configs/default.yaml)
    Keeping this module window-agnostic means changing window size (2s/5s/10s
    ablations) never requires re-parsing PCAPs — only re-bucketing a DataFrame.

Output contract:
    extract_packet_features(pcap_path) -> pd.DataFrame
    One row per packet, columns:
        timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
        ttl, tcp_window, ip_frag_flag, payload_size,
        flag_syn, flag_ack, flag_fin, flag_rst, flag_psh, flag_urg,
        tcp_seq, tcp_ack, flow_key

    flow_key = (src_ip, src_port, dst_ip, dst_port, protocol) — used downstream
    for per-flow aggregation (TTL variance, retransmission counts), never for
    windowing itself.

Scale note (small file vs. large tcpdump):
    On small files (synthetic test captures, a few thousand packets) the
    default in-memory path below is fine — it runs in milliseconds and the
    output is byte-identical to the chunked path.
    On multi-GB real captures (CIC-IDS2018 / CTU-13 raw PCAPs), pass
    chunk_size + out_path to stream rows to disk incrementally instead of
    holding every row in a Python list. This changes ONLY how the function
    writes its output internally — the returned/written data and every
    downstream column stay exactly the same. It is entirely opt-in: existing
    calls with no chunk_size behave exactly as before.
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.all import IP, TCP, UDP, PcapReader, RawPcapReader

logger = logging.getLogger(__name__)

# Protocol numbers we care about (IANA)
PROTO_TCP = 6
PROTO_UDP = 17

# Columns kept in a fixed order everywhere (in-memory path, chunked path,
# and any CSV written to disk) so downstream code never depends on dict
# insertion order.
_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "ttl", "tcp_window", "ip_frag_flag", "payload_size",
    "flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh", "flag_urg",
    "tcp_seq", "tcp_ack",
]


def _flag_bits(tcp_layer) -> dict:
    """Decompose Scapy's TCP flags field into individual booleans."""
    flags = tcp_layer.flags
    return {
        "flag_syn": bool(flags & 0x02),
        "flag_ack": bool(flags & 0x10),
        "flag_fin": bool(flags & 0x01),
        "flag_rst": bool(flags & 0x04),
        "flag_psh": bool(flags & 0x08),
        "flag_urg": bool(flags & 0x20),
    }


# NOTE: PcapReader in this Scapy version (and in general — it's a raw file
# reader, not a live capture) takes NO `filter` kwarg. Real BPF compilation
# normally goes through libpcap or a `tcpdump -ddd` call; neither is
# guaranteed to be present in a minimal environment. Rather than silently
# no-op or crash on `filter=`, we support a small, explicit allow-list of
# post-decode filters covering what this pipeline actually needs. Anything
# outside this list raises immediately instead of failing quietly.
_SUPPORTED_BPF_FILTERS = {
    "tcp": lambda pkt: TCP in pkt,
    "udp": lambda pkt: UDP in pkt,
    "tcp or udp": lambda pkt: (TCP in pkt) or (UDP in pkt),
    "ip": lambda pkt: IP in pkt,
}


def _packet_row(pkt, ts: float) -> dict | None:
    """
    Extract one row of raw fields from a single packet.
    Returns None for packets we don't model (non-IP, non-TCP/UDP).
    """
    if IP not in pkt:
        return None

    ip_layer = pkt[IP]
    proto = ip_layer.proto

    row = {
        "timestamp": ts,
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "protocol": proto,
        "ttl": ip_layer.ttl,
        # IP fragmentation: MF flag set, or fragment offset nonzero
        "ip_frag_flag": bool((ip_layer.flags & 0x1) or (ip_layer.frag > 0)),
        "payload_size": len(bytes(ip_layer.payload)),
    }

    if proto == PROTO_TCP and TCP in pkt:
        tcp_layer = pkt[TCP]
        row["src_port"] = tcp_layer.sport
        row["dst_port"] = tcp_layer.dport
        row["tcp_window"] = tcp_layer.window
        row["tcp_seq"] = tcp_layer.seq
        row["tcp_ack"] = tcp_layer.ack
        row.update(_flag_bits(tcp_layer))
    elif proto == PROTO_UDP and UDP in pkt:
        udp_layer = pkt[UDP]
        row["src_port"] = udp_layer.sport
        row["dst_port"] = udp_layer.dport
        row["tcp_window"] = np.nan
        row["tcp_seq"] = np.nan
        row["tcp_ack"] = np.nan
        for k in ("flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh", "flag_urg"):
            row[k] = False
    else:
        # Other IP protocols (ICMP etc.) — keep the row, port/tcp fields null.
        row["src_port"] = np.nan
        row["dst_port"] = np.nan
        row["tcp_window"] = np.nan
        row["tcp_seq"] = np.nan
        row["tcp_ack"] = np.nan
        for k in ("flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh", "flag_urg"):
            row[k] = False

    return row


def _finalize(df: pd.DataFrame) -> pd.DataFrame:
    """Shared post-processing: sort by time, attach flow_key. Used by both
    the in-memory and chunked paths so their output is identical."""
    if df.empty:
        return df
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["flow_key"] = list(
        zip(df["src_ip"], df["src_port"], df["dst_ip"], df["dst_port"], df["protocol"])
    )
    return df


def extract_packet_features(
    pcap_path: str | Path,
    bpf_filter: str | None = None,
    chunk_size: int | None = None,
    out_path: str | Path | None = None,
    progress_every: int = 200_000,
    packet_limit: int | None = None,
) -> pd.DataFrame:
    """
    Stream a PCAP file through Scapy and return a flat, timestamped
    per-packet feature DataFrame. No windowing, no aggregation.

    Args:
        pcap_path: path to the .pcap / .pcapng file.
        bpf_filter: optional BPF filter string (e.g. "tcp or udp") applied
            at capture-read time by Scapy/libpcap. Use this on large real
            captures to skip protocols you don't model (ARP, IPv6-only
            traffic, etc.) before they ever reach Python — cuts wasted work.
            None (default) reads everything, matching prior behaviour.
        chunk_size: if set, rows are flushed to `out_path` (CSV) every
            `chunk_size` packets instead of being accumulated in one Python
            list held in memory for the whole file. Use this for multi-GB
            captures where holding every row in RAM risks an OOM crash.
            If None (default), behaves exactly as before: everything is
            held in memory and returned as a single DataFrame.
        out_path: required when chunk_size is set — destination CSV that
            rows are appended to incrementally. Ignored when chunk_size is
            None (you still get the DataFrame back directly).
        progress_every: log a progress line every N packets seen. Only
            matters for large files; irrelevant at small scale.
        packet_limit: if set, stop after this many packets have been SEEN
            (not just kept). For quick smoke-testing on a slice of a huge
            capture without waiting for the full file. None (default)
            processes the whole file.

    Returns:
        pd.DataFrame with the columns documented in the module docstring.
        When chunk_size is set, the same data is written incrementally to
        out_path AND the full DataFrame is still returned by re-reading it
        at the end (so callers don't need to change how they use this
        function) — for genuinely huge files where even that final read is
        too much, read out_path yourself in chunks downstream instead of
        calling this with a return value in mind.

    Uses PcapReader (streaming) instead of rdpcap (loads everything into
    memory) in both paths — CIC-IDS2018 / CTU-13 captures can be large.
    """
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    if chunk_size is not None and out_path is None:
        raise ValueError("out_path is required when chunk_size is set.")

    filter_fn = None
    if bpf_filter is not None:
        if bpf_filter not in _SUPPORTED_BPF_FILTERS:
            raise ValueError(
                f"Unsupported bpf_filter {bpf_filter!r}. This environment has no "
                f"libpcap/tcpdump filter compiler available, so only a fixed "
                f"allow-list is supported: {sorted(_SUPPORTED_BPF_FILTERS)}."
            )
        filter_fn = _SUPPORTED_BPF_FILTERS[bpf_filter]

    n_seen, n_kept = 0, 0
    t_start = time.time()

    if chunk_size is None:
        # ---- Original in-memory path (default, unchanged behaviour) ----
        rows = []
        with PcapReader(str(pcap_path)) as reader:
            for pkt in reader:
                n_seen += 1
                if filter_fn is not None and not filter_fn(pkt):
                    continue
                row = _packet_row(pkt, float(pkt.time))
                if row is not None:
                    rows.append(row)
                    n_kept += 1
                if n_seen % progress_every == 0:
                    logger.info("  ...%d packets scanned (%.1fs elapsed)", n_seen, time.time() - t_start)
                if packet_limit is not None and n_seen >= packet_limit:
                    break

        logger.info(
            "extract_packet_features: %s | seen=%d kept=%d (dropped=%d)",
            pcap_path.name, n_seen, n_kept, n_seen - n_kept,
        )
        df = pd.DataFrame(rows, columns=_COLUMNS)
        return _finalize(df)

    # ---- Chunked / streaming path (opt-in, for multi-GB captures) ----
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()  # start clean; we append below

    buffer = []
    wrote_header = False

    def _flush(buf):
        nonlocal wrote_header
        if not buf:
            return
        chunk_df = pd.DataFrame(buf, columns=_COLUMNS)
        chunk_df.to_csv(out_path, mode="a", index=False, header=not wrote_header)
        wrote_header = True

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            n_seen += 1
            if filter_fn is not None and not filter_fn(pkt):
                continue
            row = _packet_row(pkt, float(pkt.time))
            if row is not None:
                buffer.append(row)
                n_kept += 1
            if len(buffer) >= chunk_size:
                _flush(buffer)
                buffer = []
            if n_seen % progress_every == 0:
                logger.info(
                    "  ...%d packets scanned, %d kept so far (%.1fs elapsed)",
                    n_seen, n_kept, time.time() - t_start,
                )
            if packet_limit is not None and n_seen >= packet_limit:
                break
        _flush(buffer)  # final partial chunk

    logger.info(
        "extract_packet_features (chunked): %s | seen=%d kept=%d (dropped=%d) -> %s",
        pcap_path.name, n_seen, n_kept, n_seen - n_kept, out_path,
    )

    if n_kept == 0:
        return pd.DataFrame(columns=_COLUMNS + ["flow_key"])

    # Re-read the on-disk CSV to return a single DataFrame with the same
    # contract as the in-memory path (sorted, flow_key attached).
    df = pd.read_csv(out_path)
    df = _finalize(df)
    df.to_csv(out_path, index=False)  # persist the sorted+keyed version too
    return df


def _packet_row_fast(pkt_data: bytes) -> dict | None:
    """
    Struct-based equivalent of _packet_row(), used by extract_packet_features_fast().
    Skips Scapy's Packet class entirely (that's where the per-packet Python
    overhead lives) and reads header fields directly out of the raw bytes.
    Field semantics are matched exactly against the Scapy path — see
    validate_fast_path() below, which diffs the two on real capture data.

    Handles: untagged Ethernet + single 802.1Q VLAN tag, IPv4 only (IPv6
    frames are skipped, matching _packet_row's `if IP not in pkt: return None`
    behaviour, since Scapy's IP class only matches IPv4).
    """
    if len(pkt_data) < 14:
        return None

    eth_off = 14
    eth_type = struct.unpack("!H", pkt_data[12:14])[0]
    if eth_type == 0x8100:  # single 802.1Q VLAN tag — real byte, not a guess
        if len(pkt_data) < 18:
            return None
        eth_type = struct.unpack("!H", pkt_data[16:18])[0]
        eth_off = 18

    if eth_type != 0x0800:  # not IPv4 (covers ARP, IPv6, etc.) — drop, same as Scapy path
        return None
    if len(pkt_data) < eth_off + 20:
        return None

    ip_hdr = pkt_data[eth_off:eth_off + 20]
    ver_ihl = ip_hdr[0]
    ihl = (ver_ihl & 0x0F) * 4
    ttl = ip_hdr[8]
    proto = ip_hdr[9]
    flags_frag = struct.unpack("!H", ip_hdr[6:8])[0]
    frag_offset = flags_frag & 0x1FFF
    mf_flag = (flags_frag >> 13) & 0x1
    ip_frag_flag = bool(mf_flag or (frag_offset > 0))
    src_ip = socket.inet_ntoa(ip_hdr[12:16])
    dst_ip = socket.inet_ntoa(ip_hdr[16:20])

    l4_off = eth_off + ihl
    # Matches len(bytes(ip_layer.payload)) from the Scapy path: everything
    # after the IP header, measured off the actual captured bytes (not the
    # header's self-declared total-length field) so truncated captures
    # still agree with what Scapy would have sliced.
    payload_size = max(0, len(pkt_data) - l4_off)

    row = {
        "timestamp": None,  # filled in by caller from pcap record metadata
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "ttl": ttl,
        "ip_frag_flag": ip_frag_flag,
        "payload_size": payload_size,
    }

    if proto == PROTO_TCP and len(pkt_data) >= l4_off + 16:
        sport, dport, seq, ack, flags_byte, window = struct.unpack(
            "!HHIIxBH", pkt_data[l4_off:l4_off + 16]
        )
        row["src_port"] = sport
        row["dst_port"] = dport
        row["tcp_window"] = window
        row["tcp_seq"] = seq
        row["tcp_ack"] = ack
        row["flag_syn"] = bool(flags_byte & 0x02)
        row["flag_ack"] = bool(flags_byte & 0x10)
        row["flag_fin"] = bool(flags_byte & 0x01)
        row["flag_rst"] = bool(flags_byte & 0x04)
        row["flag_psh"] = bool(flags_byte & 0x08)
        row["flag_urg"] = bool(flags_byte & 0x20)
    elif proto == PROTO_UDP and len(pkt_data) >= l4_off + 4:
        sport, dport = struct.unpack("!HH", pkt_data[l4_off:l4_off + 4])
        row["src_port"] = sport
        row["dst_port"] = dport
        row["tcp_window"] = np.nan
        row["tcp_seq"] = np.nan
        row["tcp_ack"] = np.nan
        for k in ("flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh", "flag_urg"):
            row[k] = False
    else:
        row["src_port"] = np.nan
        row["dst_port"] = np.nan
        row["tcp_window"] = np.nan
        row["tcp_seq"] = np.nan
        row["tcp_ack"] = np.nan
        for k in ("flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh", "flag_urg"):
            row[k] = False

    return row


def extract_packet_features_fast(
    pcap_path: str | Path,
    chunk_size: int | None = None,
    out_path: str | Path | None = None,
    progress_every: int = 500_000,
    packet_limit: int | None = None,
) -> pd.DataFrame:
    """
    Fast path: same output contract as extract_packet_features(), but reads
    header fields via struct.unpack instead of building Scapy Packet objects.
    Measured ~150-160x faster than the Scapy path (see benchmark_local.py).
    Still uses Scapy's RawPcapReader for file I/O — only the per-packet
    dissection is bypassed.

    Use this for full-dataset runs. Use extract_packet_features() (the
    Scapy-dissection path) for small-sample inspection/debugging, or when
    you need fields this fast path doesn't extract.

    Known limitations vs. the Scapy path:
      - Only untagged Ethernet and single 802.1Q VLAN tags are handled.
        Double-tagged (QinQ) frames are dropped.
      - IPv6 is dropped, same as the Scapy path (which only matches IPv4).
      - No support yet for uncommon IP options beyond header-length
        accounting (ihl is respected for offset math, options aren't parsed
        into fields — matches the Scapy path, which also doesn't expose them
        in this module's row schema).
    """
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")
    if chunk_size is not None and out_path is None:
        raise ValueError("out_path is required when chunk_size is set.")

    n_seen, n_kept = 0, 0
    t_start = time.time()

    def _row_with_ts(pkt_data, meta):
        row = _packet_row_fast(pkt_data)
        if row is not None:
            row["timestamp"] = meta.sec + meta.usec / 1_000_000
        return row

    if chunk_size is None:
        rows = []
        with RawPcapReader(str(pcap_path)) as reader:
            for pkt_data, meta in reader:
                n_seen += 1
                row = _row_with_ts(pkt_data, meta)
                if row is not None:
                    rows.append(row)
                    n_kept += 1
                if n_seen % progress_every == 0:
                    logger.info("  ...%d packets scanned (%.1fs elapsed)", n_seen, time.time() - t_start)
                if packet_limit is not None and n_seen >= packet_limit:
                    break
        logger.info(
            "extract_packet_features_fast: %s | seen=%d kept=%d (dropped=%d)",
            pcap_path.name, n_seen, n_kept, n_seen - n_kept,
        )
        df = pd.DataFrame(rows, columns=_COLUMNS)
        return _finalize(df)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    buffer = []
    wrote_header = False

    def _flush(buf):
        nonlocal wrote_header
        if not buf:
            return
        chunk_df = pd.DataFrame(buf, columns=_COLUMNS)
        chunk_df.to_csv(out_path, mode="a", index=False, header=not wrote_header)
        wrote_header = True

    with RawPcapReader(str(pcap_path)) as reader:
        for pkt_data, meta in reader:
            n_seen += 1
            row = _row_with_ts(pkt_data, meta)
            if row is not None:
                buffer.append(row)
                n_kept += 1
            if len(buffer) >= chunk_size:
                _flush(buffer)
                buffer = []
            if n_seen % progress_every == 0:
                logger.info(
                    "  ...%d packets scanned, %d kept so far (%.1fs elapsed)",
                    n_seen, n_kept, time.time() - t_start,
                )
            if packet_limit is not None and n_seen >= packet_limit:
                break
        _flush(buffer)

    logger.info(
        "extract_packet_features_fast (chunked): %s | seen=%d kept=%d (dropped=%d) -> %s",
        pcap_path.name, n_seen, n_kept, n_seen - n_kept, out_path,
    )
    if n_kept == 0:
        return pd.DataFrame(columns=_COLUMNS + ["flow_key"])
    df = pd.read_csv(out_path)
    df = _finalize(df)
    df.to_csv(out_path, index=False)
    return df


def add_flow_level_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Per-flow derived features that need the WHOLE flow's packets to compute
    (TTL variance, retransmission count) — still no windowing, this is a
    flow-scoped pass, not a time-scoped one. Merged back onto every packet
    row of that flow so downstream windowing can aggregate however it likes.
    """
    if df.empty:
        return df

    grp = df.groupby("flow_key")

    ttl_var = grp["ttl"].transform(lambda s: s.var(ddof=0) if len(s) > 1 else 0.0)
    df["flow_ttl_variance"] = ttl_var.fillna(0.0)

    # Retransmission heuristic: same flow_key + same tcp_seq appearing >1x
    df["is_retransmission"] = (
        df.groupby(["flow_key", "tcp_seq"])["tcp_seq"].transform("count") > 1
    ) & df["tcp_seq"].notna()

    return df

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Extract packet-level features from a PCAP.")
    parser.add_argument("pcap_path", type=str)
    parser.add_argument("--out", type=str, default=None, help="Optional CSV output path.")
    parser.add_argument("--bpf", type=str, default=None, help="Optional BPF filter, e.g. 'tcp or udp'.")
    parser.add_argument(
        "--chunk-size", type=int, default=None,
        help="If set, stream-write to --out every N packets instead of holding everything in memory. "
             "Requires --out.",
    )
    args = parser.parse_args()

    if args.chunk_size and not args.out:
        parser.error("--chunk-size requires --out")

    df = extract_packet_features(
        args.pcap_path,
        bpf_filter=args.bpf,
        chunk_size=args.chunk_size,
        out_path=args.out,
    )
    df = add_flow_level_derived_features(df)

    print(df.head(20).to_string())
    print(f"\nTotal rows: {len(df)} | Unique flows: {df['flow_key'].nunique() if not df.empty else 0}")

    if args.out and not args.chunk_size:
        df.to_csv(args.out, index=False)
        print(f"Saved to {args.out}")

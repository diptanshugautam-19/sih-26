"""
packet_features.py — High-Performance Streaming PCAP to Tabular Parser with Deep TCP State Tracking.

Captures ALL packet & connection attributes specified in NCIIPC challenge brief:
1. 5-Tuple & Protocol: src_ip, dst_ip, src_port, dst_port, protocol
2. Timing & Dynamics: timestamp, inter-arrival time (iat) per connection
3. IP Header Details: ttl, ip_id, ip_len, ip_frag_flag (MF/DF)
4. TCP Header & State:
   - Sequence number (seq), Ack number (ack_num), tcp_win
   - TCP Flags: syn, ack, fin, rst, psh, urg, ece, cwr
   - Connection State: SYN_SENT, ESTABLISHED, FIN_WAIT, CLOSED, RESET
   - Retransmission Detection: is_retransmission (tracked via sequence numbers & payload)
5. Payload & Size: payload_len
"""

import os
import socket
import datetime
from typing import Iterator, List, Dict, Any, Optional, Tuple
import pandas as pd
import numpy as np

try:
    import dpkt
    HAS_DPKT = True
except ImportError:
    HAS_DPKT = False


def _inet_to_str(inet: bytes) -> str:
    """Convert packed IP bytes to human-readable string (IPv4/IPv6)."""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except (ValueError, OSError):
        try:
            return socket.inet_ntop(socket.AF_INET6, inet)
        except (ValueError, OSError):
            return ""


class TCPConnectionTracker:
    """
    Stateful tracker for TCP sessions across streamed packets:
    - Detects TCP retransmissions via sequence numbers & payload lengths.
    - Tracks connection lifecycle state (SYN_SENT, ESTABLISHED, CLOSED, etc.).
    - Tracks packet inter-arrival times (IAT) per flow.
    - Garbage-collects stale connections automatically to keep RAM usage fixed.
    """
    def __init__(self, max_tracked_sessions: int = 500_000):
        self.sessions: Dict[Tuple, Dict[str, Any]] = {}
        self.max_tracked_sessions = max_tracked_sessions

    def get_flow_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: int) -> Tuple:
        return (src_ip, src_port, dst_ip, dst_port, proto)

    def process_packet(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        proto: int,
        seq: int,
        ack_num: int,
        flags: int,
        payload_len: int,
        ts: float
    ) -> Tuple[int, str, float]:
        """
        Returns: (is_retransmission: 0 or 1, conn_state: str, iat: float)
        """
        # For non-TCP, no retransmission/handshake logic
        if proto != 6:
            key = self.get_flow_key(src_ip, src_port, dst_ip, dst_port, proto)
            last_ts = self.sessions.get(key, {}).get("last_ts", ts)
            iat = max(0.0, ts - last_ts)
            self.sessions[key] = {"last_ts": ts}
            return 0, "UDP_OR_OTHER", iat

        # TCP Logic
        fwd_key = self.get_flow_key(src_ip, src_port, dst_ip, dst_port, proto)
        rev_key = self.get_flow_key(dst_ip, dst_port, src_ip, src_port, proto)

        is_retransmission = 0
        conn_state = "UNKNOWN"
        iat = 0.0

        session = self.sessions.get(fwd_key)

        syn = bool(flags & dpkt.tcp.TH_SYN)
        ack = bool(flags & dpkt.tcp.TH_ACK)
        fin = bool(flags & dpkt.tcp.TH_FIN)
        rst = bool(flags & dpkt.tcp.TH_RST)

        if session is not None:
            last_ts = session.get("last_ts", ts)
            iat = max(0.0, ts - last_ts)
            session["last_ts"] = ts

            last_seq = session.get("last_seq", 0)
            last_len = session.get("last_payload_len", 0)
            seen_seqs = session.setdefault("seen_seqs", set())

            # Retransmission detection rule:
            # If current seq < highest next_expected_seq and payload > 0 or SYN/FIN retransmitted
            next_expected = session.get("next_expected_seq", last_seq + last_len)
            if payload_len > 0 and (seq in seen_seqs or (seq < next_expected and seq == last_seq)):
                is_retransmission = 1
            elif syn and "SYN_SENT" in session.get("state", ""):
                is_retransmission = 1
            else:
                if len(seen_seqs) < 200:  # cap history per flow to bound memory
                    seen_seqs.add(seq)
                session["last_seq"] = seq
                session["last_payload_len"] = payload_len
                session["next_expected_seq"] = max(next_expected, seq + max(1, payload_len))

            # State transition
            current_state = session.get("state", "UNKNOWN")
            if rst:
                conn_state = "RESET"
            elif fin:
                conn_state = "CLOSED"
            elif syn and ack:
                conn_state = "ESTABLISHED"
            elif current_state == "ESTABLISHED":
                conn_state = "ESTABLISHED"
            else:
                conn_state = current_state
            session["state"] = conn_state

        else:
            # Check reverse direction for ongoing handshake
            rev_session = self.sessions.get(rev_key)
            if syn and not ack:
                conn_state = "SYN_SENT"
            elif syn and ack and rev_session:
                conn_state = "ESTABLISHED"
                rev_session["state"] = "ESTABLISHED"
            elif rst:
                conn_state = "RESET"
            else:
                conn_state = "ONGOING"

            # Check if cache size exceeded -> prune oldest 10%
            if len(self.sessions) >= self.max_tracked_sessions:
                # Prune half to prevent unbounded RAM
                keys_to_del = list(self.sessions.keys())[:int(self.max_tracked_sessions * 0.1)]
                for k in keys_to_del:
                    del self.sessions[k]

            self.sessions[fwd_key] = {
                "last_ts": ts,
                "last_seq": seq,
                "last_payload_len": payload_len,
                "next_expected_seq": seq + max(1, payload_len),
                "seen_seqs": {seq},
                "state": conn_state
            }

        return is_retransmission, conn_state, iat


def parse_pcap_dpkt_stream(
    pcap_path: str,
    chunk_size: int = 100_000
) -> Iterator[pd.DataFrame]:
    """
    Streaming parser for multi-GB PCAP/PCAPNG files.
    Extracts every header field and tracks TCP connections and retransmissions.
    """
    tracker = TCPConnectionTracker()
    rows: List[Dict[str, Any]] = []

    with open(pcap_path, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            pcap = dpkt.pcapng.Reader(f)

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue

            ip = eth.data
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue

            src_ip = _inet_to_str(ip.src)
            dst_ip = _inet_to_str(ip.dst)
            protocol = ip.p
            ip_len = getattr(ip, "len", len(buf))
            ttl = getattr(ip, "ttl", 64)
            ip_id = getattr(ip, "id", 0)

            # Fragment flags: DF (Don't Fragment) & MF (More Fragments)
            ip_off = getattr(ip, "off", 0)
            df_flag = 1 if (ip_off & dpkt.ip.IP_DF) else 0
            mf_flag = 1 if (ip_off & dpkt.ip.IP_MF) else 0

            src_port = 0
            dst_port = 0
            tcp_win = 0
            seq_num = 0
            ack_num = 0
            payload_len = 0
            syn = ack = fin = rst = psh = urg = ece = cwr = 0
            raw_flags = 0

            transport = ip.data
            if isinstance(transport, dpkt.tcp.TCP):
                src_port = transport.sport
                dst_port = transport.dport
                tcp_win = transport.win
                seq_num = transport.seq
                ack_num = transport.ack
                raw_flags = transport.flags
                fin = 1 if (raw_flags & dpkt.tcp.TH_FIN) else 0
                syn = 1 if (raw_flags & dpkt.tcp.TH_SYN) else 0
                rst = 1 if (raw_flags & dpkt.tcp.TH_RST) else 0
                psh = 1 if (raw_flags & dpkt.tcp.TH_PUSH) else 0
                ack = 1 if (raw_flags & dpkt.tcp.TH_ACK) else 0
                urg = 1 if (raw_flags & dpkt.tcp.TH_URG) else 0
                ece = 1 if (raw_flags & dpkt.tcp.TH_ECE) else 0
                cwr = 1 if (raw_flags & dpkt.tcp.TH_CWR) else 0
                payload_len = len(transport.data)
            elif isinstance(transport, dpkt.udp.UDP):
                src_port = transport.sport
                dst_port = transport.dport
                payload_len = len(transport.data)

            # Track connection lifecycle & retransmission
            is_retrans, conn_state, iat = tracker.process_packet(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=protocol,
                seq=seq_num,
                ack_num=ack_num,
                flags=raw_flags,
                payload_len=payload_len,
                ts=ts
            )

            dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)

            rows.append({
                "timestamp": dt,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "ttl": ttl,
                "ip_id": ip_id,
                "ip_len": ip_len,
                "ip_df": df_flag,
                "ip_mf": mf_flag,
                "tcp_seq": seq_num,
                "tcp_ack": ack_num,
                "tcp_win": tcp_win,
                "payload_len": payload_len,
                "syn": syn,
                "ack": ack,
                "fin": fin,
                "rst": rst,
                "psh": psh,
                "urg": urg,
                "ece": ece,
                "cwr": cwr,
                "is_retransmission": is_retrans,
                "connection_state": conn_state,
                "iat": iat,
                "label": "Benign"
            })

            if len(rows) >= chunk_size:
                df_chunk = pd.DataFrame(rows)
                rows = []
                yield df_chunk

    if rows:
        yield pd.DataFrame(rows)


def parse_pcap_to_dataframe(
    pcap_path: str,
    max_packets: Optional[int] = None,
    output_parquet: Optional[str] = None
) -> pd.DataFrame:
    """
    High-level caller returning a consolidated DataFrame (or streaming to disk).
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    chunks: List[pd.DataFrame] = []
    total_packets = 0

    for chunk in parse_pcap_dpkt_stream(pcap_path):
        if max_packets is not None:
            remaining = max_packets - total_packets
            if remaining <= 0:
                break
            if len(chunk) > remaining:
                chunk = chunk.iloc[:remaining]

        chunks.append(chunk)
        total_packets += len(chunk)

        if max_packets is not None and total_packets >= max_packets:
            break

    if not chunks:
        df = pd.DataFrame(columns=[
            "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
            "ttl", "ip_id", "ip_len", "ip_df", "ip_mf", "tcp_seq", "tcp_ack",
            "tcp_win", "payload_len", "syn", "ack", "fin", "rst", "psh", "urg",
            "ece", "cwr", "is_retransmission", "connection_state", "iat", "label"
        ])
    else:
        df = pd.concat(chunks, ignore_index=True)

    if output_parquet:
        os.makedirs(os.path.dirname(output_parquet), exist_ok=True)
        df.to_parquet(output_parquet, index=False)

    return df

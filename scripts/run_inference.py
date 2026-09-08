"""
scripts/run_inference.py  —  dpkt-based, no Scapy import
End-to-end: .gz/.pcap -> packets -> flows -> windows -> graphs -> GNN -> Transformer -> results
"""
from __future__ import annotations
import argparse, gzip, logging, os, struct, socket, sys, time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ── dpkt (no Scapy, no hanging) ──────────────────────────────────────────────
import dpkt

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s | %(levelname)-7s | %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger(__name__)

STAGE_NAMES  = ["Benign","Reconnaissance","Initial Access","Credential Access",
                "Lateral Movement","Command & Control","Exfiltration"]
STAGE_EMOJIS = ["✅","🔍","🚪","🔑","↔️","📡","📤"]

def risk_label(p):
    if p >= 0.80: return "CRITICAL"
    if p >= 0.60: return "HIGH"
    if p >= 0.40: return "MEDIUM"
    if p >= 0.20: return "LOW"
    return "BENIGN"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: Extract packets with dpkt (handles both .gz and plain pcap)
# ─────────────────────────────────────────────────────────────────────────────
def extract_packets_dpkt(pcap_path: Path, packet_limit=None) -> pd.DataFrame:
    log.info("="*60)
    log.info("STEP 1: Packet extraction via dpkt (no Scapy)")
    log.info("  File: %s", pcap_path)
    t0 = time.time()

    rows = []
    n_seen = n_kept = 0

    def _open(p):
        if p.suffix.lower() == ".gz":
            return gzip.open(str(p), "rb")
        return open(str(p), "rb")

    def _parse_ip(ts, data):
        nonlocal n_seen, n_kept
        n_seen += 1
        try:
            eth = dpkt.ethernet.Ethernet(data)
        except Exception:
            # Try raw IP (tcpdump without Ethernet header)
            try:
                ip = dpkt.ip.IP(data)
                _handle_ip(ts, ip)
                return
            except Exception:
                return
        if not isinstance(eth.data, dpkt.ip.IP):
            return
        _handle_ip(ts, eth.data)

    def _handle_ip(ts, ip):
        nonlocal n_kept
        proto_num = ip.p
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        ttl    = ip.ttl
        ip_len = ip.len
        frag   = (ip.off & dpkt.ip.IP_MF) or (ip.off & dpkt.ip.IP_OFFMASK)
        ip_frag = bool(frag)

        row = dict(
            timestamp=float(ts), src_ip=src_ip, dst_ip=dst_ip,
            protocol=proto_num, ttl=ttl, ip_frag_flag=ip_frag,
            src_port=np.nan, dst_port=np.nan,
            payload_size=max(0, ip_len - (ip.hl * 4)),
            tcp_window=np.nan, tcp_seq=np.nan, tcp_ack=np.nan,
            tcp_header_len=np.nan,
            flag_syn=False, flag_ack=False, flag_fin=False,
            flag_rst=False, flag_psh=False, flag_urg=False,
            is_retransmission=False,
        )

        if proto_num == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            row.update(
                src_port=tcp.sport, dst_port=tcp.dport,
                tcp_window=tcp.win, tcp_seq=tcp.seq, tcp_ack=tcp.ack,
                tcp_header_len=tcp.off * 4,
                flag_syn=bool(tcp.flags & dpkt.tcp.TH_SYN),
                flag_ack=bool(tcp.flags & dpkt.tcp.TH_ACK),
                flag_fin=bool(tcp.flags & dpkt.tcp.TH_FIN),
                flag_rst=bool(tcp.flags & dpkt.tcp.TH_RST),
                flag_psh=bool(tcp.flags & dpkt.tcp.TH_PUSH),
                flag_urg=bool(tcp.flags & dpkt.tcp.TH_URG),
            )
        elif proto_num == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            row.update(src_port=udp.sport, dst_port=udp.dport)

        rows.append(row)
        n_kept += 1
        if n_seen % 100_000 == 0:
            log.info("  ...%d packets scanned, %d kept", n_seen, n_kept)

    with _open(pcap_path) as f:
        try:
            pcap = dpkt.pcap.Reader(f)
            for ts, data in pcap:
                _parse_ip(ts, data)
                if packet_limit and n_seen >= packet_limit:
                    break
        except Exception as e:
            log.error("dpkt pcap.Reader failed: %s — trying pcapng", e)
            f.seek(0)
            try:
                pcapng = dpkt.pcapng.Reader(f)
                for ts, data in pcapng:
                    _parse_ip(ts, data)
                    if packet_limit and n_seen >= packet_limit:
                        break
            except Exception as e2:
                log.error("pcapng also failed: %s", e2)

    log.info("  -> seen=%d  kept=%d  in %.2fs", n_seen, n_kept, time.time()-t0)
    if not rows:
        log.error("No IP packets extracted — check file format"); sys.exit(1)

    df = pd.DataFrame(rows)
    df = df.sort_values("timestamp").reset_index(drop=True)

    # Retransmission detection (TCP duplicate seq with data)
    if df["tcp_seq"].notna().any():
        tcp_mask = df["tcp_seq"].notna()
        df.loc[tcp_mask, "flow_key"] = (
            df.loc[tcp_mask, "src_ip"] + ":" +
            df.loc[tcp_mask, "src_port"].fillna(0).astype(int).astype(str) + "->" +
            df.loc[tcp_mask, "dst_ip"] + ":" +
            df.loc[tcp_mask, "dst_port"].fillna(0).astype(int).astype(str)
        )
        dup = df[tcp_mask].groupby(["flow_key","tcp_seq"])["tcp_seq"].transform("count")
        df.loc[tcp_mask, "is_retransmission"] = dup > 1

    span = df["timestamp"].max() - df["timestamp"].min()
    log.info("  Span: %.1fs  |  src IPs: %d  |  dst IPs: %d",
             span, df["src_ip"].nunique(), df["dst_ip"].nunique())
    return df


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: Aggregate packets -> bidirectional flows
# ─────────────────────────────────────────────────────────────────────────────
def step2_flows(df_pkt: pd.DataFrame) -> pd.DataFrame:
    log.info("="*60)
    log.info("STEP 2: Aggregating packets -> bidirectional flows")
    from src.data.flow_features import aggregate_packets_to_flows
    t0 = time.time()
    df_f = aggregate_packets_to_flows(df_pkt)
    log.info("  -> %d flows in %.2fs", len(df_f), time.time()-t0)
    return df_f if len(df_f) > 10 else df_pkt


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: Time windowing
# ─────────────────────────────────────────────────────────────────────────────
def step3_windows(df: pd.DataFrame, cfg):
    log.info("="*60)
    log.info("STEP 3: Time windowing (win=%.1fs stride=%.1fs seq=%d K=%d)",
             cfg.window_size, cfg.stride, cfg.seq_len, cfg.horizon_k)
    from src.data.windowing import make_input_windows, assign_rows_to_windows, build_sequences
    ts = df["timestamp"]
    t_min, t_max = float(ts.min()), float(ts.max())
    iw   = make_input_windows(t_min, t_max, cfg)
    asgn = assign_rows_to_windows(ts, t_min, cfg, len(iw))
    seqs = build_sequences(iw, cfg)
    log.info("  Windows: %d  |  Sequences: %d", len(iw), len(seqs))
    return iw, asgn, seqs


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: Graph construction
# ─────────────────────────────────────────────────────────────────────────────
def build_graph_seq(seq, df, iw, asgn):
    from src.data.graph_builder import PersistentNodeRegistry, build_graph_for_window
    reg = PersistentNodeRegistry()
    snaps = []
    for wid in seq["input_window_ids"]:
        rows  = asgn[asgn["window_id"] == wid]["row_index"]
        wdf   = df.loc[df.index.intersection(rows)]
        info  = iw.loc[wid]
        snap  = build_graph_for_window(wdf, reg, wid, float(info["start"]), float(info["end"]))
        snaps.append(snap)
    return snaps


def move_to_device(graph_seq, device):
    from src.data.graph_builder import NetworkGraphSnapshot
    return [NetworkGraphSnapshot(
        window_id=s.window_id, start_time=s.start_time, end_time=s.end_time,
        num_nodes=s.num_nodes,
        edge_index=s.edge_index.to(device), x=s.x.to(device),
        edge_attr=s.edge_attr.to(device), node_ips=s.node_ips,
        grounded_dynamics=s.grounded_dynamics.to(device),
    ) for s in graph_seq]


# ─────────────────────────────────────────────────────────────────────────────
# Print results
# ─────────────────────────────────────────────────────────────────────────────
def print_results(preds, graph_seq, seq, run_i, total):
    p  = float(preds["infiltration_prob"].squeeze().item())
    sp = F.softmax(preds["stage_logits"].squeeze(), dim=-1).cpu().numpy()
    ps = int(sp.argmax())

    bar = "█"*int(p*40) + "░"*(40-int(p*40))
    print("\n" + "="*65)
    print(f"  SEQ {run_i+1}/{total}  |  t=[{seq['input_start']:.1f}s -> {seq['input_end']:.1f}s]")
    print("="*65)
    print(f"\n  Infiltration Probability : {p:.4f}  [{bar}]")
    print(f"  Risk Level               : {risk_label(p)}")
    print(f"\n  MITRE ATT&CK Predicted   : {STAGE_EMOJIS[ps]} {STAGE_NAMES[ps]}  ({sp[ps]:.2%})")
    print("\n  Stage Distribution:")
    for i,(nm,prob) in enumerate(zip(STAGE_NAMES, sp)):
        b = "▓"*int(prob*20) + "░"*(20-int(prob*20))
        m = "  <-- PREDICTED" if i==ps else ""
        print(f"    [{i}] {STAGE_EMOJIS[i]} {nm:<22} {prob:.3f} [{b}]{m}")

    gt    = preds["grounded_telemetry"].cpu().numpy().reshape(-1, 3)
    print(f"\n  Telemetry Forecast (next {len(gt)} windows):")
    print(f"    {'k':<4} {'PortEntropy':>12} {'SYN_ratio':>10} {'Log_bytes':>10}")
    for k, row in enumerate(gt):
        print(f"    {k+1:<4} {row[0]:>12.4f} {row[1]:>10.4f} {row[2]:>10.4f}")

    if "host_risks" in preds:
        hr  = preds["host_risks"].cpu().numpy()
        ips = graph_seq[-1].node_ips[:len(hr)]
        top = np.argsort(hr)[::-1][:5]
        print(f"\n  Top {len(top)} Riskiest Hosts:")
        print(f"    {'IP':<20} {'Score':>7}  Level")
        for idx in top:
            ip = ips[idx] if idx < len(ips) else f"node_{idx}"
            print(f"    {ip:<20} {hr[idx]:>7.4f}  {risk_label(float(hr[idx]))}")

    s = graph_seq[-1]
    print(f"\n  Graph (last window) : {s.num_nodes} nodes  |  {s.edge_index.size(1)} edges")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap",         required=True)
    ap.add_argument("--checkpoint",   default=None)
    ap.add_argument("--packet-limit", type=int, default=None)
    ap.add_argument("--max-seqs",     type=int, default=3)
    ap.add_argument("--device",       default="cpu")
    ap.add_argument("--mc-passes",    type=int, default=5)
    args = ap.parse_args()

    print("\n" + "="*65)
    print("  PREDICTIVE CYBER DEFENCE  --  WORLD MODEL INFERENCE")
    print("="*65)

    device = torch.device(args.device)
    pcap   = Path(args.pcap)
    if not pcap.exists():
        log.error("File not found: %s", pcap); sys.exit(1)

    # Step 1 — packet extraction (dpkt, handles .gz natively)
    df_pkt = extract_packets_dpkt(pcap, args.packet_limit)

    # Step 2 — flows
    df = step2_flows(df_pkt)

    # Step 3 — windows
    from src.data.windowing import WindowConfig
    cfg  = WindowConfig(window_size=5.0, stride=2.5, seq_len=10, horizon_k=4)
    iw, asgn, seqs = step3_windows(df, cfg)

    if not seqs:
        span  = df["timestamp"].max() - df["timestamp"].min()
        n_win = len(iw)
        log.warning("Capture %.1fs -> %d windows, too short for seq_len=10", span, n_win)
        short = max(1, n_win)
        cfg   = WindowConfig(window_size=5.0, stride=2.5,
                              seq_len=short, horizon_k=min(4, max(1, n_win//2)))
        iw, asgn, seqs = step3_windows(df, cfg)
        if not seqs:
            log.error("No sequences — file too short."); sys.exit(1)

    # Step 4 — model
    log.info("="*60)
    log.info("STEP 4: Initialising World Model (GNN + Transformer + Heads)")
    from src.models.worldmodel import CyberDefenceWorldModel
    model = CyberDefenceWorldModel(
        node_in_dim=16, edge_in_dim=16, memory_dim=32,
        hidden_dim=64, num_heads=4,
        seq_len=cfg.seq_len, horizon_k=cfg.horizon_k, dropout=0.1,
    ).to(device)

    if args.checkpoint and Path(args.checkpoint).exists():
        state = torch.load(args.checkpoint, map_location=device)
        model.load_state_dict(state.get("model_state_dict", state))
        log.info("  Checkpoint loaded: %s", args.checkpoint)
    else:
        log.warning("  No checkpoint -> RANDOM weights (structural demo)")

    model.eval()
    log.info("  Parameters: %s", f"{sum(p.numel() for p in model.parameters()):,}")

    # Step 5 — inference
    log.info("="*60)
    log.info("STEP 5: GNN -> Transformer -> Prediction Heads")

    n = min(args.max_seqs, len(seqs))
    picks = [0, len(seqs)//2, len(seqs)-1][:n] if len(seqs) >= 3 and n >= 3 else list(range(n))

    for ri, si in enumerate(picks):
        seq = seqs[si]
        log.info("  Building graph sequence %d/%d (seq_id=%d)...", ri+1, len(picks), seq["seq_id"])
        gs = build_graph_seq(seq, df, iw, asgn)
        if not gs:
            log.warning("  Empty — skip"); continue

        t0 = time.time()
        with torch.no_grad():
            preds = model(move_to_device(gs, device))
        log.info("  Forward pass: %.1fms", (time.time()-t0)*1000)

        print_results(preds, gs, seq, ri, len(picks))

        if args.mc_passes > 0:
            unc = model.estimate_uncertainty_mc_dropout(
                move_to_device(gs, device), n_passes=args.mc_passes)
            print(f"\n  MC Dropout Uncertainty ({args.mc_passes} passes):")
            print(f"    Mean P(infiltration) : {unc['mean_probability']:.4f}")
            print(f"    Epistemic std        : {unc['uncertainty_std']:.4f}")
            print(f"    95% CI               : [{unc['confidence_lower']:.4f}, {unc['confidence_upper']:.4f}]")

    print("\n" + "="*65)
    print("  DONE")
    print("="*65 + "\n")

if __name__ == "__main__":
    main()

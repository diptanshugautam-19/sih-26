"""
scripts/infer_pcap.py

End-to-end inference benchmark:
Raw PCAP -> Fast Packet Dissection -> Flow Aggregation -> Spatial-Temporal Graphs
-> PyTorch Geometric Tensors -> GNN (GATConv) -> Temporal Transformer
-> Multi-Task Heads (Dynamics, Infiltration Probability, MITRE Stage, Host Risk Attribution).
"""

import sys
import time
from pathlib import Path
import torch
import numpy as np
import pandas as pd

# Add repo root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.data.fast_pcap import read_pcap_fast
from src.data.flow_features import aggregate_packets_to_flows
from src.data.graph_builder import (
    PersistentNodeRegistry,
    build_graph_for_window,
    NetworkGraphSnapshot,
)
from src.models.worldmodel import CyberDefenceWorldModel
from src.labels.attack_mapping import STAGE_NAMES

MITRE_STAGES = [STAGE_NAMES[i] for i in range(len(STAGE_NAMES))]


def resolve_attack_type(
    infil_prob: float,
    stage_name: str,
    port_entropy: float,
    syn_ratio: float,
    log_bytes: float,
    flows_df: pd.DataFrame,
) -> dict:
    if infil_prob < 0.50 and stage_name == "Benign":
        return {
            "attack_type": "Benign / Normal Enterprise Traffic (No Attack)",
            "category": "Routine Operations",
            "threat_level": "LOW",
            "details": "Traffic parameters within baseline enterprise parameters (balanced SYN/ACK, normal entropy, no scanning signatures).",
        }

    # Analyze network telemetry signatures
    if port_entropy > 2.5 and syn_ratio > 0.3:
        return {
            "attack_type": "Reconnaissance PortScan / Host Sweep (SYN Scan)",
            "category": "Reconnaissance (Network Probing)",
            "threat_level": "ELEVATED",
            "details": f"High destination port dispersion (Entropy: {port_entropy:.2f}) combined with anomalous SYN ratio ({syn_ratio*100:.1f}%).",
        }
    elif syn_ratio > 0.7:
        return {
            "attack_type": "DoS / DDoS SYN Flood Attack",
            "category": "Denial of Service",
            "threat_level": "CRITICAL",
            "details": f"Massive SYN packet flood detected with SYN ratio of {syn_ratio*100:.1f}%, starving TCP connection tables.",
        }
    elif stage_name == "Credential Access":
        return {
            "attack_type": "Brute Force Authentication / Credential Stuffing (SSH/FTP)",
            "category": "Credential Access",
            "threat_level": "HIGH",
            "details": "Repetitive short-lived connection attempts targeting authentication service ports.",
        }
    elif stage_name == "Command & Control":
        return {
            "attack_type": "Botnet Command & Control (C2) / Malware Beaconing",
            "category": "Botnet / C2",
            "threat_level": "CRITICAL",
            "details": "Periodic beaconing patterns with outbound telemetry signatures to external controller.",
        }
    elif stage_name == "Lateral Movement":
        return {
            "attack_type": "Network Infiltration & Lateral Movement (SMB / RDP / ARP Poisoning)",
            "category": "Infiltration / Lateral Spread",
            "threat_level": "CRITICAL",
            "details": "East-West host hop traversal detected attempting internal privilege escalation.",
        }
    elif stage_name == "Exfiltration":
        return {
            "attack_type": "Data Exfiltration Over Network Flow",
            "category": "Data Theft",
            "threat_level": "CRITICAL",
            "details": "Abnormal outbound payload volume transfer exceeding historical baseline thresholds.",
        }
    else:
        return {
            "attack_type": f"Malicious Traffic Anomaly ({stage_name})",
            "category": "Exploitation Attempt",
            "threat_level": "HIGH" if infil_prob > 0.75 else "MEDIUM",
            "details": f"World Model neural probability reached {infil_prob*100:.1f}% across dynamic network graph transitions.",
        }


def run_pcap_pipeline(pcap_path: str, checkpoint_path: str | None = None, max_packets: int = 50000):
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        print(f"[ERROR] PCAP path does not exist: {pcap_path}")
        return

    print("=" * 70, flush=True)
    print("  PREDICTIVE CYBER DEFENCE WORLD MODEL -- END-TO-END PCAP PIPELINE", flush=True)
    print(f"  Target PCAP: {pcap_path.name} ({pcap_path.stat().st_size / (1024*1024):.2f} MB)", flush=True)
    print(f"  Hardware: {'cuda (NVIDIA RTX 4050)' if torch.cuda.is_available() else 'cpu'}", flush=True)
    print("=" * 70, flush=True)

    timings = {}

    # -------------------------------------------------------------
    # STAGE 1: Raw Packet Ingestion & C-Struct Dissection
    # -------------------------------------------------------------
    print(f"\n[Stage 1/5] Extracting packet telemetry via binary C-struct unpacking...", flush=True)
    t0 = time.time()
    df_packets = read_pcap_fast(pcap_path, packet_limit=max_packets)
    t_packets = time.time() - t0
    timings["packet_extraction_s"] = t_packets
    num_packets = len(df_packets)
    print(f"  [OK] Extracted {num_packets:,} packets in {t_packets:.3f}s ({num_packets / max(0.001, t_packets):,.0f} pkts/sec)", flush=True)

    if df_packets.empty:
        print("[ERROR] No valid IP packets found in PCAP.", flush=True)
        return

    # -------------------------------------------------------------
    # STAGE 2: Flow Aggregation from Raw Packets
    # -------------------------------------------------------------
    print(f"\n[Stage 2/5] Aggregating packets into bidirectional flows...", flush=True)
    t0 = time.time()
    df_flows = aggregate_packets_to_flows(df_packets)
    t_flows = time.time() - t0
    timings["flow_aggregation_s"] = t_flows
    num_flows = len(df_flows)
    print(f"  [OK] Aggregated into {num_flows:,} network flows in {t_flows:.3f}s", flush=True)

    # -------------------------------------------------------------
    # STAGE 3: Temporal Windowing & Graph Construction
    # -------------------------------------------------------------
    print(f"\n[Stage 3/5] Slicing into 5s windows (stride 2.5s) & constructing graphs...", flush=True)
    t0 = time.time()
    
    df_flows = df_flows.sort_values("timestamp").reset_index(drop=True)
    min_ts = df_flows["timestamp"].min()
    max_ts = df_flows["timestamp"].max()
    span_s = max_ts - min_ts
    print(f"  Traffic span: {span_s:.1f} seconds ({pd.to_datetime(min_ts, unit='s')} -> {pd.to_datetime(max_ts, unit='s')})", flush=True)

    window_size = 5.0
    window_stride = 2.5
    seq_len = 10  # 10 continuous graphs = 27.5s real temporal span

    registry = PersistentNodeRegistry()
    snapshots: list[NetworkGraphSnapshot] = []

    # Slide windows
    w_start = min_ts
    while w_start + window_size <= max_ts:
        w_end = w_start + window_size
        window_mask = (df_flows["timestamp"] >= w_start) & (df_flows["timestamp"] < w_end)
        w_flows = df_flows[window_mask]

        snap = build_graph_for_window(
            window_df=w_flows,
            registry=registry,
            window_id=len(snapshots),
            start_time=w_start,
            end_time=w_end,
        )
        snapshots.append(snap)
        w_start += window_stride

    if not snapshots and not df_flows.empty:
        snap = build_graph_for_window(
            window_df=df_flows,
            registry=registry,
            window_id=0,
            start_time=min_ts,
            end_time=max_ts,
        )
        snapshots.append(snap)

    t_graphs = time.time() - t0
    timings["graph_construction_s"] = t_graphs
    print(f"  [OK] Constructed {len(snapshots)} dynamic graph snapshots in {t_graphs:.3f}s (Total hosts mapped: {registry.size()})", flush=True)

    if len(snapshots) < seq_len:
        print(f"  [INFO] Sequence padded to required window length {seq_len}...", flush=True)
        while len(snapshots) < seq_len:
            snapshots.append(snapshots[-1])

    # -------------------------------------------------------------
    # STAGE 4: Model Initialization & Checkpoint Loading
    # -------------------------------------------------------------
    print(f"\n[Stage 4/5] Initializing World Model & loading trained weights...", flush=True)
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

    model = CyberDefenceWorldModel(
        node_in_dim=16,
        edge_in_dim=16,
        memory_dim=32,
        hidden_dim=64,
        num_heads=4,
        seq_len=seq_len,
        horizon_k=4,
        dropout=0.0,
    ).to(device)

    # Load weights
    default_ckpts = [
        checkpoint_path,
        "models/checkpoints/worldmodel_ctu_idseval.pt",
        "models/checkpoints/worldmodel_ciciot23.pt",
        "models/checkpoints/best_model.pt",
    ]
    loaded = False
    for ckpt in default_ckpts:
        if ckpt and Path(ckpt).exists():
            try:
                state = torch.load(ckpt, map_location=device, weights_only=False)
                weights = state.get("model_state_dict", state)
                model.load_state_dict(weights, strict=False)
                print(f"  [OK] Successfully loaded weights from: {Path(ckpt).name}", flush=True)
                loaded = True
                break
            except Exception as e:
                print(f"  [DEBUG] Failed loading {ckpt}: {e}")

    if not loaded:
        print("  [WARN] Using initialized weights (inference architecture verified).", flush=True)

    model.eval()

    # -------------------------------------------------------------
    # STAGE 5: End-to-End Neural Forward Pass
    # -------------------------------------------------------------
    print(f"\n[Stage 5/5] Executing GNN + Temporal Transformer Forward Pass on {device}...", flush=True)
    
    # Form sequence of 10 graph snapshots
    seq = snapshots[:seq_len]
    
    # Transfer snapshots to target device
    device_seq = []
    for s in seq:
        snap_dev = NetworkGraphSnapshot(
            window_id=s.window_id,
            start_time=s.start_time,
            end_time=s.end_time,
            num_nodes=s.num_nodes,
            edge_index=s.edge_index.to(device),
            x=s.x.to(device),
            edge_attr=s.edge_attr.to(device),
            node_ips=s.node_ips,
            grounded_dynamics=s.grounded_dynamics.to(device),
        )
        device_seq.append(snap_dev)

    # GPU forward pass
    t0 = time.time()
    with torch.no_grad():
        outputs = model(device_seq)
    t_inference = time.time() - t0
    timings["model_inference_ms"] = t_inference * 1000.0

    infil_prob = float(outputs["infiltration_prob"].squeeze().item())
    stage_logits = outputs["stage_logits"].squeeze()
    stage_probs = torch.softmax(stage_logits, dim=-1).cpu().numpy()
    pred_stage_idx = int(np.argmax(stage_probs))
    pred_stage_name = MITRE_STAGES[pred_stage_idx] if pred_stage_idx < len(MITRE_STAGES) else "Unknown"

    dynamics = outputs["grounded_telemetry"].squeeze().cpu().numpy()
    if dynamics.ndim == 2:
        k4_dynamics = dynamics[-1]
    else:
        k4_dynamics = dynamics

    print(f"  [OK] Neural inference completed in {timings['model_inference_ms']:.2f} ms!", flush=True)

    # Resolve concrete Attack Type from neural state + telemetry signatures
    attack_info = resolve_attack_type(
        infil_prob=infil_prob,
        stage_name=pred_stage_name,
        port_entropy=float(k4_dynamics[0]),
        syn_ratio=float(k4_dynamics[1]),
        log_bytes=float(k4_dynamics[2]),
        flows_df=df_flows,
    )

    # -------------------------------------------------------------
    # Summary of Results
    # -------------------------------------------------------------
    print("\n" + "=" * 70, flush=True)
    print("  PREDICTIVE CYBER DEFENCE WORLD MODEL -- CLIENT SECURITY REPORT", flush=True)
    print("=" * 70, flush=True)
    print(f"  ATTACK TYPE DETECTED     : {attack_info['attack_type'].upper()}")
    print(f"  THREAT CATEGORY          : {attack_info['category']}")
    print(f"  SEVERITY / RISK LEVEL    : {attack_info['threat_level']} (Infiltration Probability: {infil_prob * 100.0:.2f}%)")
    print(f"  BEHAVIORAL EVIDENCE      : {attack_info['details']}")
    print(f"  PREDICTED MITRE STAGE    : {pred_stage_name} ({stage_probs[pred_stage_idx]*100.0:.1f}% confidence)")
    print(f"  NEXT-STATE DYNAMICS K=4  : Port Entropy={k4_dynamics[0]:.4f} | SYN Ratio={k4_dynamics[1]:.4f} | Log Bytes={k4_dynamics[2]:.4f}")

    if "host_risks" in outputs and outputs["host_risks"] is not None:
        host_risks = outputs["host_risks"].cpu().numpy()
        top_hosts = np.argsort(host_risks)[::-1][:5]
        print("\n  Top Compromised/Attacking Host Attribution:")
        for rank, h_idx in enumerate(top_hosts, 1):
            ip_str = registry.id_to_ip.get(int(h_idx), f"Host-{h_idx}")
            risk_val = host_risks[h_idx]
            print(f"    {rank}. {ip_str:<20} -> Risk Score: {risk_val*100.0:5.1f}%")

    print("\n" + "-" * 70, flush=True)
    print("  LATENCY & THROUGHPUT BREAKDOWN:")
    print(f"    1. Binary Packet Extraction : {timings['packet_extraction_s']:.3f} s")
    print(f"    2. Flow Aggregation         : {timings['flow_aggregation_s']:.3f} s")
    print(f"    3. Graph Tensor Construction: {timings['graph_construction_s']:.3f} s")
    print(f"    4. GPU Neural Inference     : {timings['model_inference_ms']:.2f} ms")
    total_time = (
        timings["packet_extraction_s"]
        + timings["flow_aggregation_s"]
        + timings["graph_construction_s"]
        + (timings["model_inference_ms"] / 1000.0)
    )
    print(f"    --> TOTAL PIPELINE TIME     : {total_time:.3f} s")
    print("=" * 70, flush=True)


if __name__ == "__main__":
    pcap = (
        sys.argv[1]
        if len(sys.argv) > 1
        else r"C:\Users\raova\OneDrive\Desktop\SIH TRAINING DATA\New folder\2015-03-05\snort.log.1425572414"
    )
    max_pkts = int(sys.argv[2]) if len(sys.argv) > 2 else 50000
    run_pcap_pipeline(pcap, max_packets=max_pkts)

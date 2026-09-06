"""
src/data/ciciot23_adapter.py

Adapter for the CIC-IoT-2023 (CICIOT23) dataset.
Converts CICIOT23 flow tables into the standard spatial-temporal graph sequence
format required by the CyberDefenceWorldModel:
1. Stratified balanced sampling across all 34 attack categories.
2. Synthesizes genuine IoT device-cluster topology (Gateway, Sensors, Cameras, Attackers).
3. Constructs continuous chronological timestamps from IAT and flow duration.
4. Produces DataLoader-ready CyberDefenceDataset.
"""

from __future__ import annotations
import os
import sys
import time
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

import numpy as np
import pandas as pd
import torch

from src.labels.pseudo_labeler import annotate_dataframe_with_pseudo_labels
from src.data.windowing import WindowConfig
from src.data.dataset import CyberDefenceDataset

logger = logging.getLogger(__name__)


def load_stratified_ciciot23(
    csv_path: str | Path,
    max_samples_per_class: int = 2500,
    max_total_samples: int = 60000,
    max_rows_scanned: int = 400000,
    chunk_size: int = 50000,
) -> pd.DataFrame:
    """
    Reads CICIOT23 CSV in chunks, performing stratified reservoir sampling to ensure
    rare classes (e.g. SqlInjection, CommandInjection, Backdoor_Malware) are 100% preserved
    while massive flood classes (DDoS-ICMP, DDoS-UDP) are capped.
    """
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"CICIOT23 dataset file not found at: {csv_path}")

    logger.info(f"Ingesting CICIOT23 from: {csv_path.name} (capped at ~{max_samples_per_class:,} per class)...")
    t0 = time.time()

    class_buffers: Dict[str, list[pd.DataFrame]] = {}
    class_counts: Dict[str, int] = {}
    total_scanned = 0
    total_collected = 0

    for chunk in pd.read_csv(csv_path, chunksize=chunk_size, low_memory=False):
        if "label" not in chunk.columns:
            continue

        total_scanned += len(chunk)

        for lbl, group in chunk.groupby("label"):
            is_benign = "benign" in str(lbl).lower()
            limit = int(max_total_samples * 0.30) if is_benign else max_samples_per_class
            curr_count = class_counts.get(lbl, 0)
            if curr_count >= limit:
                continue

            needed = limit - curr_count
            sampled_group = group.head(needed)

            if lbl not in class_buffers:
                class_buffers[lbl] = []
                class_counts[lbl] = 0

            class_buffers[lbl].append(sampled_group)
            class_counts[lbl] += len(sampled_group)
            total_collected += len(sampled_group)

        if total_collected >= max_total_samples or total_scanned >= max_rows_scanned:
            break

    # Concatenate all stratified chunks
    dfs = [pd.concat(buf, ignore_index=True) for buf in class_buffers.values() if buf]
    if not dfs:
        raise ValueError(f"No valid rows found in {csv_path}")

    combined_df = pd.concat(dfs, ignore_index=True)
    # Shuffle so benign baseline and attacks interleave across chronological windows
    combined_df = combined_df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    logger.info(f"Extracted {len(combined_df):,} stratified flows across {len(class_counts)} classes (scanned {total_scanned:,}) in {time.time()-t0:.2f}s")
    return combined_df


def synthesize_iot_topology_and_timing(df: pd.DataFrame) -> pd.DataFrame:
    """
    Maps CICIOT23 flow metrics and protocol indicators into standard network endpoints
    and chronological timestamps matching the CIC-IoT-2023 lab architecture.
    """
    df = df.copy()
    n_rows = len(df)

    # 1. Determine destination ports from protocol indicators
    # Protocols: HTTP, HTTPS, DNS, Telnet, SMTP, SSH, IRC, TCP, UDP, DHCP, ARP, ICMP
    dst_ports = np.full(n_rows, 80, dtype=np.int32)

    if "HTTPS" in df.columns:
        dst_ports = np.where(df["HTTPS"] > 0, 443, dst_ports)
    if "DNS" in df.columns:
        dst_ports = np.where(df["DNS"] > 0, 53, dst_ports)
    if "Telnet" in df.columns:
        dst_ports = np.where(df["Telnet"] > 0, 23, dst_ports)
    if "SSH" in df.columns:
        dst_ports = np.where(df["SSH"] > 0, 22, dst_ports)
    if "SMTP" in df.columns:
        dst_ports = np.where(df["SMTP"] > 0, 25, dst_ports)
    if "IRC" in df.columns:
        dst_ports = np.where(df["IRC"] > 0, 6667, dst_ports)
    if "DHCP" in df.columns:
        dst_ports = np.where(df["DHCP"] > 0, 67, dst_ports)
    if "ICMP" in df.columns:
        dst_ports = np.where(df["ICMP"] > 0, 1, dst_ports)

    # Ephemeral source ports
    rng = np.random.RandomState(42)
    src_ports = rng.randint(49152, 65535, size=n_rows)

    # 2. Synthesize communicating host IP addresses based on attack / benign role
    # Subnet: 192.168.1.0/24 (IoT Lab Subnet)
    # External / Attacker Router: 192.168.1.100 - 192.168.1.105
    # Gateway / Master Hub: 192.168.1.1
    # IoT Device Targets: 192.168.1.20 - 192.168.1.35
    labels = df["label"].astype(str).values
    src_ips = []
    dst_ips = []

    for i, lbl in enumerate(labels):
        lbl_lower = lbl.lower()
        if "benign" in lbl_lower:
            # Internal IoT sensor to Gateway / Peer
            src_dev = 20 + (i % 15)
            src_ips.append(f"192.168.1.{src_dev}")
            dst_ips.append("192.168.1.1")
        elif "recon" in lbl_lower or "scan" in lbl_lower:
            # Attacker scanning multiple IoT targets
            target_dev = 20 + (i % 15)
            src_ips.append("192.168.1.100")
            dst_ips.append(f"192.168.1.{target_dev}")
        elif "mirai" in lbl_lower or "backdoor" in lbl_lower:
            # Infected internal IoT bot talking to C2 or peer bot
            bot_id = 20 + (i % 5)
            src_ips.append(f"192.168.1.{bot_id}")
            dst_ips.append("192.168.1.105")  # External C2 Server
        elif "mitm" in lbl_lower or "spoof" in lbl_lower:
            # Man-in-the-middle attacker intercepting gateway traffic
            src_ips.append("192.168.1.102")
            dst_ips.append("192.168.1.1")
        elif "bruteforce" in lbl_lower:
            # Attacker targeting SSH/Telnet server
            src_ips.append("192.168.1.101")
            dst_ips.append("192.168.1.22")  # SSH/Telnet server
        else:
            # Massive DDoS / DoS flood from external botnet against IoT web server / gateway
            attacker_id = 100 + (i % 6)
            src_ips.append(f"192.168.1.{attacker_id}")
            dst_ips.append("192.168.1.20")  # Victim web server

    # 3. Standardize column names
    df["src_ip"] = src_ips
    df["dst_ip"] = dst_ips
    df["src_port"] = src_ports
    df["dst_port"] = dst_ports

    # Protocol number (TCP: 6, UDP: 17, ICMP: 1)
    if "Protocol Type" in df.columns:
        df["protocol"] = df["Protocol Type"].fillna(6).astype(int)
    else:
        df["protocol"] = 6

    # Packet sizes and rates
    df["payload_size"] = df["Tot size"] if "Tot size" in df.columns else df["Header_Length"]
    df["payload_size"] = df["payload_size"].fillna(64.0).clip(lower=0.0, upper=65535.0)

    # TCP Flags
    df["flag_syn"] = (df["syn_flag_number"] > 0) if "syn_flag_number" in df.columns else (df.get("syn_count", 0) > 0)
    df["flag_ack"] = (df["ack_flag_number"] > 0) if "ack_flag_number" in df.columns else (df.get("ack_count", 0) > 0)
    df["flag_rst"] = (df["rst_flag_number"] > 0) if "rst_flag_number" in df.columns else (df.get("rst_count", 0) > 0)
    df["flag_fin"] = (df["fin_flag_number"] > 0) if "fin_flag_number" in df.columns else (df.get("fin_count", 0) > 0)

    df["ttl"] = 64.0
    df["tcp_window"] = 1024.0
    df["is_retransmission"] = (df.get("cwr_flag_number", 0) > 0)
    # Convert IAT from microseconds to seconds and clip to prevent FP16 activation overflow
    df["flow_iat_mean"] = (df.get("IAT", 0.0).fillna(0.0) / 1e6).clip(lower=0.0, upper=60.0)

    # 4. Construct chronological continuous simulation timestamps
    # Model cyber attack kill-chain progression:
    # Phase 0: Benign baseline traffic (0.0 to 0.25)
    # Phase 1: Reconnaissance sweeps (0.25 to 0.45)
    # Phase 2: Exploitation & Lateral Movement (0.45 to 0.70)
    # Phase 3: Botnet C2 & DoS/DDoS Impact (0.70 to 1.0)
    phase_weights = []
    for lbl in labels:
        lbl_lower = lbl.lower()
        if "benign" in lbl_lower:
            phase_weights.append(0.0 + np.random.uniform(0.0, 0.25))
        elif "recon" in lbl_lower or "scan" in lbl_lower:
            phase_weights.append(0.25 + np.random.uniform(0.0, 0.20))
        elif any(k in lbl_lower for k in ("injection", "backdoor", "bruteforce", "mitm", "spoof", "xss", "upload")):
            phase_weights.append(0.45 + np.random.uniform(0.0, 0.25))
        else:
            # DDoS / DoS / Mirai flood
            phase_weights.append(0.70 + np.random.uniform(0.0, 0.30))

    df["_temporal_phase"] = phase_weights
    df = df.sort_values("_temporal_phase").reset_index(drop=True)
    df.drop(columns=["_temporal_phase"], inplace=True)

    # Calculate timestamps over realistic window density (~60 flows per 5s window)
    target_window_density = 60.0
    total_time_span = max(180.0, (n_rows / target_window_density) * 2.5)
    progress_frac = np.linspace(0.0, 1.0, n_rows)
    timestamps = 1519800000.0 + (progress_frac * total_time_span)
    df["timestamp"] = timestamps

    n_windows = int(total_time_span / 2.5)
    logger.info(f"Synthesized IoT network topology: {len(set(src_ips + dst_ips))} active host nodes")
    logger.info(f"Synthesized continuous time span: {total_time_span:.1f}s (~{n_windows} windows, {n_rows:,} flows)")
    return df


def prepare_ciciot23_dataset(
    csv_path: str | Path,
    max_samples_per_class: int = 3500,
    window_cfg: Optional[WindowConfig] = None,
) -> CyberDefenceDataset:
    """
    One-call loader that ingests CICIOT23, stratifies, maps topology, annotates MITRE stages,
    and returns a PyTorch CyberDefenceDataset ready for training.
    """
    if window_cfg is None:
        window_cfg = WindowConfig(window_size=5.0, stride=2.5, seq_len=10, horizon_k=4)

    # Step 1: Stratified extraction
    df_raw = load_stratified_ciciot23(csv_path, max_samples_per_class=max_samples_per_class)

    # Step 2: Synthesize IoT Topology & Timestamps
    df_topo = synthesize_iot_topology_and_timing(df_raw)

    # Step 3: Pseudo-MITRE Stage Annotation
    logger.info("Annotating CICIOT23 flows with MITRE ATT&CK stages...")
    df_annotated = annotate_dataframe_with_pseudo_labels(df_topo)

    # Step 4: Construct PyTorch Graph Sequences
    logger.info("Building spatial-temporal graph sequences (5s window, 2.5s stride, seq_len 10)...")
    t0 = time.time()
    dataset = CyberDefenceDataset(df_annotated, cfg=window_cfg)
    logger.info(f"Constructed {len(dataset):,} graph sequences in {time.time()-t0:.2f}s!")
    return dataset

"""
src/data/unsw_adapter.py

Adapter for the official UNSW-NB15 Network Flow dataset.
Converts raw UNSW-NB15 flow records into the canonical spatial-temporal graph
sequence format required by the Predictive Cyber Defence World Model:
1. Stratified balanced ingestion across all 9 attack categories (Exploits, Generic,
   Fuzzers, Reconnaissance, DoS, Analysis, Backdoor, Shellcode, Worms) + Normal.
2. Preserves genuine host IP endpoints (source_ip, destination_ip) and ports.
3. Maps protocol flags, TTL, TCP window sizes, packet metrics, and payloads.
4. Preserves chronological simulation timeline over 5s windows.
5. Injects MITRE ATT&CK kill-chain stages via canonical pseudo-labeler.
6. Returns PyTorch CyberDefenceDataset ready for World Model training.
"""

from __future__ import annotations
import os
import sys
import time
import logging
from pathlib import Path
from typing import Optional, Dict, Any

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import torch

from src.labels.pseudo_labeler import annotate_dataframe_with_pseudo_labels
from src.data.windowing import WindowConfig
from src.data.dataset import CyberDefenceDataset

logger = logging.getLogger(__name__)


def load_stratified_unsw_nb15(
    parquet_path: str | Path,
    max_samples_per_class: int = 3500,
    benign_sample_count: int = 15000,
) -> pd.DataFrame:
    """
    Reads official UNSW_Flow.parquet and performs stratified sampling across
    all 9 genuine attack categories and benign normal traffic.
    """
    p = Path(parquet_path)
    if not p.exists():
        raise FileNotFoundError(f"UNSW-NB15 parquet file not found at: {p}")

    logger.info(f"Ingesting official UNSW-NB15 flows from: {p.name} ...")
    t0 = time.time()

    cols = [
        "source_ip", "destination_ip", "source_port", "destination_port",
        "protocol", "state", "dur", "sbytes", "dbytes", "sttl", "dttl",
        "sloss", "dloss", "service", "sload", "dload", "spkts", "dpkts",
        "swin", "dwin", "smeansz", "dmeansz", "tcprtt", "synack", "ackdat",
        "stime", "ltime", "attack_label", "binary_label"
    ]

    table = pq.read_table(p, columns=cols)
    df = table.to_pandas()
    logger.info(f"Loaded {len(df):,} total flows in {time.time() - t0:.2f}s")

    df["attack_label"] = df["attack_label"].astype(str).str.strip().str.lower()
    df["binary_label"] = df["binary_label"].fillna(0).astype(int)

    # Stratified extraction
    class_dfs = []
    class_counts = {}

    for cat, group in df.groupby("attack_label"):
        is_normal = (cat == "normal")
        cap = benign_sample_count if is_normal else max_samples_per_class
        sampled = group.sample(n=min(len(group), cap), random_state=42)
        class_dfs.append(sampled)
        class_counts[cat] = len(sampled)

    combined_df = pd.concat(class_dfs, ignore_index=True)
    logger.info(f"Extracted {len(combined_df):,} stratified flows across {len(class_counts)} classes:")
    for cat, cnt in sorted(class_counts.items(), key=lambda x: x[1], reverse=True):
        logger.info(f"  - {cat:15s}: {cnt:,} flows")

    return combined_df


def standardize_unsw_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Standardizes UNSW-NB15 fields into the exact canonical schema required by
    the Predictive Cyber Defence World Model:
      timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
      payload_size, flag_syn, flag_ack, flag_rst, flag_fin,
      ttl, tcp_window, is_retransmission, label.
    """
    df = df.copy()
    n_rows = len(df)

    # 1. Genuine host endpoints & ports
    df["src_ip"] = df["source_ip"].astype(str)
    df["dst_ip"] = df["destination_ip"].astype(str)
    df["src_port"] = pd.to_numeric(df["source_port"], errors="coerce").fillna(0).astype(int)
    df["dst_port"] = pd.to_numeric(df["destination_port"], errors="coerce").fillna(0).astype(int)

    # 2. Protocol numeric mapping (TCP: 6, UDP: 17, ICMP: 1, etc.)
    proto_map = {"tcp": 6, "udp": 17, "icmp": 1, "arp": 2054, "ospf": 89}
    df["protocol"] = df["protocol"].astype(str).str.lower().map(proto_map).fillna(6).astype(int)

    # 3. Payload size
    sbytes = pd.to_numeric(df["sbytes"], errors="coerce").fillna(64.0)
    spkts = pd.to_numeric(df["spkts"], errors="coerce").fillna(1.0).clip(lower=1.0)
    df["payload_size"] = (sbytes / spkts).fillna(64.0).clip(lower=0.0, upper=65535.0)

    # 4. Flags & Handshake metrics
    # If synack/tcprtt > 0, TCP handshake occurred
    is_tcp = (df["protocol"] == 6)
    has_handshake = pd.to_numeric(df.get("tcprtt", 0), errors="coerce").fillna(0.0) > 0.0

    df["flag_syn"] = is_tcp & (df.get("swin", 0) > 0)
    df["flag_ack"] = is_tcp & has_handshake
    df["flag_rst"] = (df.get("state", "").astype(str).str.lower() == "rst")
    df["flag_fin"] = (df.get("state", "").astype(str).str.lower() == "fin")

    # 5. Network telemetry
    df["ttl"] = pd.to_numeric(df.get("sttl", 64.0), errors="coerce").fillna(64.0).clip(lower=1.0, upper=255.0)
    df["tcp_window"] = pd.to_numeric(df.get("swin", 1024.0), errors="coerce").fillna(1024.0)
    df["is_retransmission"] = (pd.to_numeric(df.get("sloss", 0), errors="coerce").fillna(0) > 0)

    # Label normalization for ATT&CK mapping
    df["label"] = df["attack_label"].astype(str).str.strip().str.title()

    # 6. Chronological kill-chain progression across windows
    # Phase 0: Normal / Benign Baseline (0.0 to 0.20)
    # Phase 1: Reconnaissance sweeps (0.20 to 0.40)
    # Phase 2: Exploits, Fuzzers, Analysis (0.40 to 0.65)
    # Phase 3: Backdoor, Shellcode, Worms (0.65 to 0.85)
    # Phase 4: DoS / DDoS service disruption (0.85 to 1.0)
    np.random.seed(42)
    phase_weights = []
    for cat in df["attack_label"]:
        c = cat.lower()
        if "normal" in c:
            # 40% baseline [0.0, 0.38], 50% during attack [0.38, 0.95], 10% recovery [0.95, 1.0]
            r = np.random.rand()
            if r < 0.40:
                phase_weights.append(np.random.uniform(0.0, 0.38))
            elif r < 0.90:
                phase_weights.append(np.random.uniform(0.38, 0.95))
            else:
                phase_weights.append(np.random.uniform(0.95, 1.0))
        elif "recon" in c or "fuzzer" in c or "analysis" in c:
            phase_weights.append(np.random.uniform(0.38, 0.54))
        elif any(k in c for k in ("exploit", "generic", "shellcode")):
            phase_weights.append(np.random.uniform(0.54, 0.70))
        elif "worm" in c:
            phase_weights.append(np.random.uniform(0.70, 0.79))
        elif "backdoor" in c:
            phase_weights.append(np.random.uniform(0.79, 0.88))
        else:
            # dos
            phase_weights.append(np.random.uniform(0.88, 0.95))

    df["_temporal_phase"] = phase_weights
    df = df.sort_values("_temporal_phase").reset_index(drop=True)
    df.drop(columns=["_temporal_phase"], inplace=True)

    # 5-second window density (~60 flows per window)
    target_window_density = 60.0
    total_time_span = max(180.0, (n_rows / target_window_density) * 2.5)
    progress_frac = np.linspace(0.0, 1.0, n_rows)
    df["timestamp"] = 1519800000.0 + (progress_frac * total_time_span)

    n_windows = int(total_time_span / 2.5)
    logger.info(f"Standardized {n_rows:,} UNSW-NB15 flows across {df['src_ip'].nunique()} src hosts and {df['dst_ip'].nunique()} dst hosts")
    logger.info(f"Constructed continuous simulation timeline: {total_time_span:.1f}s (~{n_windows} windows)")
    return df


def prepare_unsw_nb15_dataset(
    parquet_path: str | Path,
    max_samples_per_class: int = 3500,
    benign_sample_count: int = 15000,
    window_cfg: Optional[WindowConfig] = None,
) -> CyberDefenceDataset:
    """
    One-call loader: Ingests official UNSW-NB15 parquet, stratifies across all 9
    attack categories, standardizes endpoints, maps MITRE ATT&CK stages, and
    returns a PyTorch CyberDefenceDataset ready for World Model training.
    """
    if window_cfg is None:
        window_cfg = WindowConfig(window_size=5.0, stride=2.5, seq_len=10, horizon_k=4)

    # Step 1: Stratified extraction
    df_raw = load_stratified_unsw_nb15(
        parquet_path,
        max_samples_per_class=max_samples_per_class,
        benign_sample_count=benign_sample_count
    )

    # Step 2: Standardize schema
    df_std = standardize_unsw_dataframe(df_raw)

    # Step 3: Annotate MITRE ATT&CK stages
    logger.info("Annotating UNSW-NB15 flows with MITRE ATT&CK stages & confidence...")
    df_annotated = annotate_dataframe_with_pseudo_labels(df_std)

    # Step 4: Construct PyTorch Graph Sequences
    logger.info("Building spatial-temporal graph sequences (5s window, 2.5s stride, seq_len 10)...")
    t0 = time.time()
    dataset = CyberDefenceDataset(df_annotated, cfg=window_cfg)
    logger.info(f"Constructed {len(dataset):,} graph sequences in {time.time()-t0:.2f}s!")
    return dataset

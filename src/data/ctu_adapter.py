"""
src/data/ctu_adapter.py

Adapter for the official CTU-IDSEVAL-6 (CTU-13) dataset.
Parses Zeek .conn-labeled.log files (from zeek.zip or directory) into standardized
telemetry DataFrames with genuine IP endpoints, TCP flag history, and MITRE ATT&CK stages,
then builds the CyberDefenceDataset for the World Model.
"""

from __future__ import annotations
import os
import io
import sys
import time
import zipfile
import logging
from pathlib import Path
from typing import Optional, Dict, List, Any

import numpy as np
import pandas as pd
import torch

from src.labels.pseudo_labeler import annotate_dataframe_with_pseudo_labels
from src.data.windowing import WindowConfig
from src.data.dataset import CyberDefenceDataset

logger = logging.getLogger(__name__)

PROTO_MAP = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
}


def parse_zeek_conn_log(file_bytes: bytes, filename: str) -> pd.DataFrame:
    """
    Parses a Zeek .conn-labeled.log file content into a clean Pandas DataFrame
    using the header line `#fields` to identify columns dynamically.
    """
    lines = file_bytes.decode("utf-8", errors="replace").splitlines()
    col_names = []
    data_lines = []

    for line in lines:
        if line.startswith("#fields"):
            col_names = line.strip().split("\t")[1:]
        elif not line.startswith("#") and line.strip():
            data_lines.append(line)

    if not col_names or not data_lines:
        logger.warning(f"Empty or malformed Zeek log: {filename}")
        return pd.DataFrame()

    df = pd.read_csv(io.StringIO("\n".join(data_lines)), sep="\t", header=None, names=col_names, low_memory=False)
    return df


def load_ctu_idseval_data(
    dataset_path: str | Path,
    max_samples_per_capture: int = 15000,
) -> pd.DataFrame:
    """
    Reads all 6 CTU-IDSEVAL-6 captures from zeek.zip (or extracted zeek directory)
    and standardizes them into a single coherent network flow DataFrame.
    """
    p = Path(dataset_path)
    zip_path = None
    if p.is_file() and p.suffix == ".zip":
        zip_path = p
    elif p.is_dir():
        cand = p / "zeek.zip"
        if cand.exists():
            zip_path = cand

    dfs = []
    t0 = time.time()

    if zip_path and zip_path.exists():
        logger.info(f"Extracting Zeek conn logs from: {zip_path.name}...")
        with zipfile.ZipFile(zip_path) as z:
            conn_logs = [f for f in z.namelist() if f.endswith(".conn-labeled.log") and not f.startswith("__")]
            logger.info(f"Found {len(conn_logs)} Zeek labeled captures in zip archive")
            for log_name in sorted(conn_logs):
                raw_bytes = z.read(log_name)
                df_cap = parse_zeek_conn_log(raw_bytes, log_name)
                if df_cap.empty:
                    continue
                if len(df_cap) > max_samples_per_capture:
                    df_cap = df_cap.sample(n=max_samples_per_capture, random_state=42).reset_index(drop=True)
                df_cap["_capture_file"] = Path(log_name).name
                dfs.append(df_cap)
                logger.info(f"  Loaded {len(df_cap):,} flows from {Path(log_name).name}")
    else:
        # Search for .conn-labeled.log on disk
        log_files = list(p.glob("**/*.conn-labeled.log"))
        logger.info(f"Found {len(log_files)} Zeek log files in {p}")
        for lf in sorted(log_files):
            raw_bytes = lf.read_bytes()
            df_cap = parse_zeek_conn_log(raw_bytes, lf.name)
            if df_cap.empty:
                continue
            if len(df_cap) > max_samples_per_capture:
                df_cap = df_cap.sample(n=max_samples_per_capture, random_state=42).reset_index(drop=True)
            df_cap["_capture_file"] = lf.name
            dfs.append(df_cap)
            logger.info(f"  Loaded {len(df_cap):,} flows from {lf.name}")

    if not dfs:
        raise ValueError(f"No valid Zeek conn logs found in {dataset_path}")

    combined = pd.concat(dfs, ignore_index=True)
    logger.info(f"Successfully loaded {len(combined):,} total flows across all captures in {time.time()-t0:.2f}s")
    return combined


def standardize_ctu_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Standardizes Zeek flow records into the exact format required by
    the Predictive Cyber Defence World Model:
    timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
    payload_size, flag_syn, flag_ack, flag_rst, flag_fin,
    ttl, tcp_window, is_retransmission, label.
    """
    df = df.copy()
    n_rows = len(df)

    # 1. Genuine host endpoints
    df["src_ip"] = df["id.orig_h"].astype(str)
    df["dst_ip"] = df["id.resp_h"].astype(str)
    df["src_port"] = pd.to_numeric(df["id.orig_p"], errors="coerce").fillna(0).astype(int)
    df["dst_port"] = pd.to_numeric(df["id.resp_p"], errors="coerce").fillna(0).astype(int)

    # 2. Protocol conversion
    df["protocol"] = df["proto"].astype(str).str.lower().map(PROTO_MAP).fillna(6).astype(int)

    # 3. Payload size
    orig_bytes = pd.to_numeric(df.get("orig_ip_bytes", df.get("orig_bytes", 0)), errors="coerce").fillna(0)
    resp_bytes = pd.to_numeric(df.get("resp_ip_bytes", df.get("resp_bytes", 0)), errors="coerce").fillna(0)
    df["payload_size"] = (orig_bytes + resp_bytes).clip(lower=0.0, upper=65535.0)

    # 4. TCP history flags
    # Zeek history encoding: S = SYN, H = SYN-ACK, A = ACK, D = Payload, F = FIN, R = RST
    history_str = df["history"].astype(str).fillna("")
    df["flag_syn"] = history_str.str.contains("S|s", regex=True)
    df["flag_ack"] = history_str.str.contains("A|a|H|h", regex=True)
    df["flag_rst"] = history_str.str.contains("R|r", regex=True)
    df["flag_fin"] = history_str.str.contains("F|f", regex=True)

    df["ttl"] = 64.0
    df["tcp_window"] = 1024.0

    # Retransmission detection: missed bytes > 0 or multiple SYNs
    missed = pd.to_numeric(df.get("missed_bytes", 0), errors="coerce").fillna(0)
    multiple_syn = history_str.str.count("S") > 1
    df["is_retransmission"] = (missed > 0) | multiple_syn

    # 5. Label attribution: prioritize detailedlabel if specific attack, else high-level label
    labels = []
    raw_labels = df["label"].astype(str).values
    detailed_labels = df["detailedlabel"].astype(str).values if "detailedlabel" in df.columns else raw_labels
    capture_files = df.get("_capture_file", "").astype(str).values

    for i in range(n_rows):
        lbl = raw_labels[i].strip()
        det = detailed_labels[i].strip()
        cap = capture_files[i].lower()

        if "portscan" in cap or "portscan" in det.lower():
            labels.append("PortScan")
        elif "malware" in cap or "botnet" in det.lower() or "cc" in det.lower():
            labels.append(det if det and det != "-" else "From_Malware")
        elif lbl.lower() in ("malicious", "attack"):
            labels.append(det if det and det != "-" else "Malicious")
        else:
            labels.append("Benign")

    df["label"] = labels

    # 6. Chronological continuous simulation timestamps
    # Sort by attack kill-chain progression:
    # Phase 0: Benign user traffic (0.0 to 0.30)
    # Phase 1: PortScan / Reconnaissance (0.30 to 0.60)
    # Phase 2: Malware C2 / Botnet (0.60 to 1.00)
    phase_weights = []
    for lbl in labels:
        lbl_lower = lbl.lower()
        if "benign" in lbl_lower:
            phase_weights.append(0.0 + np.random.uniform(0.0, 0.30))
        elif "portscan" in lbl_lower or "scan" in lbl_lower:
            phase_weights.append(0.30 + np.random.uniform(0.0, 0.30))
        else:
            # Malware / CC
            phase_weights.append(0.60 + np.random.uniform(0.0, 0.40))

    df["_phase"] = phase_weights
    df = df.sort_values("_phase").reset_index(drop=True)
    df.drop(columns=["_phase"], inplace=True)

    # Generate continuous timestamp stream with realistic density (~60 flows per 5s window)
    target_density = 60.0
    total_time_span = max(180.0, (n_rows / target_density) * 2.5)
    progress = np.linspace(0.0, 1.0, n_rows)
    df["timestamp"] = 1519800000.0 + (progress * total_time_span)

    n_windows = int(total_time_span / 2.5)
    logger.info(f"Standardized {n_rows:,} CTU-IDSEVAL flows across {df['src_ip'].nunique()} src hosts and {df['dst_ip'].nunique()} dst hosts")
    logger.info(f"Synthesized continuous time span: {total_time_span:.1f}s (~{n_windows} windows)")
    return df


def prepare_ctu_idseval_dataset(
    dataset_path: str | Path,
    max_samples_per_capture: int = 12000,
    window_cfg: Optional[WindowConfig] = None,
) -> CyberDefenceDataset:
    """
    Full pipeline: Ingests CTU Zeek logs, standardizes endpoints and flags,
    annotates MITRE ATT&CK stages, and returns PyTorch CyberDefenceDataset.
    """
    if window_cfg is None:
        window_cfg = WindowConfig(window_size=5.0, stride=2.5, seq_len=10, horizon_k=4)

    # 1. Load raw Zeek logs
    df_raw = load_ctu_idseval_data(dataset_path, max_samples_per_capture=max_samples_per_capture)

    # 2. Standardize fields
    df_std = standardize_ctu_dataframe(df_raw)

    # 3. Annotate MITRE ATT&CK stages
    logger.info("Annotating CTU-IDSEVAL flows with MITRE ATT&CK stages...")
    df_annotated = annotate_dataframe_with_pseudo_labels(df_std)

    # 4. Build PyTorch Graph Sequences
    logger.info("Constructing spatial-temporal graph sequences (5s window, 2.5s stride, seq_len 10)...")
    t0 = time.time()
    dataset = CyberDefenceDataset(df_annotated, cfg=window_cfg)
    logger.info(f"Constructed {len(dataset):,} graph sequences in {time.time()-t0:.2f}s!")
    return dataset

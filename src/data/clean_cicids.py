"""
clean_cicids.py — Data sanitization pipeline for CIC-IDS2018 CSVs.
Handles known traps:
- Trailing whitespace on labels -> .str.strip()
- Flow Bytes/s & Flow Packets/s containing 'inf'/'Infinity' -> converted to NaN and imputed
- Deduplication on key: (src_ip, src_port, dst_ip, dst_port, protocol, timestamp)
"""

import os
import pandas as pd
import numpy as np
from typing import Optional

DEDUPE_COLS = ["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "timestamp"]

COLUMN_MAPPING = {
    "Src IP": "src_ip",
    "Source IP": "src_ip",
    "Src Port": "src_port",
    "Source Port": "src_port",
    "Dst IP": "dst_ip",
    "Destination IP": "dst_ip",
    "Dst Port": "dst_port",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Label": "label",
    "Flow Duration": "flow_duration",
    "Tot Fwd Pkts": "tot_fwd_pkts",
    "Tot Bwd Pkts": "tot_bwd_pkts",
    "TotLen Fwd Pkts": "tot_len_fwd_pkts",
    "TotLen Bwd Pkts": "tot_len_bwd_pkts",
    "Flow Byts/s": "flow_byts_s",
    "Flow Bytes/s": "flow_byts_s",
    "Flow Pkts/s": "flow_pkts_s",
    "Flow Packets/s": "flow_pkts_s",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "SYN Flag Cnt": "syn_flag_cnt",
    "ACK Flag Cnt": "ack_flag_cnt",
    "FIN Flag Cnt": "fin_flag_cnt",
    "RST Flag Cnt": "rst_flag_cnt",
    "PSH Flag Cnt": "psh_flag_cnt",
    "URG Flag Cnt": "urg_flag_cnt",
}


def standardize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Standardizes column names to lowercase snake_case based on known variations."""
    df = df.copy()
    rename_dict = {}
    for col in df.columns:
        clean_name = col.strip()
        if clean_name in COLUMN_MAPPING:
            rename_dict[col] = COLUMN_MAPPING[clean_name]
        else:
            rename_dict[col] = clean_name.lower().replace(" ", "_").replace("/", "_")
    df = df.rename(columns=rename_dict)
    return df


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans DataFrame:
    1. Standardizes columns
    2. Strips whitespace in label strings
    3. Replaces +/- inf / 'Infinity' / strings with NaN
    4. Handles missing timestamps and parses them into datetime
    5. Deduplicates on flow key
    """
    df = standardize_columns(df)

    if "label" in df.columns:
        df["label"] = df["label"].astype(str).str.strip()

    # Replace infinite values and common string representations of infinity
    df = df.replace([np.inf, -np.inf, "Infinity", "-Infinity", "inf", "-inf"], np.nan)

    # Convert numeric columns where possible
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0.0)

    # Parse timestamps
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])
        df = df.sort_values("timestamp").reset_index(drop=True)

    # Deduplication
    present_dedupe_cols = [c for c in DEDUPE_COLS if c in df.columns]
    if present_dedupe_cols:
        df = df.drop_duplicates(subset=present_dedupe_cols).reset_index(drop=True)

    return df


def clean_cicids_file(input_path: str, output_path: Optional[str] = None) -> pd.DataFrame:
    """Reads a raw CIC-IDS2018 CSV, cleans it, and optionally saves to interim directory."""
    df = pd.read_csv(input_path, low_memory=False)
    cleaned_df = clean_dataframe(df)

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        cleaned_df.to_csv(output_path, index=False)

    return cleaned_df

"""
file_upload.py — Ingestion handler for PCAP, PCAPNG, and CSV files.
Parses multi-GB captures or flow CSVs into a standardized DataFrame.
"""

import os
import sys
import tempfile
from pathlib import Path
import pandas as pd
from typing import Tuple, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.data.packet_features import extract_packet_features, add_flow_level_derived_features
from src.data.clean_cicids import clean_dataframe
from src.labels.pseudo_labeler import annotate_dataframe_with_pseudo_labels


def process_uploaded_file(
    uploaded_file,
    max_preview_packets: int = 200_000
) -> Tuple[pd.DataFrame, str]:
    """
    Processes an uploaded file from Streamlit file_uploader.
    Returns: (df, file_type)
    """
    file_name = uploaded_file.name.lower()
    suffix = os.path.splitext(file_name)[1]

    # Save to a temporary file on disk for streaming parsers
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(uploaded_file.getbuffer())
        tmp_path = tmp.name

    try:
        if suffix in [".pcap", ".pcapng", ".cap"]:
            df = extract_packet_features(tmp_path, packet_limit=max_preview_packets)
            df = add_flow_level_derived_features(df)
            df = annotate_dataframe_with_pseudo_labels(df)
            file_type = "Raw Packet Capture (PCAP)"
        elif suffix in [".parquet"]:
            df = pd.read_parquet(tmp_path)
            file_type = "Preprocessed Parquet Telemetry"
        elif suffix in [".csv"]:
            raw_df = pd.read_csv(tmp_path, nrows=max_preview_packets, low_memory=False)
            df = clean_dataframe(raw_df)
            df = annotate_dataframe_with_pseudo_labels(df)
            file_type = "NetFlow / IPFIX (CSV)"
        else:
            raise ValueError(f"Unsupported file format: {suffix}. Please upload .pcap, .pcapng, .csv, or .parquet")
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    return df, file_type

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

from src.data.packet_features import parse_pcap_to_dataframe
from src.data.clean_cicids import clean_dataframe


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
            df = parse_pcap_to_dataframe(tmp_path, max_packets=max_preview_packets)
            file_type = "Raw Packet Capture (PCAP)"
        elif suffix in [".csv"]:
            raw_df = pd.read_csv(tmp_path, nrows=max_preview_packets, low_memory=False)
            df = clean_dataframe(raw_df)
            file_type = "NetFlow / IPFIX (CSV)"
        else:
            raise ValueError(f"Unsupported file format: {suffix}. Please upload .pcap, .pcapng, or .csv")
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    return df, file_type

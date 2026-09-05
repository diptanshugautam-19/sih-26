"""
src/data/live_sniffer.py

Real-Time Live Network Interface Sniffer for World Model.
Captures actual IP packets directly from active NIC (Ethernet/Wi-Fi)
and converts them into standardized telemetry DataFrames with pseudo-MITRE labels.
"""

from __future__ import annotations
import time
from typing import Optional
import pandas as pd
import numpy as np

try:
    from scapy.all import sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from src.data.packet_features import _packet_row_fast, _COLUMNS, add_flow_level_derived_features
from src.labels.pseudo_labeler import annotate_dataframe_with_pseudo_labels


def capture_live_telemetry(
    duration: float = 3.0,
    max_packets: int = 200,
    bpf_filter: Optional[str] = "ip"
) -> pd.DataFrame:
    """
    Captures live packets from the network adapter for `duration` seconds,
    formats them into a clean telemetry DataFrame, and attaches MITRE ATT&CK labels.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not installed. Live sniffing unavailable.")

    t_start = time.time()
    try:
        pkts = sniff(
            count=max_packets,
            timeout=duration,
            filter=bpf_filter if bpf_filter else None
        )
    except Exception:
        pkts = sniff(count=max_packets, timeout=duration)

    rows = []
    for p in pkts:
        raw = bytes(p)
        r = _packet_row_fast(raw)
        if r is not None:
            r["timestamp"] = float(p.time) if hasattr(p, "time") else time.time()
            rows.append(r)

    if not rows:
        return pd.DataFrame(columns=_COLUMNS + ["flow_key", "mitre_stage_id", "mitre_stage_name", "mitre_confidence"])

    df = pd.DataFrame(rows, columns=_COLUMNS)
    df = add_flow_level_derived_features(df)
    df = annotate_dataframe_with_pseudo_labels(df)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df

"""
windowing.py — Time-window aggregation & dataset sequence slicing.

Locked architecture decisions:
- Window size: 5.0s (fixed)
- Input stride: 2.5s (50% overlap between consecutive input windows)
- Target window: Strictly non-overlapping with the last input window (prevents target leakage)
- Sequence length: 10 input windows (~27.5s span)
- Prediction horizon K: 3-5 windows (default K=4 non-overlapping targets)
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Any, Tuple
from src.labels.attack_mapping import map_label_to_stage, is_malicious


def slice_into_windows(
    df: pd.DataFrame,
    window_size_sec: float = 5.0,
    stride_sec: float = 2.5,
    skip_empty: bool = True
) -> List[Dict[str, Any]]:
    """
    Slices a time-sorted DataFrame into fixed time windows.
    Returns a list of window dicts with window boundaries and flows.
    """
    if df.empty or "timestamp" not in df.columns:
        return []

    # Ensure timestamp is datetime
    if not np.issubdtype(df["timestamp"].dtype, np.datetime64):
        df = df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"])

    start_time = df["timestamp"].min()
    end_time = df["timestamp"].max()

    windows = []
    current_start = start_time
    window_delta = pd.Timedelta(seconds=window_size_sec)
    stride_delta = pd.Timedelta(seconds=stride_sec)

    while current_start + window_delta <= end_time + window_delta:
        current_end = current_start + window_delta
        mask = (df["timestamp"] >= current_start) & (df["timestamp"] < current_end)
        window_flows = df[mask]

        if skip_empty and len(window_flows) == 0:
            current_start += stride_delta
            continue

        # Extract dominant/highest attack stage if any malicious flows exist
        labels = window_flows["label"].tolist() if "label" in window_flows.columns else []
        malicious_present = any(is_malicious(lbl) for lbl in labels)
        
        # Max stage ID in window (or 0 for Benign)
        stages = [map_label_to_stage(lbl)[0] for lbl in labels] if labels else [0]
        max_stage = max(stages) if stages else 0

        windows.append({
            "start_time": current_start,
            "end_time": current_end,
            "flows": window_flows,
            "flow_count": len(window_flows),
            "is_malicious": malicious_present,
            "stage_id": max_stage
        })

        current_start += stride_delta

    return windows


def create_sequences_and_targets(
    windows: List[Dict[str, Any]],
    seq_len: int = 10,
    k_horizon: int = 4,
    window_size_sec: float = 5.0
) -> List[Dict[str, Any]]:
    """
    Creates sequences of input windows and non-overlapping target windows.

    CRITICAL RULE (Zero Target Leakage):
    - Input sequence: [W_0, W_1, ..., W_{seq_len - 1}]
    - Last input window ends at: W_{seq_len - 1}['end_time']
    - Target windows: Next K windows that start >= last input window's end_time.
    """
    samples = []
    target_duration = pd.Timedelta(seconds=window_size_sec)

    for i in range(len(windows) - seq_len):
        input_seq = windows[i : i + seq_len]
        last_input_end = input_seq[-1]["end_time"]

        # Search for non-overlapping target windows strictly starting at or after last_input_end
        future_targets = []
        for candidate in windows[i + seq_len :]:
            if candidate["start_time"] >= last_input_end:
                future_targets.append(candidate)
            if len(future_targets) == k_horizon:
                break

        if len(future_targets) == k_horizon:
            # Aggregate infiltration label over the K-horizon: 1.0 if any window in horizon is malicious
            infiltration_prob_ground_truth = 1.0 if any(t["is_malicious"] for t in future_targets) else 0.0
            # Target stage is the maximum stage seen in the horizon
            target_stages = [t["stage_id"] for t in future_targets]
            target_stage = max(target_stages) if target_stages else 0

            samples.append({
                "inputs": input_seq,
                "targets": future_targets,
                "last_input_end": last_input_end,
                "first_target_start": future_targets[0]["start_time"],
                "infiltration_target": infiltration_prob_ground_truth,
                "stage_target": target_stage
            })

    return samples

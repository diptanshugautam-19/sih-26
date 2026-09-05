"""
src/labels/window_labels.py

Aggregates packet/flow-level MITRE labels into structured 5-second window-level targets.

KEY RESPONSIBILITIES:
1. Robust window aggregation: When a window contains 95% benign packets and 5% malicious attack
   traffic (e.g. stealthy beaconing or scan probes), naive majority voting would incorrectly classify
   the entire window as Benign. This module isolates the attack subset when present, selecting the
   dominant or highest-severity ATT&CK stage.
2. Confidence weighting: Averages confidence scores over active attack flows.
3. Multi-window trajectory tracking: Extracts stage transitions across consecutive time slices.
"""

from __future__ import annotations
from typing import Dict, List, Tuple, Any, Optional
import numpy as np
import pandas as pd
from src.labels.attack_mapping import STAGE_NAMES


def aggregate_window_mitre_label(
    window_df: pd.DataFrame,
    min_malicious_rows: int = 1,
) -> Tuple[int, str, float, bool]:
    """
    Aggregates packet/flow labels in a window into a single window-level MITRE target.

    Args:
        window_df: DataFrame of packets/flows within the time window.
        min_malicious_rows: Minimum malicious rows required to mark the window malicious.

    Returns:
        (mitre_stage_id, mitre_stage_name, confidence, is_malicious)
    """
    if window_df.empty:
        return 0, "Benign", 1.0, False

    # Check for mitre_stage_id column
    if "mitre_stage_id" in window_df.columns:
        stages = window_df["mitre_stage_id"].fillna(0).astype(int).to_numpy()
        confs = window_df["mitre_confidence"].fillna(0.5).astype(float).to_numpy() if "mitre_confidence" in window_df.columns else np.full(len(stages), 0.5)

        mal_mask = stages > 0
        if np.sum(mal_mask) >= min_malicious_rows:
            mal_stages = stages[mal_mask]
            mal_confs = confs[mal_mask]

            # Choose the most frequent malicious stage in this window
            vals, counts = np.unique(mal_stages, return_counts=True)
            dominant_stage = int(vals[np.argmax(counts)])
            avg_conf = float(np.mean(mal_confs[mal_stages == dominant_stage]))
            stage_name = STAGE_NAMES.get(dominant_stage, "Unknown")
            return dominant_stage, stage_name, avg_conf, True
        else:
            # Benign window
            benign_confs = confs[~mal_mask] if len(confs) > 0 else [0.95]
            avg_conf = float(np.mean(benign_confs)) if len(benign_confs) > 0 else 0.95
            return 0, "Benign", avg_conf, False

    # Check for raw label column fallback
    label_col = "label" if "label" in window_df.columns else ("Label" if "Label" in window_df.columns else None)
    if label_col is not None:
        from src.labels.attack_mapping import map_label_to_stage
        mapped = [map_label_to_stage(lbl) for lbl in window_df[label_col].dropna()]
        mal_stages = [sid for sid, _, _ in mapped if sid > 0]
        if len(mal_stages) >= min_malicious_rows:
            vals, counts = np.unique(mal_stages, return_counts=True)
            dominant_stage = int(vals[np.argmax(counts)])
            return dominant_stage, STAGE_NAMES.get(dominant_stage, "Unknown"), 0.85, True
        return 0, "Benign", 0.95, False

    return 0, "Benign", 1.0, False


def extract_stage_transitions(
    window_stages: List[int],
) -> List[Tuple[int, int]]:
    """
    Extracts directed MITRE stage transitions across consecutive window sequence:
    e.g. [1, 1, 3, 3, 4] -> [(1, 1), (1, 3), (3, 3), (3, 4)]
    """
    if len(window_stages) < 2:
        return []
    return [(window_stages[i], window_stages[i + 1]) for i in range(len(window_stages) - 1)]

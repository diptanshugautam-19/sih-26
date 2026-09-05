"""
src/eval/unseen_attacks.py

Out-of-Distribution Attack Generalisation Suite.
Evaluates model robustness when presented with entire attack types held out
during training (e.g., zero-day or unfamiliar attack classes like Slowloris).
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
import torch

from src.eval.metrics import compute_classification_metrics, compute_brier_score, compute_ece
from src.eval.ood_score import compute_distribution_kl_divergence, OODScorer


def split_by_held_out_attacks(
    df: pd.DataFrame,
    held_out_attack_names: List[str],
    label_col: str = "label",
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Partitions DataFrame into:
    1. train_seen_df: Benign traffic + seen attack categories
    2. held_out_df: The specified novel/unseen attack types
    """
    normalized_held_out = [a.lower().strip() for a in held_out_attack_names]
    mask = df[label_col].astype(str).str.lower().str.strip().isin(normalized_held_out)
    held_out_df = df[mask].copy()
    seen_df = df[~mask].copy()
    return seen_df, held_out_df


def evaluate_unseen_attack_robustness(
    y_seen_true: np.ndarray,
    y_seen_prob: np.ndarray,
    y_unseen_true: np.ndarray,
    y_unseen_prob: np.ndarray,
    seen_features: Optional[np.ndarray] = None,
    unseen_features: Optional[np.ndarray] = None,
    attack_name: str = "Held-Out Attack",
) -> Dict[str, Any]:
    """
    Evaluates generalisation gap between seen test data and novel attack traffic.
    """
    seen_metrics = compute_classification_metrics(y_seen_true, y_seen_prob)
    unseen_metrics = compute_classification_metrics(y_unseen_true, y_unseen_prob)

    f1_seen = float(seen_metrics["f1"])
    f1_unseen = float(unseen_metrics["f1"])
    gen_retention = (f1_unseen / max(f1_seen, 1e-6)) if f1_seen > 0 else 0.0

    kl_div = float("nan")
    mean_ood_score = float("nan")
    if seen_features is not None and unseen_features is not None:
        try:
            kl_div = compute_distribution_kl_divergence(seen_features, unseen_features)
            scorer = OODScorer().fit(seen_features)
            ood_scores = scorer.score(unseen_features)
            mean_ood_score = float(np.mean(ood_scores))
        except Exception:
            pass

    return {
        "attack_name": attack_name,
        "seen_test_metrics": seen_metrics,
        "unseen_attack_metrics": unseen_metrics,
        "generalisation_retention_ratio": round(float(gen_retention), 4),
        "distribution_kl_divergence": round(float(kl_div), 4),
        "mean_ood_score": round(float(mean_ood_score), 4),
        "brier_seen": round(compute_brier_score(y_seen_true, y_seen_prob), 4),
        "brier_unseen": round(compute_brier_score(y_unseen_true, y_unseen_prob), 4),
    }

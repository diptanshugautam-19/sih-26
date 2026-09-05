"""
src/eval/metrics.py

World Model Evaluation Metrics Suite.

Covers all metrics required by the NCIIPC brief AND the additional
"world model quality" metrics that distinguish this from a plain classifier:

Standard Classification Metrics (for comparison with LR baseline):
    - F1, Precision, Recall, FPR (per-class and macro)

World Model Quality Metrics:
    - Lead-Time: How many seconds before attack onset does the model cross threshold?
    - Grounded Dynamics MSE: Did we actually predict future telemetry correctly?
    - Calibration (ECE / Brier Score): Is the probability output trustworthy?
    - Per-Stage MITRE F1: Not just overall accuracy — per kill-chain stage

OOD Generalisation:
    - OOD divergence score (KL divergence between seen and unseen attack distributions)
"""

from __future__ import annotations
from typing import Dict, List, Optional, Tuple
import numpy as np


def compute_classification_metrics(
    y_true: np.ndarray,
    y_pred_prob: np.ndarray,
    threshold: float = 0.5,
) -> Dict:
    """F1, Precision, Recall, FPR at the given threshold."""
    from sklearn.metrics import (
        f1_score, precision_score, recall_score, confusion_matrix, roc_auc_score
    )
    y_pred = (y_pred_prob >= threshold).astype(int)
    y_true_bin = (y_true > 0.5).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_true_bin, y_pred, labels=[0, 1]).ravel()
    fpr = fp / max(fp + tn, 1)

    try:
        auroc = roc_auc_score(y_true_bin, y_pred_prob)
    except Exception:
        auroc = float("nan")

    return {
        "f1":        f1_score(y_true_bin, y_pred, zero_division=0),
        "precision": precision_score(y_true_bin, y_pred, zero_division=0),
        "recall":    recall_score(y_true_bin, y_pred, zero_division=0),
        "fpr":       fpr,
        "auroc":     auroc,
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
    }


def compute_lead_time(
    timestamps: np.ndarray,
    y_pred_prob: np.ndarray,
    t_attack: float,
    threshold: float = 0.7,
) -> Dict:
    """
    Computes lead-time: how many seconds before t_attack does the model
    first cross `threshold`?

    Returns:
        lead_time_seconds: positive = advance warning, negative = late detection
        first_alert_time: Unix timestamp of first alert
    """
    mask_before_attack = timestamps <= t_attack
    probs_before = y_pred_prob[mask_before_attack]
    times_before = timestamps[mask_before_attack]

    if len(probs_before) == 0:
        return {"lead_time_seconds": float("nan"), "first_alert_time": None}

    alert_mask = probs_before >= threshold
    if not alert_mask.any():
        return {"lead_time_seconds": float("nan"), "first_alert_time": None}

    first_alert_idx = np.argmax(alert_mask)
    first_alert_time = float(times_before[first_alert_idx])
    lead_time = t_attack - first_alert_time

    return {
        "lead_time_seconds": float(lead_time),
        "first_alert_time": first_alert_time,
        "threshold_used": threshold,
    }


def compute_brier_score(y_true: np.ndarray, y_pred_prob: np.ndarray) -> float:
    """
    Brier Score: mean squared probability error.
    Lower is better (0 = perfect, 0.25 = random for balanced classes).
    """
    y_true_bin = (y_true > 0.5).astype(float)
    return float(np.mean((y_pred_prob - y_true_bin) ** 2))


def compute_ece(
    y_true: np.ndarray,
    y_pred_prob: np.ndarray,
    n_bins: int = 10,
) -> float:
    """
    Expected Calibration Error (ECE).
    Measures how well predicted probabilities match actual frequencies.
    Critical for a proactive defence tool where operators act on probabilities.
    """
    y_true_bin = (y_true > 0.5).astype(float)
    bins = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    n = len(y_true_bin)
    for lo, hi in zip(bins[:-1], bins[1:]):
        mask = (y_pred_prob >= lo) & (y_pred_prob < hi)
        if mask.sum() == 0:
            continue
        bin_conf = y_pred_prob[mask].mean()
        bin_acc = y_true_bin[mask].mean()
        ece += (mask.sum() / n) * abs(bin_acc - bin_conf)
    return float(ece)


def compute_per_stage_f1(
    stage_true: np.ndarray,
    stage_pred: np.ndarray,
    stage_names: Optional[Dict[int, str]] = None,
) -> Dict:
    """
    Per-class F1 scores for each MITRE ATT&CK stage.
    This is the headline OOD metric — overall macro F1 can hide stage-level failure.
    """
    from sklearn.metrics import classification_report
    if stage_names is None:
        stage_names = {
            0: "Benign", 1: "Reconnaissance", 2: "Initial Access",
            3: "Credential Access", 4: "Lateral Movement",
            5: "Command & Control", 6: "Exfiltration",
        }
    labels = sorted(stage_names.keys())
    target_names = [stage_names[l] for l in labels]
    report = classification_report(
        stage_true, stage_pred,
        labels=labels,
        target_names=target_names,
        output_dict=True,
        zero_division=0,
    )
    return report


def compute_dynamics_mse(
    grounded_pred: np.ndarray,
    grounded_target: np.ndarray,
) -> Dict:
    """
    MSE on grounded future telemetry predictions [N, K, 3].
    Validates that the model actually learned state-transition dynamics.
    """
    mse = float(np.mean((grounded_pred - grounded_target) ** 2))
    per_dim_mse = {
        "port_entropy_mse": float(np.mean((grounded_pred[..., 0] - grounded_target[..., 0]) ** 2)),
        "syn_ratio_mse":    float(np.mean((grounded_pred[..., 1] - grounded_target[..., 1]) ** 2)),
        "log_bytes_mse":    float(np.mean((grounded_pred[..., 2] - grounded_target[..., 2]) ** 2)),
    }
    return {"dynamics_mse_overall": mse, **per_dim_mse}


def full_evaluation_report(
    y_true_infil: np.ndarray,
    y_pred_infil_prob: np.ndarray,
    stage_true: np.ndarray,
    stage_pred: np.ndarray,
    grounded_pred: Optional[np.ndarray] = None,
    grounded_target: Optional[np.ndarray] = None,
    timestamps: Optional[np.ndarray] = None,
    t_attack: Optional[float] = None,
    model_name: str = "World Model",
) -> Dict:
    """Assembles the complete evaluation report for submission benchmarking."""
    report = {"model": model_name}

    # Standard metrics
    report.update(compute_classification_metrics(y_true_infil, y_pred_infil_prob))

    # Calibration
    report["brier_score"] = compute_brier_score(y_true_infil, y_pred_infil_prob)
    report["ece"] = compute_ece(y_true_infil, y_pred_infil_prob)

    # MITRE per-stage F1
    report["per_stage_f1"] = compute_per_stage_f1(stage_true, stage_pred)

    # Grounded dynamics
    if grounded_pred is not None and grounded_target is not None:
        report.update(compute_dynamics_mse(grounded_pred, grounded_target))

    # Lead-time
    if timestamps is not None and t_attack is not None:
        report["lead_time"] = compute_lead_time(timestamps, y_pred_infil_prob, t_attack)

    return report

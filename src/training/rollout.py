"""
src/training/rollout.py

K-Step Forward Rollout Evaluation for the Predictive Cyber Defence World Model.

Implements the "K-step forward simulation" requirement from AGENTS.md:
  - Runs the trained model on observed graph sequences
  - Collects K-step predicted telemetry, infiltration probability, and MITRE stage
  - Evaluates per-horizon-step accuracy vs ground truth telemetry
  - Supports counterfactual rollout (host isolation)

Usage:
    from src.training.rollout import rollout_k_steps, evaluate_rollout_dataset
"""

from __future__ import annotations
from typing import List, Dict, Optional, Tuple
import numpy as np
import torch

from src.models.worldmodel import CyberDefenceWorldModel
from src.data.graph_builder import NetworkGraphSnapshot


def _to_device(snap: NetworkGraphSnapshot, device: torch.device) -> NetworkGraphSnapshot:
    """Move snapshot tensor fields to device."""
    snap.x          = snap.x.to(device)
    snap.edge_index = snap.edge_index.to(device)
    snap.edge_attr  = snap.edge_attr.to(device)
    return snap


def rollout_k_steps(
    model: CyberDefenceWorldModel,
    graph_sequence: List[NetworkGraphSnapshot],
    isolated_host_id: Optional[int] = None,
    device: Optional[torch.device] = None,
) -> Dict[str, object]:
    """
    Single K-step rollout from an observed graph sequence.

    The model already outputs K future telemetry steps via the grounded head.
    This function wraps forward_sequence with:
      - Device placement
      - Optional counterfactual host isolation
      - Structured return including per-step predictions

    Args:
        model: Trained CyberDefenceWorldModel.
        graph_sequence: List of NetworkGraphSnapshot (length = seq_len, e.g. 10).
        isolated_host_id: If set, zero out that host and recompute (counterfactual).
        device: Target device. Defaults to the model's first parameter device.

    Returns:
        dict with keys:
            grounded_telemetry  : np.ndarray [K, 3]  (port_entropy, syn_ratio, log_bytes)
            infiltration_prob   : float
            stage_logits        : np.ndarray [num_stages]
            spatial_attention   : torch.Tensor [num_edges]
            is_counterfactual   : bool
    """
    if device is None:
        device = next(model.parameters()).device

    seq = [_to_device(s, device) for s in graph_sequence]

    model.eval()
    with torch.no_grad():
        if isolated_host_id is not None:
            preds = model.simulate_counterfactual(seq, isolated_host_id=isolated_host_id)
        else:
            preds = model.forward_sequence(seq)

    return {
        "grounded_telemetry":   preds["grounded_telemetry"].cpu().numpy(),
        "infiltration_prob":    float(preds["infiltration_prob"].squeeze().item()),
        "stage_logits":         preds["stage_logits"].cpu().numpy(),
        "spatial_attention":    preds["spatial_attention"].cpu(),
        "is_counterfactual":    isolated_host_id is not None,
    }


def evaluate_rollout_dataset(
    model: CyberDefenceWorldModel,
    samples: list,          # list of CyberDefenceSample from dataset
    device: Optional[torch.device] = None,
    max_samples: int = 500,
) -> Dict[str, object]:
    """
    Evaluate K-step rollout quality over a set of samples.

    For each sample, compares predicted grounded telemetry [K, 3] against
    the actual future telemetry captured in the target windows.

    Returns:
        dict with:
            mae_per_step    : np.ndarray [K, 3]  - MAE per horizon step per feature
            rmse_per_step   : np.ndarray [K, 3]  - RMSE per horizon step per feature
            infil_f1        : float
            stage_acc       : float
            n_samples       : int
    """
    if device is None:
        device = next(model.parameters()).device

    if len(samples) > max_samples:
        import random
        samples = random.sample(samples, max_samples)

    all_grounded_pred, all_grounded_true = [], []
    all_infil_pred, all_infil_true       = [], []
    all_stage_pred, all_stage_true       = [], []

    model.eval()
    with torch.no_grad():
        for sample in samples:
            seq   = [_to_device(s, device) for s in sample.graph_sequence]
            preds = model.forward_sequence(seq)

            gt_pred = preds["grounded_telemetry"].cpu().numpy()    # [K, 3]
            gt_true = sample.grounded_targets.numpy()              # [K, 3]

            all_grounded_pred.append(gt_pred)
            all_grounded_true.append(gt_true)

            all_infil_pred.append(float(preds["infiltration_prob"].squeeze()))
            all_infil_true.append(float(sample.infiltration_target))

            all_stage_pred.append(int(preds["stage_logits"].argmax().item()))
            all_stage_true.append(int(sample.stage_id))

    pred_arr  = np.stack(all_grounded_pred)   # [N, K, 3]
    true_arr  = np.stack(all_grounded_true)   # [N, K, 3]
    err       = pred_arr - true_arr

    mae_per_step  = np.abs(err).mean(axis=0)            # [K, 3]
    rmse_per_step = np.sqrt((err ** 2).mean(axis=0))    # [K, 3]

    infil_pred_bin = (np.array(all_infil_pred) > 0.5).astype(int)
    infil_true_bin = (np.array(all_infil_true) > 0.5).astype(int)

    tp = int(((infil_pred_bin == 1) & (infil_true_bin == 1)).sum())
    fp = int(((infil_pred_bin == 1) & (infil_true_bin == 0)).sum())
    fn = int(((infil_pred_bin == 0) & (infil_true_bin == 1)).sum())
    infil_f1 = tp / max(tp + 0.5 * (fp + fn), 1e-8)

    stage_pred_arr = np.array(all_stage_pred)
    stage_true_arr = np.array(all_stage_true)
    stage_acc      = float((stage_pred_arr == stage_true_arr).mean())

    return {
        "mae_per_step":   mae_per_step,
        "rmse_per_step":  rmse_per_step,
        "infil_f1":       infil_f1,
        "stage_acc":      stage_acc,
        "n_samples":      len(samples),
        "feature_names":  ["port_entropy", "syn_ratio", "log_bytes"],
    }


def print_rollout_report(metrics: Dict[str, object]) -> None:
    """Pretty-print K-step rollout evaluation results."""
    print("\n" + "=" * 60)
    print("  K-Step Rollout Evaluation Report")
    print("=" * 60)
    print(f"  Samples evaluated : {metrics['n_samples']}")
    print(f"  Infiltration F1   : {metrics['infil_f1']:.4f}")
    print(f"  MITRE Stage Acc   : {metrics['stage_acc']:.4f}")
    print()
    mae  = metrics["mae_per_step"]
    rmse = metrics["rmse_per_step"]
    feats = metrics["feature_names"]
    for k in range(mae.shape[0]):
        print(f"  Horizon k={k+1}:")
        for fi, feat in enumerate(feats):
            print(f"    {feat:<18}  MAE={mae[k, fi]:.4f}  RMSE={rmse[k, fi]:.4f}")
    print("=" * 60 + "\n")


__all__ = [
    "rollout_k_steps",
    "evaluate_rollout_dataset",
    "print_rollout_report",
]

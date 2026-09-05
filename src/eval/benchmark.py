"""
src/eval/benchmark.py

Automated benchmarking suite comparing World Model vs. Baselines:
1. World Model (GNN + Transformer)
2. Single-Frame GNN Ablation (GNN-only without temporal sequence modeling)
3. Per-Flow Logistic Regression Baseline
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd

from src.eval.metrics import full_evaluation_report, compute_classification_metrics


def run_benchmark_comparison(
    y_true: np.ndarray,
    world_model_probs: np.ndarray,
    gnn_only_probs: Optional[np.ndarray] = None,
    logistic_probs: Optional[np.ndarray] = None,
    stage_true: Optional[np.ndarray] = None,
    stage_preds: Optional[np.ndarray] = None,
    timestamps: Optional[np.ndarray] = None,
    t_attack: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Runs unified benchmark across all models and compiles comparison report.
    """
    models_report = {}

    # 1. World Model
    if stage_true is None:
        stage_true = (y_true > 0.5).astype(int)
    if stage_preds is None:
        stage_preds = (world_model_probs >= 0.5).astype(int)

    wm_report = full_evaluation_report(
        y_true_infil=y_true,
        y_pred_infil_prob=world_model_probs,
        stage_true=stage_true,
        stage_pred=stage_preds,
        timestamps=timestamps,
        t_attack=t_attack,
        model_name="World Model (GNN + Transformer)",
    )
    models_report["world_model"] = wm_report

    # 2. GNN-Only Ablation
    if gnn_only_probs is not None:
        gnn_report = full_evaluation_report(
            y_true_infil=y_true,
            y_pred_infil_prob=gnn_only_probs,
            stage_true=stage_true,
            stage_pred=(gnn_only_probs >= 0.5).astype(int),
            timestamps=timestamps,
            t_attack=t_attack,
            model_name="GNN-Only Single Frame Ablation",
        )
        models_report["gnn_only"] = gnn_report

    # 3. Logistic Regression Baseline
    if logistic_probs is not None:
        lr_report = full_evaluation_report(
            y_true_infil=y_true,
            y_pred_infil_prob=logistic_probs,
            stage_true=stage_true,
            stage_pred=(logistic_probs >= 0.5).astype(int),
            timestamps=timestamps,
            t_attack=t_attack,
            model_name="Per-Flow Logistic Regression Baseline",
        )
        models_report["logistic_regression"] = lr_report

    return {
        "benchmark_results": models_report,
        "summary_table": generate_benchmark_markdown_table(models_report),
    }


def generate_benchmark_markdown_table(results: Dict[str, Dict[str, Any]]) -> str:
    """
    Renders benchmark results into a clean GitHub-style Markdown table.
    """
    headers = [
        "Model",
        "F1 Score",
        "Precision",
        "Recall",
        "FPR",
        "AUROC",
        "Brier Score",
        "ECE",
    ]
    rows = []

    for key, rep in results.items():
        name = rep.get("model", key)
        f1 = f"{rep.get('f1', 0.0):.3f}"
        prec = f"{rep.get('precision', 0.0):.3f}"
        rec = f"{rep.get('recall', 0.0):.3f}"
        fpr = f"{rep.get('fpr', 0.0):.3%}"
        auroc = f"{rep.get('auroc', float('nan')):.3f}" if not np.isnan(rep.get('auroc', float('nan'))) else "N/A"
        brier = f"{rep.get('brier_score', 0.0):.4f}"
        ece = f"{rep.get('ece', 0.0):.4f}"

        rows.append(f"| **{name}** | {f1} | {prec} | {rec} | {fpr} | {auroc} | {brier} | {ece} |")

    header_str = "| " + " | ".join(headers) + " |"
    sep_str = "| " + " | ".join(["---"] * len(headers)) + " |"
    return "\n".join([header_str, sep_str] + rows)

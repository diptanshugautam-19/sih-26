"""
src/eval module exports.
"""

from src.eval.metrics import (
    compute_classification_metrics,
    compute_lead_time,
    compute_brier_score,
    compute_ece,
    compute_per_stage_f1,
    compute_dynamics_mse,
    full_evaluation_report,
)
from src.eval.ood_score import (
    compute_distribution_kl_divergence,
    OODScorer,
    compute_ood_score,
)
from src.eval.unseen_attacks import (
    split_by_held_out_attacks,
    evaluate_unseen_attack_robustness,
)
from src.eval.benchmark import (
    run_benchmark_comparison,
    generate_benchmark_markdown_table,
)

__all__ = [
    "compute_classification_metrics",
    "compute_lead_time",
    "compute_brier_score",
    "compute_ece",
    "compute_per_stage_f1",
    "compute_dynamics_mse",
    "full_evaluation_report",
    "compute_distribution_kl_divergence",
    "OODScorer",
    "compute_ood_score",
    "split_by_held_out_attacks",
    "evaluate_unseen_attack_robustness",
    "run_benchmark_comparison",
    "generate_benchmark_markdown_table",
]

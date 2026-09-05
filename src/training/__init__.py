"""
src/training package: Training loop, loss functions, seeding, and rollout evaluation.
"""

from src.training.seed import set_seed
from src.training.losses import UncertaintyWeightedMultiTaskLoss
from src.training.train import (
    train,
    train_epoch,
    eval_epoch,
)
from src.training.rollout import (
    rollout_k_steps,
    evaluate_rollout_dataset,
    print_rollout_report,
)

# Friendly alias
train_world_model = train

__all__ = [
    "set_seed",
    "UncertaintyWeightedMultiTaskLoss",
    "train",
    "train_world_model",
    "train_epoch",
    "eval_epoch",
    "rollout_k_steps",
    "evaluate_rollout_dataset",
    "print_rollout_report",
]

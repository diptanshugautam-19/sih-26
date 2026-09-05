"""
src/training/losses.py

Multi-Task Loss for the Predictive Cyber Defence World Model.

Three task losses combined using Kendall, Gal & Cipolla (2018) homoscedastic
uncertainty weighting — the model learns the relative weights during training:

    L_total = sum_i [ (1 / (2 * sigma_i^2)) * L_i  +  log(sigma_i) ]

Tasks:
    1. Grounded Dynamics Loss  (MSE)      — predicts real future telemetry values
    2. Infiltration Risk Loss  (BCE)      — graded anticipation probability
    3. MITRE Stage Loss        (CE)       — kill-chain stage classification

Additionally includes:
    - Focal weighting for the BCE head to address CIC-IDS2018 class imbalance (~80% benign)
    - Confidence-weighted CE: reduces gradient from low-confidence pseudo-labels
"""

from __future__ import annotations
import torch
import torch.nn as nn
import torch.nn.functional as F


class UncertaintyWeightedMultiTaskLoss(nn.Module):
    """
    Kendall et al. (2018) homoscedastic uncertainty loss.
    Learnable log-sigma parameters per task prevent manual weight tuning.

    Usage:
        loss_fn = UncertaintyWeightedMultiTaskLoss()
        loss, breakdown = loss_fn(
            grounded_pred, grounded_target,
            infil_pred, infil_target,
            stage_logits, stage_target, stage_conf
        )
    """

    def __init__(self, focal_gamma: float = 2.0, label_smoothing: float = 0.1):
        super().__init__()
        self.focal_gamma = focal_gamma
        self.label_smoothing = label_smoothing

        # Learnable log(sigma) per task — initialised to log(1) = 0
        self.log_sigma_dynamics = nn.Parameter(torch.zeros(1))
        self.log_sigma_infiltration = nn.Parameter(torch.zeros(1))
        self.log_sigma_stage = nn.Parameter(torch.zeros(1))

    def _focal_bce(self, pred: torch.Tensor, target: torch.Tensor) -> torch.Tensor:
        """
        Focal Binary Cross-Entropy with label smoothing.
        Suppresses easy-negative (benign) loss contributions.
        """
        eps = 1e-7
        pred = pred.float().squeeze(-1)
        target = target.float()

        # Standard binary label smoothing: push positives down to (1-ε), push negatives up to ε.
        # Original formula used 0.5*ε which over-smoothed negatives asymmetrically.
        target_smooth = target * (1 - self.label_smoothing) + (1 - target) * self.label_smoothing

        bce = F.binary_cross_entropy(pred.clamp(eps, 1 - eps), target_smooth, reduction="none")
        pt = torch.where(target >= 0.5, pred, 1 - pred)
        focal_weight = (1 - pt.clamp(eps, 1 - eps)) ** self.focal_gamma
        return (focal_weight * bce).mean()

    def _confidence_weighted_ce(
        self,
        logits: torch.Tensor,
        targets: torch.Tensor,
        confidences: torch.Tensor,
    ) -> torch.Tensor:
        """
        Cross-Entropy weighted by pseudo-label confidence scores.
        Low-confidence pseudo-labels contribute proportionally less gradient.
        """
        ce = F.cross_entropy(logits, targets, label_smoothing=self.label_smoothing, reduction="none")
        return (confidences * ce).mean()

    def forward(
        self,
        grounded_pred: torch.Tensor,      # [B, K, 3]  or  [K, 3]
        grounded_target: torch.Tensor,    # same shape
        infil_pred: torch.Tensor,         # [B, 1]  or  scalar
        infil_target: torch.Tensor,       # [B]
        stage_logits: torch.Tensor,       # [B, num_stages]
        stage_target: torch.Tensor,       # [B] long
        stage_conf: torch.Tensor,         # [B] float 0..1
    ):
        # 1. Grounded dynamics MSE
        L_dyn = F.mse_loss(grounded_pred.float(), grounded_target.float())

        # 2. Focal BCE for infiltration risk
        L_infil = self._focal_bce(infil_pred, infil_target)

        # 3. Confidence-weighted CE for MITRE stage
        L_stage = self._confidence_weighted_ce(stage_logits, stage_target, stage_conf)

        # 4. Kendall uncertainty weighting
        s_dyn   = torch.exp(-2 * self.log_sigma_dynamics)
        s_infil = torch.exp(-2 * self.log_sigma_infiltration)
        s_stage = torch.exp(-2 * self.log_sigma_stage)

        L_total = (
            s_dyn   * L_dyn   + 2 * self.log_sigma_dynamics   +
            s_infil * L_infil + 2 * self.log_sigma_infiltration +
            s_stage * L_stage + 2 * self.log_sigma_stage
        )

        breakdown = {
            "loss_dynamics":      L_dyn.item(),
            "loss_infiltration":  L_infil.item(),
            "loss_stage":         L_stage.item(),
            "loss_total":         L_total.item(),
            "sigma_dynamics":     float(self.log_sigma_dynamics.exp().item()),
            "sigma_infiltration": float(self.log_sigma_infiltration.exp().item()),
            "sigma_stage":        float(self.log_sigma_stage.exp().item()),
        }
        return L_total, breakdown

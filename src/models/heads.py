"""
src/models/heads.py

Multi-Task Output Heads for the Predictive Cyber Defence World Model:
1. Grounded Next-State Telemetry Dynamics Head (predicts future port entropy, SYN ratio, bytes).
2. Graded Infiltration Risk Head (outputs time-series anticipation probability).
3. MITRE ATT&CK Stage Progression Classifier.
4. Node-Level Host Risk Attribution Head (identifies targeted/escalating victim IPs).
"""

from __future__ import annotations
import torch
import torch.nn as nn
import torch.nn.functional as F


class MultiTaskWorldModelHeads(nn.Module):
    def __init__(
        self,
        latent_dim: int = 64,
        num_stages: int = 7,       # 0: Benign, 1: Recon, 2: Initial Access, 3: Cred Access, 4: Lateral, 5: C2, 6: Exfil
        telemetry_dim: int = 3,    # port_entropy, syn_ratio, log_bytes
        horizon_k: int = 4,
    ):
        super().__init__()
        self.horizon_k = horizon_k
        self.telemetry_dim = telemetry_dim   # stored so view() uses it, not a hardcoded literal

        # Head 1: Grounded Next-State Dynamics Prediction (K future steps)
        self.grounded_head = nn.Sequential(
            nn.Linear(latent_dim, 128),
            nn.ReLU(),
            nn.Linear(128, horizon_k * telemetry_dim),
        )

        # Head 2: Graded Infiltration Probability
        self.infiltration_head = nn.Sequential(
            nn.Linear(latent_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2), # Kept for MC Dropout uncertainty
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

        # Head 3: MITRE ATT&CK Stage Classifier
        self.stage_head = nn.Sequential(
            nn.Linear(latent_dim, 64),
            nn.ReLU(),
            nn.Linear(64, num_stages),
        )

        # Head 4: Host-Level Attribution Head
        self.host_risk_head = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

    def forward(
        self,
        summary_latent: torch.Tensor,
        node_latents: torch.Tensor | None = None
    ) -> dict[str, torch.Tensor]:
        """
        Inputs:
            summary_latent: [batch_size, latent_dim] (pooled sequence representation)
            node_latents: Optional [num_nodes, latent_dim]
        Outputs:
            dict containing:
                "grounded_telemetry": [batch_size, horizon_k, 3]
                "infiltration_prob": [batch_size, 1]
                "stage_logits": [batch_size, num_stages]
                "host_risks": [num_nodes] (if node_latents provided)
        """
        is_single = (summary_latent.dim() == 1)
        if is_single:
            summary_latent = summary_latent.unsqueeze(0)

        batch_size = summary_latent.size(0)

        # 1. Grounded dynamics
        grounded_flat = self.grounded_head(summary_latent)
        grounded_pred = grounded_flat.view(batch_size, self.horizon_k, self.telemetry_dim)

        # 2. Infiltration prob
        infil_prob = self.infiltration_head(summary_latent)

        # 3. MITRE stage
        stage_logits = self.stage_head(summary_latent)

        out = {
            "grounded_telemetry": grounded_pred.squeeze(0) if is_single else grounded_pred,
            "infiltration_prob": infil_prob.squeeze(0) if is_single else infil_prob,
            "stage_logits": stage_logits.squeeze(0) if is_single else stage_logits,
        }

        # 4. Host-level risk attribution
        if node_latents is not None:
            host_risks = self.host_risk_head(node_latents).squeeze(-1)
            out["host_risks"] = host_risks

        return out

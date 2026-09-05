"""
src/models/baselines/gnn_only.py

Single-Frame GNN-Only Ablation Baseline.
Meets the challenge brief baseline requirement:
Evaluates network infiltration risk and grounded dynamics from a SINGLE graph snapshot
without temporal sequence modeling (no Transformer Encoder).
Isolates the exact performance contribution of the causal temporal world model.
"""

from __future__ import annotations
from typing import Dict, Any, Optional
import torch
import torch.nn as nn
import torch.nn.functional as F

from src.models.gnn_encoder import GNNEncoder
from src.data.graph_builder import NetworkGraphSnapshot


class GNNOnlyBaseline(nn.Module):
    """
    Static single-frame GNN baseline.
    Takes a single NetworkGraphSnapshot and directly predicts:
    - infiltration_prob (binary risk)
    - stage_logits (MITRE ATT&CK stage)
    - grounded_telemetry (next-state port entropy, syn ratio, log bytes)
    """

    def __init__(
        self,
        node_in_dim: int = 16,
        edge_in_dim: int = 16,          # graph_builder.py produces 16 edge features
        hidden_dim: int = 64,
        num_classes_stage: int = 7,
        num_heads: int = 4,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.node_in_dim = node_in_dim
        self.edge_in_dim = edge_in_dim
        self.hidden_dim = hidden_dim

        # Spatial GNN encoder with mean+max pooling projected to hidden_dim
        self.encoder = GNNEncoder(
            node_in_dim=node_in_dim,
            edge_in_dim=edge_in_dim,
            hidden_dim=hidden_dim,
            out_dim=hidden_dim,
            num_heads=num_heads,
            dropout=dropout,
            concat_pooling=True,
            project_pooling=True,
        )

        # Single-frame prediction heads (ablation of temporal Transformer)
        self.prob_head = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

        self.stage_head = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, num_classes_stage),
        )

        self.telemetry_head = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 3),  # [entropy, syn_ratio, log_bytes]
        )

    def forward(self, snapshot: NetworkGraphSnapshot) -> Dict[str, torch.Tensor]:
        h_nodes, pooled_graph, attn = self.encoder(
            x=snapshot.x,
            edge_index=snapshot.edge_index,
            edge_attr=snapshot.edge_attr,
        )

        prob = self.prob_head(pooled_graph).squeeze(-1)
        stages = self.stage_head(pooled_graph)
        telemetry = self.telemetry_head(pooled_graph)

        return {
            "infiltration_prob": prob,
            "stage_logits": stages,
            "grounded_telemetry": telemetry,
            "spatial_attention": attn,
            "node_embeddings": h_nodes,
        }

"""
src/models/worldmodel.py

Complete Predictive Cyber Defence World Model:
- Spatial GNN with persistent TGN Node Memory Bank
- Causal Temporal Transformer Encoder
- Multi-task Prediction Heads (Grounded Dynamics, Graded Risk, MITRE progression)
- Counterfactual Simulation Engine (instant action_mask rollout)
- Epistemic Uncertainty Estimation (Monte Carlo Dropout)
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional
import torch
import torch.nn as nn

from src.models.dynamic_gnn import DynamicGATWithMemory
from src.models.temporal import CausalTemporalTransformer
from src.models.heads import MultiTaskWorldModelHeads
from src.data.graph_builder import NetworkGraphSnapshot


class CyberDefenceWorldModel(nn.Module):
    def __init__(
        self,
        node_in_dim: int = 16,
        edge_in_dim: int = 16,
        node_dim: int | None = None,
        edge_dim: int | None = None,
        memory_dim: int = 32,
        hidden_dim: int = 64,
        num_heads: int = 4,
        seq_len: int = 10,
        horizon_k: int = 4,
        dropout: float = 0.1,
        **kwargs,
    ):
        super().__init__()
        actual_node_dim = node_dim if node_dim is not None else node_in_dim
        actual_edge_dim = edge_dim if edge_dim is not None else edge_in_dim

        self.node_in_dim = actual_node_dim
        self.edge_in_dim = actual_edge_dim
        self.node_dim = actual_node_dim
        self.edge_dim = actual_edge_dim

        self.seq_len = seq_len
        self.horizon_k = horizon_k
        self.hidden_dim = hidden_dim
        self.memory_dim = memory_dim

        # 1. Spatial Dynamic GNN Encoder
        self.spatial_gnn = DynamicGATWithMemory(
            node_feat_dim=actual_node_dim,
            edge_feat_dim=actual_edge_dim,
            memory_dim=memory_dim,
            hidden_dim=hidden_dim,
            num_heads=num_heads,
            dropout=dropout,
        )

        # 2. Causal Temporal Sequence Transformer
        self.temporal_transformer = CausalTemporalTransformer(
            embed_dim=hidden_dim,
            num_layers=3,
            num_heads=num_heads,
            ff_dim=256,
            dropout=dropout,
        )

        # 3. Multi-task Heads
        self.heads = MultiTaskWorldModelHeads(
            latent_dim=hidden_dim,
            num_stages=7,
            telemetry_dim=3,
            horizon_k=horizon_k,
        )

    def forward(
        self,
        graph_sequence: List[NetworkGraphSnapshot],
        action_mask_nodes: torch.Tensor | None = None,
        action_mask_edges: torch.Tensor | None = None,
    ) -> Dict[str, Any]:
        """Standard PyTorch forward entrypoint delegating to forward_sequence."""
        return self.forward_sequence(
            graph_sequence=graph_sequence,
            action_mask_nodes=action_mask_nodes,
            action_mask_edges=action_mask_edges,
        )

    def forward_sequence(
        self,
        graph_sequence: List[NetworkGraphSnapshot],
        action_mask_nodes: torch.Tensor | None = None,
        action_mask_edges: torch.Tensor | None = None,
    ) -> Dict[str, Any]:
        """
        Rolls through a sequence of 10 graph snapshots, updating persistent node memory,
        encoding temporal dynamics, and computing future forecasts.
        """
        assert len(graph_sequence) > 0, "Graph sequence must contain at least 1 snapshot."
        device = graph_sequence[0].x.device

        # The persistent registry grows monotonically: later snapshots may have
        # MORE nodes than earlier ones. Initialize memory to cover the maximum
        # node count seen anywhere in this sequence.
        max_nodes = max(snap.num_nodes for snap in graph_sequence)
        node_memory = torch.zeros((max_nodes, self.memory_dim), device=device)

        if action_mask_nodes is not None and len(action_mask_nodes) < max_nodes:
            mask_pad = torch.ones(max_nodes - len(action_mask_nodes), device=device, dtype=action_mask_nodes.dtype)
            action_mask_nodes = torch.cat([action_mask_nodes, mask_pad], dim=0)

        graph_embeddings = []
        spatial_attentions = []
        last_node_latents = None

        for snap in graph_sequence:
            # Sanity check: edge_index must only reference nodes within this snapshot.
            # If edge_index.max() >= cur_nodes the scatter in DynamicGATWithMemory would
            # silently write into padded-zero rows, corrupting the graph embedding.
            cur_nodes = snap.num_nodes
            if snap.edge_index.numel() > 0:
                assert snap.edge_index.max() < cur_nodes, (
                    f"edge_index references node {snap.edge_index.max().item()} "
                    f"but snapshot only has {cur_nodes} nodes. "
                    "Check graph_builder window-scoped registry."
                )

            # Pad node features if this snapshot has fewer nodes than max_nodes
            # (can happen because new nodes appear in later windows)
            if cur_nodes < max_nodes:
                pad = torch.zeros((max_nodes - cur_nodes, snap.x.size(1)),
                                  dtype=snap.x.dtype, device=device)
                x_padded = torch.cat([snap.x, pad], dim=0)
            else:
                x_padded = snap.x

            # node_memory is always max_nodes — no padding needed here.
            h_nodes, pooled_graph, node_memory, attn = self.spatial_gnn(
                x=x_padded,
                edge_index=snap.edge_index,
                edge_attr=snap.edge_attr,
                node_memory=node_memory,
                action_mask_nodes=action_mask_nodes,
                action_mask_edges=action_mask_edges,
            )
            graph_embeddings.append(pooled_graph)
            spatial_attentions.append(attn)
            last_node_latents = h_nodes

        # Stack into temporal sequence [1, seq_len, hidden_dim]
        graph_seq_tensor = torch.stack(graph_embeddings, dim=0).unsqueeze(0)

        # Temporal dynamics rollout
        temporal_latents = self.temporal_transformer(graph_seq_tensor)
        summary_latent = temporal_latents[0, -1, :]  # Latest context state

        # Compute multi-task predictions
        predictions = self.heads(summary_latent, node_latents=last_node_latents)
        predictions["spatial_attention"] = spatial_attentions[-1]
        predictions["latest_node_memory"] = node_memory
        return predictions

    def simulate_counterfactual(
        self,
        graph_sequence: List[NetworkGraphSnapshot],
        isolated_host_id: int | None = None,
        blocked_port: int | None = None,
        action: Any | None = None,
    ) -> Dict[str, Any]:
        """
        Counterfactual "What-If" simulation:
        Zeroes out node/port features or executes structured CounterfactualAction
        and recalculates predicted trajectory in <30ms.
        """
        assert len(graph_sequence) > 0, "Graph sequence must contain at least 1 snapshot."

        if action is not None:
            from src.models.counterfactual import CounterfactualEngine
            engine = CounterfactualEngine(self)
            return engine.evaluate_intervention(graph_sequence, action)

        if blocked_port is not None:
            from src.models.counterfactual import CounterfactualAction, _apply_action_to_snapshot
            act = CounterfactualAction(action_type="block_port", target=str(blocked_port))
            intervened = [_apply_action_to_snapshot(s, act)[0] for s in graph_sequence]
            return self.forward_sequence(intervened)

        max_nodes = max(snap.num_nodes for snap in graph_sequence)
        device = graph_sequence[0].x.device

        action_mask_nodes = torch.ones(max_nodes, device=device)
        if isolated_host_id is not None and 0 <= isolated_host_id < max_nodes:
            action_mask_nodes[isolated_host_id] = 0.0

        # Run forward pass with action mask
        return self.forward_sequence(graph_sequence, action_mask_nodes=action_mask_nodes)

    def rank_counterfactual_actions(
        self,
        graph_sequence: List[NetworkGraphSnapshot],
        candidate_actions: list | None = None,
    ) -> list:
        """
        Evaluates and ranks candidate mitigations by Net Defense Score
        (Risk Reduction balanced against Operational Disruption).
        """
        from src.models.counterfactual import CounterfactualEngine
        engine = CounterfactualEngine(self)
        return engine.rank_interventions(graph_sequence, candidate_actions=candidate_actions)

    def estimate_uncertainty_mc_dropout(
        self,
        graph_sequence: List[NetworkGraphSnapshot],
        n_passes: int = 5,
    ) -> Dict[str, float]:
        """
        Monte Carlo Dropout for epistemic uncertainty estimation.
        Returns mean infiltration probability and standard deviation.
        """
        self.train()  # Keep dropout active
        probs = []
        with torch.no_grad():
            for _ in range(n_passes):
                preds = self.forward_sequence(graph_sequence)
                probs.append(float(preds["infiltration_prob"].squeeze().item()))
        self.eval()

        mean_p = float(torch.tensor(probs).mean().item())
        std_p = float(torch.tensor(probs).std().item()) if len(probs) > 1 else 0.0
        return {
            "mean_probability": mean_p,
            "uncertainty_std": std_p,
            "confidence_lower": max(0.0, mean_p - 1.96 * std_p),
            "confidence_upper": min(1.0, mean_p + 1.96 * std_p),
        }


# Standard alias matching project specifications
WorldModel = CyberDefenceWorldModel

__all__ = ["CyberDefenceWorldModel", "WorldModel"]

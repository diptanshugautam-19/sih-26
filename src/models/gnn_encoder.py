"""
src/models/gnn_encoder.py

Spatial GNN Encoder for Network Graph Snapshots:
- Computes node embeddings and spatial attention via multi-head graph attention.
- Incorporates edge attributes directly into key/value attention projections.
- Graph Pooling: Concatenates Mean + Max pooling (capturing both background activity and peak burst anomalies).
- Configurable pooling projection: defaults to projecting 2*hidden_dim -> graph_embedding_dim (64)
  to ensure seamless dimension matching with the downstream CausalTemporalTransformer.
"""

from __future__ import annotations
import math
from typing import Optional, Tuple
import torch
import torch.nn as nn
import torch.nn.functional as F


class GNNEncoder(nn.Module):
    """
    Spatial Graph Attention Encoder with Mean+Max Concatenated Pooling.

    Args:
        node_in_dim: Number of input node features (default: 16 from graph_builder.py).
        edge_in_dim: Number of input edge features (default: 12 from graph_builder.py).
        hidden_dim: Hidden representation dimension per node (default: 64).
        out_dim: Output graph embedding dimension (default: 64, matching graph_embedding_dim).
        num_heads: Number of attention heads (default: 4).
        dropout: Dropout rate (default: 0.1).
        concat_pooling: Whether to concatenate mean and max pooling (default: True -> 2*hidden_dim).
        project_pooling: If True, projects concatenated pooling (2*hidden_dim) down to out_dim (64).
                         If False, outputs raw concatenated dimension (2*hidden_dim = 128).
    """

    def __init__(
        self,
        node_in_dim: int = 16,
        edge_in_dim: int = 12,
        hidden_dim: int = 64,
        out_dim: int = 64,
        num_heads: int = 4,
        dropout: float = 0.1,
        concat_pooling: bool = True,
        project_pooling: bool = True,
        node_feat_dim: Optional[int] = None,
        edge_feat_dim: Optional[int] = None,
        **kwargs,
    ):
        super().__init__()
        actual_node_in = node_feat_dim if node_feat_dim is not None else node_in_dim
        actual_edge_in = edge_feat_dim if edge_feat_dim is not None else edge_in_dim

        self.node_in_dim = actual_node_in
        self.edge_in_dim = actual_edge_in
        self.hidden_dim = hidden_dim
        self.out_dim = out_dim
        self.num_heads = num_heads
        self.head_dim = hidden_dim // num_heads
        self.concat_pooling = concat_pooling
        self.project_pooling = project_pooling

        # Node and edge feature projections
        self.node_proj = nn.Linear(actual_node_in, hidden_dim)
        self.edge_proj = nn.Linear(actual_edge_in, hidden_dim)

        # Multi-head attention projections
        self.q_proj = nn.Linear(hidden_dim, hidden_dim)
        self.k_proj = nn.Linear(hidden_dim, hidden_dim)
        self.v_proj = nn.Linear(hidden_dim, hidden_dim)

        self.out_proj = nn.Linear(hidden_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout)
        self.layer_norm = nn.LayerNorm(hidden_dim)

        # Pooling projection: projects 2 * hidden_dim down to out_dim (64)
        pooled_in_dim = (2 * hidden_dim) if concat_pooling else hidden_dim
        if project_pooling:
            self.pool_proj = nn.Linear(pooled_in_dim, out_dim)
        else:
            self.pool_proj = nn.Identity()

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Forward pass.
        Inputs:
            x: [num_nodes, node_in_dim]
            edge_index: [2, num_edges]
            edge_attr: [num_edges, edge_in_dim]
        Outputs:
            node_embeddings: [num_nodes, hidden_dim]
            graph_embedding: [out_dim] (projected) or [2*hidden_dim] (unprojected)
            attention_weights: [num_edges]
        """
        num_nodes = x.size(0)
        num_edges = edge_index.size(1)

        h_node = F.relu(self.node_proj(x))

        if num_edges == 0:
            if self.concat_pooling:
                pooled_raw = torch.cat([h_node.mean(dim=0), h_node.max(dim=0)[0]], dim=-1)
            else:
                pooled_raw = h_node.mean(dim=0)
            pooled_graph = self.pool_proj(pooled_raw)
            dummy_attn = torch.empty(0, device=x.device)
            return h_node, pooled_graph, dummy_attn

        h_edge = F.relu(self.edge_proj(edge_attr))

        src_nodes, dst_nodes = edge_index[0], edge_index[1]

        q = self.q_proj(h_node[dst_nodes]).view(num_edges, self.num_heads, self.head_dim)
        k = (self.k_proj(h_node[src_nodes]) + h_edge).view(num_edges, self.num_heads, self.head_dim)
        v = (self.v_proj(h_node[src_nodes]) + h_edge).view(num_edges, self.num_heads, self.head_dim)

        scores = (q * k).sum(dim=-1) / math.sqrt(self.head_dim)
        attn_weights = torch.sigmoid(scores)
        mean_attn_per_edge = attn_weights.mean(dim=-1)

        messages = (v * attn_weights.unsqueeze(-1)).view(num_edges, self.hidden_dim)
        aggregated = torch.zeros((num_nodes, self.hidden_dim), device=x.device)
        aggregated.index_add_(0, dst_nodes, messages)

        h_out = self.layer_norm(h_node + self.dropout(self.out_proj(aggregated)))

        # Graph-level pooling: Mean + Max pooling concatenated
        if self.concat_pooling:
            mean_p = h_out.mean(dim=0)
            max_p = h_out.max(dim=0)[0]
            pooled_raw = torch.cat([mean_p, max_p], dim=-1)
        else:
            pooled_raw = h_out.mean(dim=0)

        pooled_graph = self.pool_proj(pooled_raw)
        return h_out, pooled_graph, mean_attn_per_edge

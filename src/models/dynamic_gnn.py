"""
src/models/dynamic_gnn.py

Spatial Graph Attention Layer with Dynamic TGN/GRU Node Memory Bank.

Solves the static GAT limitation:
- Even when an IP goes silent across multiple windows, its memory state h_v^(t)
  decays gracefully rather than vanishing.
- When an attacker suddenly initiates lateral movement, the node's prior memory
  spikes the spatial attention weights α_ij on suspicious edges.
"""

from __future__ import annotations
import math
import torch
import torch.nn as nn
import torch.nn.functional as F


class DynamicGATWithMemory(nn.Module):
    """
    Spatial Graph Attention layer integrated with a GRU-based Node Memory bank.
    
    Inputs:
        x: [num_nodes, in_node_feats]
        edge_index: [2, num_edges]
        edge_attr: [num_edges, in_edge_feats]
        node_memory: [num_nodes, memory_dim] (persistent GRU hidden state across windows)
        action_mask: Optional [num_nodes] or [num_edges] binary mask for counterfactual interventions
    
    Outputs:
        node_embeddings: [num_nodes, hidden_dim]
        graph_embedding: [hidden_dim] (mean pooled)
        updated_memory: [num_nodes, memory_dim]
        attention_weights: [num_edges] (for spatial explainability)
    """
    def __init__(
        self,
        node_feat_dim: int = 16,
        edge_feat_dim: int = 16,
        node_in_dim: int | None = None,
        edge_in_dim: int | None = None,
        memory_dim: int = 32,
        hidden_dim: int = 64,
        num_heads: int = 4,
        dropout: float = 0.1,
        **kwargs,
    ):
        super().__init__()
        actual_node_dim = node_in_dim if node_in_dim is not None else node_feat_dim
        actual_edge_dim = edge_in_dim if edge_in_dim is not None else edge_feat_dim

        self.hidden_dim = hidden_dim
        self.memory_dim = memory_dim
        self.num_heads = num_heads
        self.head_dim = hidden_dim // num_heads

        # Node feature projection (combines static features + prior node memory)
        self.node_proj = nn.Linear(actual_node_dim + memory_dim, hidden_dim)
        self.edge_proj = nn.Linear(actual_edge_dim, hidden_dim)

        # Multi-head attention projections
        self.q_proj = nn.Linear(hidden_dim, hidden_dim)
        self.k_proj = nn.Linear(hidden_dim, hidden_dim)
        self.v_proj = nn.Linear(hidden_dim, hidden_dim)

        # Spatial attention scorer
        self.attn_score = nn.Linear(self.head_dim, 1)

        # GRU Node Memory updater: h_v^(t) = GRU(h_v^(t-1), message_v)
        self.memory_gru = nn.GRUCell(hidden_dim, memory_dim)

        self.out_proj = nn.Linear(hidden_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout)
        self.layer_norm = nn.LayerNorm(hidden_dim)

        # Graph pooling projection: combines mean + max pooling (2 x hidden_dim -> hidden_dim)
        # Prevents dimension mismatch when feeding temporal transformer
        self.pool_proj = nn.Linear(2 * hidden_dim, hidden_dim)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor,
        node_memory: torch.Tensor,
        action_mask_nodes: torch.Tensor | None = None,
        action_mask_edges: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        num_nodes = x.size(0)
        num_edges = edge_index.size(1)

        # Counterfactual intervention: mask isolated nodes
        if action_mask_nodes is not None:
            x = x * action_mask_nodes.unsqueeze(-1)
            node_memory = node_memory * action_mask_nodes.unsqueeze(-1)

        # 1. Combine node features with prior node memory
        node_input = torch.cat([x, node_memory], dim=-1)
        h_node = F.relu(self.node_proj(node_input))

        if num_edges == 0:
            # Degenerate case: isolated nodes only — no aggregation happened,
            # so do NOT update memory (would inject ghost drift).
            mean_p = h_node.mean(dim=0)
            max_p = h_node.max(dim=0)[0]
            pooled = self.pool_proj(torch.cat([mean_p, max_p], dim=-1))
            dummy_attn = torch.empty(0, device=x.device)
            return h_node, pooled, node_memory, dummy_attn  # memory unchanged

        # Counterfactual intervention: mask blocked edges (e.g. blocked ports)
        if action_mask_edges is not None:
            edge_attr = edge_attr * action_mask_edges.unsqueeze(-1)

        h_edge = F.relu(self.edge_proj(edge_attr))

        # 2. Compute spatial attention on active edges
        src_nodes, dst_nodes = edge_index[0], edge_index[1]

        # Target node Q, Source node K (with edge features integrated into key)
        q = self.q_proj(h_node[dst_nodes]).view(num_edges, self.num_heads, self.head_dim)
        k = (self.k_proj(h_node[src_nodes]) + h_edge).view(num_edges, self.num_heads, self.head_dim)
        v = (self.v_proj(h_node[src_nodes]) + h_edge).view(num_edges, self.num_heads, self.head_dim)

        # Scaled dot-product attention
        scores = (q * k).sum(dim=-1) / math.sqrt(self.head_dim)            # [E, H]

        # Scatter softmax: normalise over each destination node's in-edges.
        # sigmoid would let aggregated messages grow unboundedly on high-degree nodes.
        exp_scores = torch.exp(scores - scores.max())                      # stability shift
        denom = torch.zeros(num_nodes, self.num_heads, device=x.device)
        denom.index_add_(0, dst_nodes, exp_scores)
        attn_weights = exp_scores / (denom[dst_nodes] + 1e-16)             # [E, H]
        mean_attn_per_edge = attn_weights.mean(dim=-1)                     # [E] for explainability

        # Weighted message aggregation to destination nodes
        messages = (v * attn_weights.unsqueeze(-1)).view(num_edges, self.hidden_dim)
        aggregated = torch.zeros((num_nodes, self.hidden_dim), device=x.device)
        aggregated.index_add_(0, dst_nodes, messages)

        # 3. Residual connection & LayerNorm
        h_out = self.layer_norm(h_node + self.dropout(self.out_proj(aggregated)))

        # 4. TGN Node Memory Update
        updated_memory = self.memory_gru(h_out, node_memory)

        # 5. Graph-level pooled embedding: mean + max pooling concatenated, projected to hidden_dim
        mean_pool = h_out.mean(dim=0)
        max_pool = h_out.max(dim=0)[0]
        pooled_graph = self.pool_proj(torch.cat([mean_pool, max_pool], dim=-1))

        return h_out, pooled_graph, updated_memory, mean_attn_per_edge

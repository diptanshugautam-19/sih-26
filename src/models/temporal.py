"""
src/models/temporal.py

Causal Temporal Sequence Transformer Encoder.

Operates over the ordered sequence of graph embeddings [z_1, ..., z_10].
Uses strict causal triangular masking to enforce the arrow of time:
predictions at time t cannot peek at future windows t' > t.
"""

from __future__ import annotations
import math
import torch
import torch.nn as nn
import torch.nn.functional as F


class CausalTemporalTransformer(nn.Module):
    """
    Learns temporal state-transition dynamics P(S_{t+1} | S_t, ..., S_{t-9}).
    """
    def __init__(
        self,
        embed_dim: int = 64,
        in_dim: int | None = None,
        num_layers: int = 3,
        num_heads: int = 4,
        ff_dim: int = 256,
        dropout: float = 0.1,
        max_seq_len: int = 32,
    ):
        super().__init__()
        self.embed_dim = embed_dim
        actual_in_dim = in_dim if in_dim is not None else embed_dim

        # Input projection layer: projects from in_dim (e.g. 2 x hidden_dim = 128 from mean+max pooling)
        # down to transformer embed_dim (64)
        if actual_in_dim != embed_dim:
            self.in_proj = nn.Linear(actual_in_dim, embed_dim)
        else:
            self.in_proj = nn.Identity()

        # Learnable / Sinusoidal positional embeddings
        self.pos_embedding = nn.Parameter(torch.randn(1, max_seq_len, embed_dim) * 0.02)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=ff_dim,
            dropout=dropout,
            batch_first=True,
            activation="gelu",
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.norm = nn.LayerNorm(embed_dim)

    def _generate_causal_mask(self, seq_len: int, device: torch.device) -> torch.Tensor:
        """Lower triangular boolean mask preventing attention to future tokens."""
        mask = torch.triu(torch.ones(seq_len, seq_len, device=device), diagonal=1).bool()
        return mask

    def forward(self, graph_seq: torch.Tensor) -> torch.Tensor:
        """
        Inputs:
            graph_seq: [batch_size, seq_len, in_dim] or [seq_len, in_dim]
        Outputs:
            temporal_latents: [batch_size, seq_len, embed_dim]
        """
        is_single = (graph_seq.dim() == 2)
        if is_single:
            graph_seq = graph_seq.unsqueeze(0)

        # Safeguard: GNN encoder must output exactly embed_dim.
        # The runtime auto-projection trick that was here before was NOT registered
        # in nn.Module, so it never appeared in state_dict and was silently re-randomised
        # on every checkpoint load. Enforce the contract with a hard assert instead.
        if graph_seq.size(-1) != self.embed_dim:
            raise ValueError(
                f"Expected graph embeddings of dim {self.embed_dim}, "
                f"got {graph_seq.size(-1)}. Ensure GNNEncoder/DynamicGATWithMemory "
                f"uses project_pooling=True and out_dim={self.embed_dim}."
            )
        graph_seq = self.in_proj(graph_seq)  # Identity when dims match

        batch_size, seq_len, _ = graph_seq.shape
        pos = self.pos_embedding[:, :seq_len, :]

        x = graph_seq + pos
        causal_mask = self._generate_causal_mask(seq_len, graph_seq.device)

        out = self.transformer(x, mask=causal_mask)
        out = self.norm(out)

        if is_single:
            return out.squeeze(0)
        return out

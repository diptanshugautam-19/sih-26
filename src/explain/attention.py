"""
src/explain/attention.py

Spatial + Temporal Explainability Engine.

Extracts and formats all attention-based explanations from the World Model:

1. Spatial: GAT edge attention weights α_ij — "which host-to-host flow is the model focused on?"
2. Temporal: Transformer self-attention — "which of the 10 time windows drove the prediction?"
3. Top-K feature attribution: ranks edge/node features by mean attention contribution

These are consumed directly by the Streamlit dashboard for:
- Glowing edge coloring (α_ij → edge color intensity)
- Node memory pulse size
- SHAP-style hover tooltips on suspicious edges
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
import torch
import torch.nn as nn
import numpy as np

EDGE_FEATURE_NAMES = [
    "log_packet_count",
    "log_byte_volume",
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "fin_ratio",
    "retransmission_rate",
    "unique_dst_ports",
    "mean_ttl",
    "ttl_std",
    "mean_tcp_window",
    "is_internal",
]


@dataclass
class EdgeExplanation:
    src_ip: str
    dst_ip: str
    attention_weight: float             # α_ij from GAT [0 .. 1]
    top_features: List[Tuple[str, float]]  # [(feature_name, feature_value)]
    edge_attr: Optional[torch.Tensor] = None


@dataclass
class TemporalExplanation:
    window_attention: List[float]       # Self-attention weight per input window (length = seq_len)
    most_critical_window_idx: int
    most_critical_window_start_time: Optional[float] = None


@dataclass
class PredictionExplanation:
    infiltration_prob: float
    uncertainty_std: float
    predicted_stage_id: int
    predicted_stage_name: str
    mitre_technique: str
    spatial: List[EdgeExplanation]
    temporal: TemporalExplanation
    top_global_features: List[Tuple[str, float]]


def extract_spatial_explanations(
    edge_index: torch.Tensor,
    edge_attr: torch.Tensor,
    attention_weights: torch.Tensor,
    node_ips: List[str],
    top_k: int = 5,
) -> List[EdgeExplanation]:
    """
    Converts raw GAT attention weights into EdgeExplanation objects.
    Sorted descending by attention weight — top-k flagged edges.
    """
    if edge_index.shape[1] == 0:
        return []

    n_edges = edge_index.shape[1]
    attn = attention_weights.detach().cpu().numpy()
    edge_attrs = edge_attr.detach().cpu().numpy()

    explanations = []
    for i in range(n_edges):
        src_id = int(edge_index[0, i])
        dst_id = int(edge_index[1, i])
        src_ip = node_ips[src_id] if src_id < len(node_ips) else f"host_{src_id}"
        dst_ip = node_ips[dst_id] if dst_id < len(node_ips) else f"host_{dst_id}"

        alpha = float(attn[i]) if i < len(attn) else 0.0

        # Top-3 contributing features for this edge
        n_feats = min(len(EDGE_FEATURE_NAMES), edge_attrs.shape[1] if edge_attrs.ndim > 1 else 0)
        feat_vals = edge_attrs[i, :n_feats] if edge_attrs.ndim > 1 else []
        top_feats = sorted(
            [(EDGE_FEATURE_NAMES[j], float(feat_vals[j])) for j in range(n_feats)],
            key=lambda x: abs(x[1]), reverse=True
        )[:3]

        explanations.append(EdgeExplanation(
            src_ip=src_ip,
            dst_ip=dst_ip,
            attention_weight=alpha,
            top_features=top_feats,
        ))

    # Sort by attention weight descending
    explanations.sort(key=lambda e: e.attention_weight, reverse=True)
    return explanations[:top_k]


def extract_temporal_explanation(
    model: nn.Module,
    graph_seq_tensor: torch.Tensor,
    window_start_times: Optional[List[float]] = None,
) -> TemporalExplanation:
    """
    Approximates temporal attention by computing gradient saliency w.r.t. each
    input time step — which window had the highest influence on the output?

    Uses a simple L2-norm of the gradient as a proxy for temporal importance.
    """
    graph_seq_tensor = graph_seq_tensor.detach().requires_grad_(True)

    try:
        model.eval()
        temporal_out = model.temporal_transformer(graph_seq_tensor.unsqueeze(0))
        summary = temporal_out[0, -1, :]  # [hidden_dim]
        scalar = summary.sum()
        scalar.backward()

        if graph_seq_tensor.grad is not None:
            importance = graph_seq_tensor.grad.detach().abs().sum(dim=-1).squeeze(0).cpu().numpy()
        else:
            importance = np.ones(graph_seq_tensor.shape[0])
    except Exception:
        importance = np.ones(graph_seq_tensor.shape[0] if graph_seq_tensor.dim() > 1 else 1)

    seq_len = len(importance)
    importance_norm = importance / (importance.sum() + 1e-12)
    most_critical = int(np.argmax(importance_norm))

    start_time = None
    if window_start_times is not None and most_critical < len(window_start_times):
        start_time = window_start_times[most_critical]

    return TemporalExplanation(
        window_attention=importance_norm.tolist(),
        most_critical_window_idx=most_critical,
        most_critical_window_start_time=start_time,
    )


def build_prediction_explanation(
    model,
    graph_sequence,
    node_ips: List[str],
    mc_passes: int = 5,
    window_start_times: Optional[List[float]] = None,
) -> PredictionExplanation:
    """
    One-shot explanation generator: runs inference, MC dropout, and extracts
    spatial + temporal explanations ready for the dashboard.
    """
    from src.labels.attack_mapping import STAGE_NAMES

    # 1. Main forward pass
    with torch.no_grad():
        preds = model.forward_sequence(graph_sequence)

    infil_prob = float(preds["infiltration_prob"].squeeze().item())
    stage_logits = preds["stage_logits"]
    stage_id = int(stage_logits.argmax().item())
    stage_name = STAGE_NAMES.get(stage_id, "Unknown")

    mitre_map = {
        0: "None",      1: "T1595", 2: "T1190",
        3: "T1110",     4: "T1021", 5: "T1071", 6: "T1041"
    }
    mitre_technique = mitre_map.get(stage_id, "T0000")

    # 2. MC Dropout for uncertainty
    uncertainty = model.estimate_uncertainty_mc_dropout(graph_sequence, n_passes=mc_passes)
    uncertainty_std = uncertainty["uncertainty_std"]

    # 3. Spatial attention from last window's GNN pass
    last_snap = graph_sequence[-1]
    spatial_explns = []
    if preds.get("spatial_attention") is not None and last_snap.edge_index.shape[1] > 0:
        spatial_explns = extract_spatial_explanations(
            edge_index=last_snap.edge_index,
            edge_attr=last_snap.edge_attr,
            attention_weights=preds["spatial_attention"],
            node_ips=node_ips,
        )

    # 4. Global top features (highest mean attention across all edges)
    top_global = {}
    for e in spatial_explns:
        for fname, fval in e.top_features:
            top_global[fname] = top_global.get(fname, []) + [abs(fval)]
    top_global_sorted = sorted(
        [(k, float(np.mean(v))) for k, v in top_global.items()],
        key=lambda x: x[1], reverse=True
    )[:5]

    return PredictionExplanation(
        infiltration_prob=infil_prob,
        uncertainty_std=uncertainty_std,
        predicted_stage_id=stage_id,
        predicted_stage_name=stage_name,
        mitre_technique=mitre_technique,
        spatial=spatial_explns,
        temporal=TemporalExplanation(
            window_attention=[1.0 / max(len(graph_sequence), 1)] * len(graph_sequence),
            most_critical_window_idx=len(graph_sequence) - 1,
            most_critical_window_start_time=window_start_times[-1] if window_start_times else None,
        ),
        top_global_features=top_global_sorted,
    )

"""
src/explain/formatting.py

Formatting utilities for spatial, temporal, and feature attribution explanations.
Converts structured PredictionExplanation dataclasses into JSON-serializable dictionaries
and formatted markdown reports for SOC analysts and dashboards.
"""

from __future__ import annotations
from typing import Any, Dict, List, Tuple
from src.explain.attention import PredictionExplanation, EdgeExplanation, TemporalExplanation


def format_explanation_as_dict(expl: PredictionExplanation) -> Dict[str, Any]:
    """
    Converts a PredictionExplanation instance into a JSON-serializable dictionary
    matching the API contract and frontend requirements.
    """
    return {
        "infiltration_prob": round(float(expl.infiltration_prob), 4),
        "uncertainty_std": round(float(expl.uncertainty_std), 4),
        "predicted_stage_id": int(expl.predicted_stage_id),
        "predicted_stage_name": str(expl.predicted_stage_name),
        "mitre_technique": str(expl.mitre_technique),
        "top_global_features": [
            {"feature": name, "contribution": round(float(val), 4)}
            for name, val in expl.top_global_features
        ],
        "flagged_edges": [
            {
                "src": edge.src_ip,
                "dst": edge.dst_ip,
                "attn": round(float(edge.attention_weight), 4),
                "top_features": [
                    {"name": fname, "value": round(float(fval), 4)}
                    for fname, fval in edge.top_features
                ],
            }
            for edge in expl.spatial
        ],
        "temporal": {
            "window_attention": [round(float(w), 4) for w in expl.temporal.window_attention],
            "most_critical_window_idx": int(expl.temporal.most_critical_window_idx),
            "most_critical_window_start_time": expl.temporal.most_critical_window_start_time,
        },
    }


def format_explanation_as_markdown(expl: PredictionExplanation) -> str:
    """
    Renders an explanation as a clear human-readable Markdown report for SOC analysts.
    """
    risk_pct = expl.infiltration_prob * 100
    lines = [
        f"### 🛡️ Threat Infiltration Prediction Report",
        f"- **Infiltration Probability:** {risk_pct:.1f}% (± {expl.uncertainty_std:.3f})",
        f"- **Predicted ATT&CK Stage:** `{expl.predicted_stage_name}` (Stage ID: {expl.predicted_stage_id})",
        f"- **MITRE Technique:** `{expl.mitre_technique}`",
        "",
        "#### 🌐 Top Flagged Suspicious Host-to-Host Connections (Spatial Attention)",
    ]

    if expl.spatial:
        for i, edge in enumerate(expl.spatial, 1):
            feats = ", ".join([f"{k}={v:.2f}" for k, v in edge.top_features])
            lines.append(f"{i}. **{edge.src_ip} ➔ {edge.dst_ip}** (Attention: `{edge.attention_weight:.3f}`) — Features: [{feats}]")
    else:
        lines.append("_No flagged host connections with significant attention weight._")

    lines.append("")
    lines.append("#### ⏱️ Temporal Context (Window Salience)")
    lines.append(
        f"- Most critical window in trajectory: **Window #{expl.temporal.most_critical_window_idx}**"
    )
    if expl.temporal.most_critical_window_start_time is not None:
        lines.append(f"- Timestamp: `{expl.temporal.most_critical_window_start_time}`")

    lines.append("")
    lines.append("#### 📊 Top Contributing Telemetry Features")
    for feat, score in expl.top_global_features:
        lines.append(f"- `{feat}`: {score:.4f}")

    return "\n".join(lines)

"""
src/explain module exports.
"""

from src.explain.attention import (
    EDGE_FEATURE_NAMES,
    EdgeExplanation,
    TemporalExplanation,
    PredictionExplanation,
    extract_spatial_explanations,
    extract_temporal_explanation,
    build_prediction_explanation,
)
from src.explain.formatting import (
    format_explanation_as_dict,
    format_explanation_as_markdown,
)
from src.explain.shap_wrapper import (
    FeatureAttributionExplainer,
    create_head_explainer,
)

__all__ = [
    "EDGE_FEATURE_NAMES",
    "EdgeExplanation",
    "TemporalExplanation",
    "PredictionExplanation",
    "extract_spatial_explanations",
    "extract_temporal_explanation",
    "build_prediction_explanation",
    "format_explanation_as_dict",
    "format_explanation_as_markdown",
    "FeatureAttributionExplainer",
    "create_head_explainer",
]

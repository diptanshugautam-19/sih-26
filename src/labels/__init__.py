"""
src/labels module exports.
"""

from src.labels.attack_mapping import (
    STAGE_NAMES,
    RAW_LABEL_TO_ATTACK_STAGE,
    map_label_to_stage,
    is_malicious,
    normalize_label,
)
from src.labels.pseudo_labeler import annotate_dataframe_with_pseudo_labels
from src.labels.window_labels import (
    aggregate_window_mitre_label,
    extract_stage_transitions,
)
from src.labels.splits import (
    temporal_block_split,
    unseen_attack_split,
)

__all__ = [
    "STAGE_NAMES",
    "RAW_LABEL_TO_ATTACK_STAGE",
    "map_label_to_stage",
    "is_malicious",
    "normalize_label",
    "annotate_dataframe_with_pseudo_labels",
    "aggregate_window_mitre_label",
    "extract_stage_transitions",
    "temporal_block_split",
    "unseen_attack_split",
]

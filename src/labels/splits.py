"""
src/labels/splits.py

Dataset splitting methodologies for predictive cyber defence world models.

CRITICAL DESIGN PRINCIPLES:
1. Temporal Block Splitting:
   Consecutive sliding sequences share 90% overlap (stride 2.5s on 5s windows, seq_len=10).
   A naive random shuffle leaks near-identical graph sequences between train and test sets.
   Temporal splitting partitions continuous time blocks and inserts a blackout safety buffer
   (buffer >= seq_len + horizon_k) to prevent boundary leakage.

2. Unseen-Attack OOD Splitting:
   Evaluates true generalization against novel zero-day threats by holding out entire
   MITRE ATT&CK stages or attack families from train/val, reserving them purely for test.
"""

from __future__ import annotations
import random
from typing import List, Tuple, Optional, Set, Any
import numpy as np


def temporal_block_split(
    dataset: Any,
    train_frac: float = 0.70,
    val_frac: float = 0.15,
    buffer_sequences: int = 14,
) -> Tuple[List[int], List[int], List[int]]:
    """
    Partitions sequences into contiguous chronological blocks with safety buffers.

    Structure:
    [--- Train Block ---][Buffer][--- Val Block ---][Buffer][--- Test Block ---]

    Args:
        dataset: CyberDefenceDataset or any indexable sequence list.
        train_frac: Proportion of timeline allocated to training (default 0.70).
        val_frac: Proportion of timeline allocated to validation (default 0.15).
        buffer_sequences: Number of sequences discarded between splits to prevent
            boundary overlap leakage (default 14 >= seq_len 10 + horizon 4).

    Returns:
        (train_indices, val_indices, test_indices)
    """
    n_total = len(dataset)
    if n_total == 0:
        return [], [], []

    # Dynamically scale buffer if dataset is compact (e.g. unit tests)
    buf = buffer_sequences
    while buf > 0 and (n_total - 2 * buf) < 3:
        buf = max(0, buf - 1)

    n_train_target = int(n_total * train_frac)
    n_val_target = int(n_total * val_frac)

    train_end = max(1, min(n_train_target, n_total - 2))
    train_idx = list(range(0, train_end))

    val_start = min(train_end + buf, n_total)
    val_end = min(val_start + n_val_target, n_total)
    val_idx = list(range(val_start, val_end))

    test_start = min(val_end + buf, n_total)
    test_idx = list(range(test_start, n_total))

    # Guard against empty partitions on miniature test fixtures
    if len(test_idx) == 0 and len(train_idx) > 2:
        test_idx = [train_idx.pop()]
    if len(val_idx) == 0 and len(train_idx) > 2:
        val_idx = [train_idx.pop()]

    return train_idx, val_idx, test_idx


def unseen_attack_split(
    dataset: Any,
    holdout_stages: Optional[List[int]] = None,
    holdout_names: Optional[List[str]] = None,
    train_val_frac: float = 0.85,
    buffer_sequences: int = 14,
    seed: int = 42,
) -> Tuple[List[int], List[int], List[int]]:
    """
    Partitions dataset by holding out entire attack classes/stages for Out-Of-Distribution (OOD) evaluation.

    Any sequence featuring a holdout MITRE stage (or attack type) is routed directly
    to the test split. The remaining known traffic (benign + other attacks) is split
    temporally into train and val.

    Args:
        dataset: CyberDefenceDataset.
        holdout_stages: List of MITRE stage IDs to hold out (e.g. [5, 6] for Lateral Movement & Exfiltration).
        holdout_names: Optional list of attack strings or stage names to hold out.
        train_val_frac: Fraction of known traffic allocated to train vs val.
        buffer_sequences: Safety buffer applied between train and val.
        seed: Random seed for reproducibility.

    Returns:
        (train_indices, val_indices, test_unseen_indices)
    """
    holdout_stage_set: Set[int] = set(holdout_stages or [])
    holdout_name_set: Set[str] = set(n.lower() for n in (holdout_names or []))

    known_indices: List[int] = []
    test_unseen_indices: List[int] = []

    for idx, sample in enumerate(dataset):
        is_holdout = False

        stage_id = getattr(sample, "mitre_stage_id", None)
        if stage_id is not None and stage_id in holdout_stage_set:
            is_holdout = True

        stage_name = getattr(sample, "mitre_stage_name", "")
        if stage_name and stage_name.lower() in holdout_name_set:
            is_holdout = True

        if is_holdout:
            test_unseen_indices.append(idx)
        else:
            known_indices.append(idx)

    # Split known indices temporally
    n_known = len(known_indices)
    if n_known == 0:
        return [], [], test_unseen_indices

    buf = buffer_sequences
    while buf > 0 and (n_known - buf) < 2:
        buf = max(0, buf - 1)

    n_train = max(1, int(n_known * train_val_frac))
    train_known = known_indices[:n_train]
    val_start = min(n_train + buf, n_known)
    val_known = known_indices[val_start:]

    return train_known, val_known, test_unseen_indices

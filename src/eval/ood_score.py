"""
src/eval/ood_score.py

Out-Of-Distribution (OOD) Scoring & Distribution Divergence Engine.
Measures distribution shift between seen training traffic and novel/unseen attack traffic.
"""

from __future__ import annotations
from typing import Dict, Optional, Tuple, Union
import numpy as np


def compute_distribution_kl_divergence(
    p_samples: np.ndarray,
    q_samples: np.ndarray,
    bins: int = 30,
    epsilon: float = 1e-7,
) -> float:
    """
    Computes symmetric Kullback-Leibler (Jensen-Shannon) divergence between
    two feature distributions across shared feature dimensions.
    """
    p = np.asarray(p_samples, dtype=np.float64)
    q = np.asarray(q_samples, dtype=np.float64)

    if p.ndim == 1:
        p = p[:, None]
    if q.ndim == 1:
        q = q[:, None]

    n_feats = min(p.shape[1], q.shape[1])
    divs = []

    for i in range(n_feats):
        f_min = min(float(np.min(p[:, i])), float(np.min(q[:, i])))
        f_max = max(float(np.max(p[:, i])), float(np.max(q[:, i])))
        if abs(f_max - f_min) < 1e-9:
            continue

        bin_edges = np.linspace(f_min, f_max, bins + 1)
        p_hist, _ = np.histogram(p[:, i], bins=bin_edges, density=True)
        q_hist, _ = np.histogram(q[:, i], bins=bin_edges, density=True)

        p_prob = (p_hist + epsilon) / (np.sum(p_hist + epsilon))
        q_prob = (q_hist + epsilon) / (np.sum(q_hist + epsilon))

        m = 0.5 * (p_prob + q_prob)
        js = 0.5 * np.sum(p_prob * np.log(p_prob / m)) + 0.5 * np.sum(q_prob * np.log(q_prob / m))
        divs.append(float(js))

    return float(np.mean(divs)) if divs else 0.0


class OODScorer:
    """
    Calibrated Out-Of-Distribution detector based on embedding distance to training distribution.
    Produces an OOD score normalized between 0.0 (in-distribution) and 1.0 (novel distribution).
    """

    def __init__(self):
        self.mean: Optional[np.ndarray] = None
        self.cov_inv: Optional[np.ndarray] = None
        self.threshold_95: float = 1.0

    def fit(self, train_embeddings: np.ndarray) -> "OODScorer":
        """
        Fits baseline distribution parameters on training graph/telemetry embeddings.
        """
        emb = np.asarray(train_embeddings, dtype=np.float64)
        if emb.ndim == 1:
            emb = emb.reshape(1, -1)

        self.mean = np.mean(emb, axis=0)
        diff = emb - self.mean
        cov = np.cov(diff, rowvar=False)

        # Add small ridge for numerical stability
        if cov.ndim == 0:
            cov = np.array([[float(cov)]])
        cov += np.eye(cov.shape[0]) * 1e-4
        self.cov_inv = np.linalg.pinv(cov)

        # Calibrate 95th percentile distance on training set
        train_dists = [self._mahalanobis(v) for v in emb]
        self.threshold_95 = float(np.percentile(train_dists, 95)) if len(train_dists) > 0 else 1.0
        if self.threshold_95 <= 0.0:
            self.threshold_95 = 1.0
        return self

    def _mahalanobis(self, vec: np.ndarray) -> float:
        if self.mean is None or self.cov_inv is None:
            return 0.0
        diff = (vec - self.mean).reshape(1, -1)
        dist = np.sqrt(np.clip(diff @ self.cov_inv @ diff.T, 0.0, None))
        return float(dist.item())

    def score(self, test_embeddings: np.ndarray) -> np.ndarray:
        """
        Returns normalized OOD scores [0.0 ... 1.0].
        Scores > 0.8 indicate highly anomalous / unseen traffic.
        """
        emb = np.asarray(test_embeddings, dtype=np.float64)
        is_single = (emb.ndim == 1)
        if is_single:
            emb = emb.reshape(1, -1)

        scores = []
        for v in emb:
            d = self._mahalanobis(v)
            # Sigmoid scaling around 95th percentile
            norm_score = 1.0 / (1.0 + np.exp(-1.5 * (d / self.threshold_95 - 1.0)))
            scores.append(float(np.clip(norm_score, 0.0, 1.0)))

        res = np.array(scores, dtype=np.float32)
        return res[0] if is_single else res


def compute_ood_score(
    test_embedding: np.ndarray,
    reference_embeddings: Optional[np.ndarray] = None,
) -> float:
    """
    Convenience function returning a single OOD score float in [0.0, 1.0].
    """
    if reference_embeddings is None:
        # Fallback heuristic based on norm variance
        val = float(np.tanh(np.linalg.norm(test_embedding) / 20.0))
        return round(val, 4)

    scorer = OODScorer().fit(reference_embeddings)
    return round(float(scorer.score(test_embedding)), 4)

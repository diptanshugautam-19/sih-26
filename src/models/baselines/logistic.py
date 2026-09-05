"""
src/models/baselines/logistic.py

Per-Flow Logistic Regression Baseline (Ablation 1).

Required by the NCIIPC challenge brief — explicitly demonstrates that the
World Model's temporal dynamics learning provides measurable improvement
over a static per-flow classifier.

Pipeline:
1. Flattens each flow into a flat feature vector (no temporal context).
2. Trains a Logistic Regression with class-weight balancing.
3. Evaluates on the same train/val/test split as the World Model.
"""

from __future__ import annotations
from typing import Tuple, Dict, List, Optional
import numpy as np
import pandas as pd

from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    f1_score, precision_score, recall_score, confusion_matrix, roc_auc_score
)


# Feature names must match the columns produced by src/data/flow_features.py.
# The original list (payload_size, flag_syn, ...) did not exist in flow_features output,
# so _extract_features silently returned an empty matrix and the baseline trained on
# zero features — producing meaningless metrics.
FLOW_FEATURES = [
    "bytes_fwd",        # total forward bytes
    "bytes_bwd",        # total backward bytes
    "pkt_size_mean",    # mean packet size
    "pkt_size_std",     # stddev packet size
    "iat_mean_ms",      # mean inter-arrival time (ms)
    "iat_std_ms",       # stddev inter-arrival time
    "syn_ratio",        # SYN packet fraction
    "fin_ratio",        # FIN packet fraction
    "port_entropy",     # entropy over destination ports
    "log_bytes_total",  # log(1 + total bytes)
]


class PerFlowLogisticBaseline:
    """
    Logistic Regression trained on individual flow-level features with no
    temporal or graph context. Serves as the benchmark for demonstrating
    world model improvement.
    """

    def __init__(self, max_iter: int = 500, seed: int = 42):
        self.pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                class_weight="balanced",
                max_iter=max_iter,
                random_state=seed,
                solver="lbfgs",
            ))
        ])
        self.is_trained = False
        self._feature_names: List[str] = []

    def _extract_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Extract available features as a numpy matrix."""
        available = [f for f in FLOW_FEATURES if f in df.columns]
        self._feature_names = available

        X = df[available].fillna(0.0).astype(float).values

        # Binary label: 1 if any attack stage, 0 if benign
        if "mitre_stage_id" in df.columns:
            y = (df["mitre_stage_id"] > 0).astype(int).values
        elif "label" in df.columns:
            from src.labels.attack_mapping import is_malicious
            y = df["label"].apply(is_malicious).astype(int).values
        elif "Label" in df.columns:
            from src.labels.attack_mapping import is_malicious
            y = df["Label"].apply(is_malicious).astype(int).values
        else:
            y = np.zeros(len(df), dtype=int)

        return X, y

    def fit(self, train_df: pd.DataFrame, max_samples: int = 200_000) -> "PerFlowLogisticBaseline":
        if len(train_df) > max_samples:
            train_df = train_df.sample(n=max_samples, random_state=42)
        X, y = self._extract_features(train_df)
        self.pipeline.fit(X, y)
        self.is_trained = True
        return self

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call .fit() first.")
        available = [f for f in FLOW_FEATURES if f in df.columns]
        X = df[available].fillna(0.0).astype(float).values
        return self.pipeline.predict(X)

    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call .fit() first.")
        available = [f for f in FLOW_FEATURES if f in df.columns]
        X = df[available].fillna(0.0).astype(float).values
        return self.pipeline.predict_proba(X)[:, 1]

    def evaluate(self, test_df: pd.DataFrame, threshold: float = 0.5, max_samples: int = 200_000) -> Dict:
        """Returns the full benchmark metric suite."""
        if len(test_df) > max_samples:
            test_df = test_df.sample(n=max_samples, random_state=42)
        _, y_true = self._extract_features(test_df)
        y_prob = self.predict_proba(test_df)
        y_pred = (y_prob >= threshold).astype(int)

        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        fpr = fp / max(fp + tn, 1)

        try:
            auroc = roc_auc_score(y_true, y_prob)
        except Exception:
            auroc = float("nan")

        return {
            "model": "LogisticRegression (per-flow, no temporal context)",
            "f1":        f1_score(y_true, y_pred, zero_division=0),
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall":    recall_score(y_true, y_pred, zero_division=0),
            "fpr":       fpr,
            "auroc":     auroc,
            "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
            "features_used": self._feature_names,
        }

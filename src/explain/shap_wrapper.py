"""
src/explain/shap_wrapper.py

SHAP and Feature Attribution Wrapper for World Model Prediction Heads.
Provides local feature attribution for infiltration and stage predictions.
Supports SHAP library if installed, with a native PyTorch gradient/perturbation
fallback when shap is not present in offline environments.
"""

from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import numpy as np
import torch
import torch.nn as nn


class FeatureAttributionExplainer:
    """
    Computes feature importance attributions for the infiltration prediction head.
    """

    def __init__(
        self,
        predict_fn: Callable[[np.ndarray], np.ndarray],
        feature_names: Optional[List[str]] = None,
        background_data: Optional[np.ndarray] = None,
    ):
        """
        Args:
            predict_fn: Function mapping [N, num_features] -> [N] (predicted infiltration probabilities)
            feature_names: Names for each feature column
            background_data: Baseline reference samples [M, num_features]
        """
        self.predict_fn = predict_fn
        self.feature_names = feature_names or []
        self.background_data = background_data
        self._has_shap = False

        try:
            import shap  # noqa: F401
            self._has_shap = True
        except ImportError:
            self._has_shap = False

    def explain(
        self,
        x: np.ndarray,
        num_samples: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Explains a single feature vector or batch of vectors.
        Returns a list of dictionaries with feature names and signed attribution values.
        """
        x = np.asarray(x, dtype=np.float32)
        if x.ndim == 1:
            x = x.reshape(1, -1)

        n_feats = x.shape[1]
        feature_names = (
            self.feature_names
            if len(self.feature_names) == n_feats
            else [f"feature_{i}" for i in range(n_feats)]
        )

        # Use SHAP KernelExplainer if available and background data provided
        if self._has_shap and self.background_data is not None:
            try:
                import shap
                explainer = shap.KernelExplainer(self.predict_fn, self.background_data[:10])
                shap_values = explainer.shap_values(x, nsamples=num_samples)
                if isinstance(shap_values, list):
                    vals = shap_values[0]
                else:
                    vals = shap_values
                mean_impacts = np.mean(vals, axis=0) if vals.ndim > 1 else vals[0]
                results = [
                    {"feature": name, "attribution": float(val)}
                    for name, val in zip(feature_names, mean_impacts)
                ]
                results.sort(key=lambda r: abs(r["attribution"]), reverse=True)
                return results
            except Exception:
                pass  # Fallback to perturbation attribution below

        # Native Shapley / Perturbation Attribution Fallback
        base_pred = float(self.predict_fn(x)[0])
        attributions = []

        baseline = (
            np.mean(self.background_data, axis=0, keepdims=True)
            if self.background_data is not None
            else np.zeros((1, n_feats), dtype=np.float32)
        )

        for i in range(n_feats):
            perturbed = x.copy()
            perturbed[0, i] = baseline[0, i]
            perturbed_pred = float(self.predict_fn(perturbed)[0])
            # Drop in prediction when feature is masked out
            attr = base_pred - perturbed_pred
            attributions.append({"feature": feature_names[i], "attribution": float(attr)})

        attributions.sort(key=lambda r: abs(r["attribution"]), reverse=True)
        return attributions


def create_head_explainer(
    head_module: nn.Module,
    input_dim: int,
    feature_names: Optional[List[str]] = None,
    device: str = "cpu",
) -> FeatureAttributionExplainer:
    """
    Convenience factory to build a FeatureAttributionExplainer for any PyTorch classification head.
    """
    head_module.eval().to(device)

    def predict_wrapper(x_np: np.ndarray) -> np.ndarray:
        with torch.no_grad():
            t = torch.as_tensor(x_np, dtype=torch.float32, device=device)
            out = head_module(t)
            if isinstance(out, dict):
                out = out.get("infiltration_prob", list(out.values())[0])
            if out.ndim > 1 and out.shape[-1] == 1:
                out = out.squeeze(-1)
            elif out.ndim > 1 and out.shape[-1] > 1:
                out = torch.softmax(out, dim=-1)[:, 1]
            return out.cpu().numpy()

    return FeatureAttributionExplainer(predict_fn=predict_wrapper, feature_names=feature_names)

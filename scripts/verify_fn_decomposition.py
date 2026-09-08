"""
scripts/verify_fn_decomposition.py

Direct validation of the 42/42 (Active Detection) + 4/10 (Anticipation) decomposition.
Tests the FN samples against stage labels, soft infiltration targets, and predictions.
"""

from __future__ import annotations
import sys
import math
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import torch

from src.data.unsw_adapter import prepare_unsw_nb15_dataset
from src.data.dataset import make_dataloaders
from src.models.worldmodel import CyberDefenceWorldModel
from src.training.train import eval_epoch
from src.training.losses import UncertaintyWeightedMultiTaskLoss

def wilson_ci(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    z = 1.95996  # 95%
    p = k / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    spread = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return max(0.0, center - spread), min(1.0, center + spread)

def main():
    data_path = Path("data/raw/unsw_nb15/UNSW_Flow.parquet")
    print(f"[1] Preparing dataset from {data_path.name}...")
    dataset = prepare_unsw_nb15_dataset(data_path, max_samples_per_class=3500, benign_sample_count=15000)

    _, _, test_dl = make_dataloaders(dataset, batch_size=32, seed=42, weighted_sampler=True)

    print("[2] Loading model weights...")
    model = CyberDefenceWorldModel()
    ckpt_path = Path("models/checkpoints/worldmodel_unsw_nb15.pt")
    state = torch.load(ckpt_path, map_location="cpu", weights_only=True)
    model.load_state_dict(state, strict=False)
    model.eval()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = model.to(device)

    loss_fn = UncertaintyWeightedMultiTaskLoss().to(device)
    _, test_raw = eval_epoch(model, test_dl, loss_fn, device)

    raw_targets = test_raw["infil_targets"]
    probs = test_raw["infil_preds"]
    y_true = (raw_targets >= 0.5).astype(int)
    y_pred = (probs >= 0.5).astype(int)
    stage_true = test_raw["stage_targets"]
    stage_pred = test_raw["stage_preds"]

    n = len(y_true)
    tp_mask = (y_true == 1) & (y_pred == 1)
    tn_mask = (y_true == 0) & (y_pred == 0)
    fp_mask = (y_true == 0) & (y_pred == 1)
    fn_mask = (y_true == 1) & (y_pred == 0)

    print("=" * 60)
    print(f"CONFUSION MATRIX (N = {n}):")
    print(f"  TP = {tp_mask.sum()} | TN = {tn_mask.sum()} | FP = {fp_mask.sum()} | FN = {fn_mask.sum()}")
    print("=" * 60)

    # Deconstruct into:
    # 1. Active In-Window Attack (Stage > 0)
    # 2. Anticipatory Window (Stage == 0, but y_true == 1 [attack in future horizon])
    # 3. Pure Benign Window (Stage == 0, and y_true == 0 [no attack now or horizon])
    active_mask = (stage_true > 0)
    anticipatory_mask = (stage_true == 0) & (y_true == 1)
    pure_benign_mask = (stage_true == 0) & (y_true == 0)

    print(f"\n[3] GROUND TRUTH SEQUENCE DECOMPOSITION:")
    print(f"  - Active Attack (In-Window Stage > 0) : {active_mask.sum()}")
    print(f"  - Anticipatory (Stage 0, Target in Horizon): {anticipatory_mask.sum()}")
    print(f"  - Pure Benign (Stage 0, Target Benign)     : {pure_benign_mask.sum()}")
    print(f"  Total: {active_mask.sum() + anticipatory_mask.sum() + pure_benign_mask.sum()} == {n}")

    # Active detection evaluation
    active_tp = tp_mask & active_mask
    active_fn = fn_mask & active_mask
    active_recall = active_tp.sum() / max(1, active_mask.sum())
    act_lo, act_hi = wilson_ci(active_tp.sum(), active_mask.sum())

    # Anticipation evaluation
    ant_tp = tp_mask & anticipatory_mask
    ant_fn = fn_mask & anticipatory_mask
    ant_recall = ant_tp.sum() / max(1, anticipatory_mask.sum())
    ant_lo, ant_hi = wilson_ci(ant_tp.sum(), anticipatory_mask.sum())

    # Pure benign evaluation
    ben_tn = tn_mask & pure_benign_mask
    ben_fp = fp_mask & pure_benign_mask
    fpr = ben_fp.sum() / max(1, pure_benign_mask.sum())
    fpr_lo, fpr_hi = wilson_ci(ben_fp.sum(), pure_benign_mask.sum())

    print("\n" + "=" * 60)
    print("REVEALED HEADLINE DECOMPOSITION:")
    print("=" * 60)
    print(f"  1. Active Attack Detection Recall: {active_tp.sum()}/{active_mask.sum()} = {active_recall*100:.2f}% (95% CI: [{act_lo*100:.1f}%, {act_hi*100:.1f}%])")
    print(f"  2. Anticipation Early-Warning Recall: {ant_tp.sum()}/{anticipatory_mask.sum()} = {ant_recall*100:.2f}% (95% CI: [{ant_lo*100:.1f}%, {ant_hi*100:.1f}%])")
    print(f"  3. Pure Benign False Positive Rate: {ben_fp.sum()}/{pure_benign_mask.sum()} = {fpr*100:.2f}% (95% CI: [{fpr_lo*100:.1f}%, {fpr_hi*100:.1f}%])")

    print("\n[4] DETAILS OF THE 6 FALSE NEGATIVES:")
    fn_indices = np.where(fn_mask)[0]
    for idx in fn_indices:
        st = stage_true[idx]
        sp = stage_pred[idx]
        yt = raw_targets[idx]
        yp = probs[idx]
        is_ant = bool(anticipatory_mask[idx])
        print(f"  Index {idx:2d} | Stage True: {st} | Stage Pred: {sp} | Infil Target: {yt:.3f} | Pred Prob: {yp:.3f} | Is Anticipation: {is_ant}")

    print("\n[5] DETAILS OF THE 4 ANTICIPATION HITS (TP):")
    ant_tp_indices = np.where(ant_tp)[0]
    for idx in ant_tp_indices:
        st = stage_true[idx]
        sp = stage_pred[idx]
        yt = raw_targets[idx]
        yp = probs[idx]
        print(f"  Index {idx:2d} | Stage True: {st} | Stage Pred: {sp} | Infil Target: {yt:.3f} | Pred Prob: {yp:.3f}")

    print("\n[6] HEAD DISAGREEMENT (Binary vs Stage Preds):")
    # Where Infil Pred >= 0.5 but Stage Pred == 0 (or vice versa)
    disagree = (y_pred == 1) & (stage_pred == 0)
    print(f"  Predicted Malicious (Prob >= 0.5) but Stage Pred == Benign (0): {disagree.sum()} samples")
    if disagree.sum() > 0:
        for idx in np.where(disagree)[0]:
            print(f"    Index {idx:2d} | Prob: {probs[idx]:.3f} | Infil Target: {raw_targets[idx]:.3f} | Stage Pred: {stage_pred[idx]} (Stage True: {stage_true[idx]})")

    disagree2 = (y_pred == 0) & (stage_pred > 0)
    print(f"  Predicted Benign (Prob < 0.5) but Stage Pred > 0: {disagree2.sum()} samples")

if __name__ == "__main__":
    main()

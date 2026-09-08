"""
scripts/investigate_temporal_positions.py

Checks:
1. Exact positions of stage_true > 0 in test_dl (0-67)
2. Exact timestamps and window intervals for all 68 test sequences
3. Attack packet timestamp distribution vs window [input_start, input_end] and [target_start, target_end]
4. Raw soft target formula inspect in dataset.py:187-206
"""

from __future__ import annotations
import sys
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

def main():
    data_path = Path("data/raw/unsw_nb15/UNSW_Flow.parquet")
    dataset = prepare_unsw_nb15_dataset(data_path, max_samples_per_class=3500, benign_sample_count=15000)

    train_dl, val_dl, test_dl = make_dataloaders(dataset, batch_size=32, seed=42, weighted_sampler=True)

    # 1. Recover test sequence samples directly
    test_samples = []
    for batch in test_dl:
        test_samples.extend(batch["samples"])

    # 2. Evaluate model
    model = CyberDefenceWorldModel()
    ckpt_path = Path("models/checkpoints/worldmodel_unsw_nb15.pt")
    state = torch.load(ckpt_path, map_location="cpu", weights_only=True)
    model.load_state_dict(state, strict=False)
    model.eval()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = model.to(device)
    loss_fn = UncertaintyWeightedMultiTaskLoss().to(device)

    _, test_raw = eval_epoch(model, test_dl, loss_fn, device)

    stage_true = test_raw["stage_targets"]
    probs = test_raw["infil_preds"]
    raw_targets = test_raw["infil_targets"]

    print("=" * 60)
    print("CHECK 1: EXACT POSITIONS OF stage_true > 0")
    print("=" * 60)
    actives = np.where(stage_true > 0)[0]
    print(f"Indices of stage_true > 0 (count={len(actives)}):")
    print(actives)

    stage0 = np.where(stage_true == 0)[0]
    print(f"\nIndices of stage_true == 0 (count={len(stage0)}):")
    print(stage0)

    print("\n" + "=" * 60)
    print("CHECK 2: PER-SAMPLE TIMELINE & WINDOW INSPECTION (Indices 35 to 55)")
    print("=" * 60)
    for i in range(max(0, 38), min(len(test_samples), 55)):
        s = test_samples[i]
        snaps = s.graph_sequence
        in_start = snaps[0].start_time
        in_end = snaps[-1].end_time
        # Inspect target windows
        print(f"Seq {i:2d} | In: [{in_start:.1f}s -> {in_end:.1f}s] | StageTrue: {s.mitre_stage_id} | SoftTarget: {s.infiltration_target:.4f} | Pred: {probs[i]:.4f}")

    print("\n" + "=" * 60)
    print("CHECK 3: ALL 68 SAMPLES SEQUENCE SUMMARY")
    print("=" * 60)
    for i in range(len(test_samples)):
        s = test_samples[i]
        st = s.mitre_stage_id
        yt = s.infiltration_target
        yp = probs[i]
        in_s = s.graph_sequence[0].start_time
        in_e = s.graph_sequence[-1].end_time
        if i % 5 == 0 or st == 0 or i >= 40:
            print(f"[{i:2d}] in=[{in_s:6.1f} - {in_e:6.1f}] st_true={st} target={yt:.3f} prob={yp:.3f}")

if __name__ == "__main__":
    main()

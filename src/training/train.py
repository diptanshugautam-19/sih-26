"""
src/training/train.py

Full Training Loop for the Predictive Cyber Defence World Model.

Features:
- AdamW optimiser with cosine annealing LR schedule
- Early stopping on validation infiltration loss
- Gradient clipping to prevent exploding gradients in Transformer
- Periodic checkpoint saving (best val loss and latest)
- Deterministic seed management
- Per-epoch metrics logging
"""

from __future__ import annotations
import os
import sys
import time
import random
import logging
from pathlib import Path

# Force UTF-8 on Windows to avoid cp1252 UnicodeEncodeError
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from typing import Dict, Tuple, Optional

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from sklearn.metrics import f1_score

from src.models.worldmodel import CyberDefenceWorldModel
from src.training.losses import UncertaintyWeightedMultiTaskLoss
from src.data.dataset import CyberDefenceDataset, make_dataloaders, collate_sequences
from src.training.seed import set_seed          # canonical location

logger = logging.getLogger(__name__)


# set_seed is defined in src/training/seed.py and re-imported above.
# Kept as a local passthrough so callers using `from src.training.train import set_seed` still work.



def _snap_to_device(snap, device: torch.device):
    """Move NetworkGraphSnapshot tensor fields to the target device in-place-safe way."""
    non_blocking = (device.type == "cuda")
    snap.x          = snap.x.to(device, non_blocking=non_blocking)
    snap.edge_index = snap.edge_index.to(device, non_blocking=non_blocking)
    snap.edge_attr  = snap.edge_attr.to(device, non_blocking=non_blocking)
    return snap


def _forward_batch(
    model: CyberDefenceWorldModel,
    batch: Dict,
    device: torch.device,
) -> Tuple[Dict[str, torch.Tensor], Dict[str, torch.Tensor]]:
    """
    Runs model forward pass over a batch, returning predictions and targets.
    Iterates sample-by-sample (no PyG batching required — keeps the codebase
    framework-independent and verifiable).
    """
    all_preds = {
        "grounded": [], "infiltration": [], "stage_logits": []
    }

    for sample in batch["samples"]:
        # Move every snapshot's tensors to device before the forward pass.
        # Without this, GPU training crashes with a device-mismatch error inside
        # DynamicGATWithMemory because targets are on CUDA but graph tensors are on CPU.
        graph_seq = [_snap_to_device(s, device) for s in sample.graph_sequence]
        preds = model.forward_sequence(graph_seq)
        all_preds["grounded"].append(preds["grounded_telemetry"])
        all_preds["infiltration"].append(preds["infiltration_prob"])
        all_preds["stage_logits"].append(preds["stage_logits"])

    # Stack into batch tensors
    # grounded: [B, K, 3]
    grounded_pred = torch.stack(all_preds["grounded"], dim=0)
    infil_pred    = torch.stack(all_preds["infiltration"], dim=0)      # [B, 1]
    stage_logits  = torch.stack(all_preds["stage_logits"], dim=0)      # [B, num_stages]

    non_blocking = (device.type == "cuda")
    targets = {
        "grounded": batch["grounded_targets"].to(device, non_blocking=non_blocking),              # [B, K, 3]
        "infiltration": batch["infiltration_targets"].to(device, non_blocking=non_blocking),      # [B]
        "stage": batch["stage_ids"].to(device, non_blocking=non_blocking),                        # [B]
        "stage_conf": batch["stage_confs"].to(device, non_blocking=non_blocking),                 # [B]
    }

    return {
        "grounded": grounded_pred,
        "infiltration": infil_pred,
        "stage_logits": stage_logits,
    }, targets


def train_epoch(
    model: CyberDefenceWorldModel,
    loader: DataLoader,
    optimizer: torch.optim.Optimizer,
    loss_fn: UncertaintyWeightedMultiTaskLoss,
    device: torch.device,
    grad_clip: float = 1.0,
    scaler: Optional[torch.amp.GradScaler] = None,
) -> Dict[str, float]:
    model.train()
    loss_fn.train()
    running = {k: 0.0 for k in ["loss_total", "loss_dynamics", "loss_infiltration", "loss_stage"]}
    n_batches = 0
    use_amp = (device.type == "cuda")

    for batch in loader:
        optimizer.zero_grad()

        with torch.amp.autocast(device_type="cuda", dtype=torch.float16, enabled=use_amp):
            preds, targets = _forward_batch(model, batch, device)

            loss, breakdown = loss_fn(
                grounded_pred=preds["grounded"],
                grounded_target=targets["grounded"],
                infil_pred=preds["infiltration"],
                infil_target=targets["infiltration"],
                stage_logits=preds["stage_logits"],
                stage_target=targets["stage"],
                stage_conf=targets["stage_conf"],
            )

        if scaler is not None and use_amp:
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(
                list(model.parameters()) + list(loss_fn.parameters()),
                max_norm=grad_clip
            )
            scaler.step(optimizer)
            scaler.update()
        else:
            loss.backward()
            torch.nn.utils.clip_grad_norm_(
                list(model.parameters()) + list(loss_fn.parameters()),
                max_norm=grad_clip
            )
            optimizer.step()

        for k in running:
            running[k] += breakdown.get(k, 0.0)
        n_batches += 1

    return {k: v / max(n_batches, 1) for k, v in running.items()}


@torch.no_grad()
def eval_epoch(
    model: CyberDefenceWorldModel,
    loader: DataLoader,
    loss_fn: UncertaintyWeightedMultiTaskLoss,
    device: torch.device,
) -> Tuple[Dict[str, float], Dict]:
    """Returns average losses and raw prediction arrays for metric computation."""
    model.eval()
    loss_fn.eval()
    running = {k: 0.0 for k in ["loss_total", "loss_dynamics", "loss_infiltration", "loss_stage"]}
    n_batches = 0
    use_amp = (device.type == "cuda")

    all_infil_preds, all_infil_targets, all_stage_preds, all_stage_targets = [], [], [], []

    for batch in loader:
        with torch.amp.autocast(device_type="cuda", dtype=torch.float16, enabled=use_amp):
            preds, targets = _forward_batch(model, batch, device)

            _, breakdown = loss_fn(
                grounded_pred=preds["grounded"],
                grounded_target=targets["grounded"],
                infil_pred=preds["infiltration"],
                infil_target=targets["infiltration"],
                stage_logits=preds["stage_logits"],
                stage_target=targets["stage"],
                stage_conf=targets["stage_conf"],
            )

        for k in running:
            running[k] += breakdown.get(k, 0.0)
        n_batches += 1

        all_infil_preds.extend(preds["infiltration"].squeeze(-1).cpu().tolist())
        all_infil_targets.extend(targets["infiltration"].cpu().tolist())
        all_stage_preds.extend(preds["stage_logits"].argmax(dim=-1).cpu().tolist())
        all_stage_targets.extend(targets["stage"].cpu().tolist())

    avg_losses = {k: v / max(n_batches, 1) for k, v in running.items()}
    raw = {
        "infil_preds": np.array(all_infil_preds),
        "infil_targets": np.array(all_infil_targets),
        "stage_preds": np.array(all_stage_preds),
        "stage_targets": np.array(all_stage_targets),
    }
    return avg_losses, raw


def train(
    dataset: CyberDefenceDataset,
    model: Optional[CyberDefenceWorldModel] = None,
    checkpoint_dir: str = "models",
    num_epochs: int = 25,
    batch_size: int = 8,
    lr: float = 5e-4,
    weight_decay: float = 1e-4,
    patience: int = 5,
    seed: int = 42,
    device_str: str = "auto",
) -> CyberDefenceWorldModel:
    """
    Full training pipeline. Returns the best-checkpoint model.

    Args:
        dataset: Pre-built CyberDefenceDataset.
        model: Optional pre-existing model. If None, creates a new one.
        checkpoint_dir: Where to save .pt checkpoints.
        num_epochs: Maximum training epochs.
        batch_size: Sequences per forward pass.
        lr: AdamW learning rate.
        weight_decay: L2 regularization.
        patience: Early-stopping patience (epochs without val improvement).
        seed: RNG seed for full reproducibility.
        device_str: "auto" | "cpu" | "cuda".
    """
    set_seed(seed)

    if device_str == "auto":
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    else:
        device = torch.device(device_str)

    if device.type == "cuda":
        torch.backends.cudnn.benchmark = True
        scaler = torch.amp.GradScaler("cuda")
        dev_name = torch.cuda.get_device_name(device)
        total_vram_gb = torch.cuda.get_device_properties(device).total_memory / (1024 ** 3)
        logger.info(f"CUDA enabled! GPU: {dev_name} ({total_vram_gb:.2f} GB VRAM) | cuDNN benchmark: True | AMP: True")
    else:
        scaler = None
        logger.info(f"Training on device: {device}")

    # Report class imbalance
    report = dataset.imbalance_report()
    logger.info(f"Dataset: {report}")

    # Build DataLoaders
    train_dl, val_dl, test_dl = make_dataloaders(
        dataset, batch_size=batch_size, seed=seed, weighted_sampler=True
    )

    if model is None:
        model = CyberDefenceWorldModel(
            node_dim=16, edge_dim=16, memory_dim=32, hidden_dim=64, seq_len=dataset.cfg.seq_len, horizon_k=dataset.cfg.horizon_k
        )
    model = model.to(device)

    loss_fn = UncertaintyWeightedMultiTaskLoss().to(device)

    optimizer = torch.optim.AdamW(
        list(model.parameters()) + list(loss_fn.parameters()),
        lr=lr, weight_decay=weight_decay
    )
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=num_epochs, eta_min=lr * 0.01)

    Path(checkpoint_dir).mkdir(parents=True, exist_ok=True)
    best_val_loss = float("inf")
    patience_counter = 0
    best_ckpt_path = Path(checkpoint_dir) / "best_model.pt"
    train_history = []

    print(f"\n{'='*60}")
    print(f"  Cyber Defence World Model -- Training")
    if device.type == "cuda":
        print(f"  Device: {device} ({torch.cuda.get_device_name(device)}) | VRAM: {total_vram_gb:.2f} GB")
    else:
        print(f"  Device: {device}")
    print(f"  Epochs: {num_epochs} | Batch: {batch_size} | AMP: {device.type == 'cuda'}")
    print(f"  Sequences: {len(dataset)} (Train: {len(train_dl.dataset)}, Val: {len(val_dl.dataset)}, Test: {len(test_dl.dataset)})")
    print(f"{'='*60}\n")

    for epoch in range(1, num_epochs + 1):
        t0 = time.time()
        train_losses = train_epoch(model, train_dl, optimizer, loss_fn, device, scaler=scaler)
        val_losses, val_raw = eval_epoch(model, val_dl, loss_fn, device)
        scheduler.step()

        elapsed = time.time() - t0
        val_loss = val_losses["loss_total"]

        # Infiltration F1 on validation set.
        # Raw accuracy is misleading on CIC-IDS2018 (~80% benign) — a model that
        # always predicts Benign achieves 80% accuracy while catching 0 attacks.
        if len(val_raw["infil_targets"]) > 0:
            val_infil_f1 = float(f1_score(
                (val_raw["infil_targets"] > 0.5).astype(int),
                (val_raw["infil_preds"]   > 0.5).astype(int),
                zero_division=0,
            ))
        else:
            val_infil_f1 = 0.0

        vram_stat = ""
        if device.type == "cuda":
            alloc_mb = torch.cuda.memory_allocated(device) / (1024 * 1024)
            peak_mb = torch.cuda.max_memory_allocated(device) / (1024 * 1024)
            vram_stat = f" | VRAM: {alloc_mb:.0f}MB (Peak {peak_mb:.0f}MB)"

        row = {
            "epoch": epoch,
            **{f"train_{k}": v for k, v in train_losses.items()},
            **{f"val_{k}": v for k, v in val_losses.items()},
            "val_infil_f1": val_infil_f1,
            "lr": scheduler.get_last_lr()[0],
            "elapsed_s": elapsed,
        }
        train_history.append(row)

        print(
            f"Epoch {epoch:03d}/{num_epochs:03d} | "
            f"Train Loss: {train_losses['loss_total']:.4f} | "
            f"Val Loss: {val_loss:.4f} | "
            f"Val Infil F1: {val_infil_f1:.3f} | "
            f"LR: {scheduler.get_last_lr()[0]:.2e} | "
            f"Time: {elapsed:.1f}s{vram_stat}"
        )

        # Save latest checkpoint every epoch
        torch.save({
            "epoch": epoch,
            "model_state": model.state_dict(),
            "loss_fn_state": loss_fn.state_dict(),
            "optimizer_state": optimizer.state_dict(),
            "val_loss": val_loss,
            "history": train_history,
        }, Path(checkpoint_dir) / "latest_model.pt")

        # Save best checkpoint
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            torch.save(model.state_dict(), best_ckpt_path)
            print(f"  [BEST] New best model saved (val_loss={best_val_loss:.4f})")
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"\n  [STOP] Early stopping triggered at epoch {epoch} (patience={patience})")
                break

    # Load best model before returning
    if best_ckpt_path.exists():
        # weights_only=True required for PyTorch >=2.0 to avoid FutureWarning and
        # >=2.6 hard error; also prevents arbitrary code execution from pickled objects.
        model.load_state_dict(torch.load(best_ckpt_path, map_location=device, weights_only=True))
        print(f"\n  [OK] Best model loaded from {best_ckpt_path}")

    # Run final test evaluation
    test_losses, test_raw = eval_epoch(model, test_dl, loss_fn, device)
    print(f"\n  Test Loss: {test_losses['loss_total']:.4f}")

    return model, test_raw, train_history


if __name__ == "__main__":
    import argparse
    import pandas as pd
    from src.data.clean_cicids import clean_dataframe
    from src.labels.pseudo_labeler import annotate_dataframe_with_pseudo_labels
    from src.data.packet_features import add_flow_level_derived_features
    from src.data.windowing import WindowConfig

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Train the Cyber Defence World Model.")
    parser.add_argument("csv_path", help="Path to cleaned CIC-IDS2018 or CTU-13 CSV file.")
    parser.add_argument("--epochs", type=int, default=25)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--lr", type=float, default=5e-4)
    parser.add_argument("--device", default="auto")
    parser.add_argument("--checkpoint-dir", default="models")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print(f"Loading {args.csv_path}...")
    df = pd.read_csv(args.csv_path)
    df = clean_dataframe(df)
    df = annotate_dataframe_with_pseudo_labels(df)

    cfg = WindowConfig(window_size=5.0, stride=2.5, seq_len=10, horizon_k=4)
    dataset = CyberDefenceDataset(df, cfg=cfg)

    print(f"Dataset built: {dataset.imbalance_report()}")

    model, test_raw, history = train(
        dataset,
        checkpoint_dir=args.checkpoint_dir,
        num_epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        device_str=args.device,
        seed=args.seed,
    )
    print("Training complete.")

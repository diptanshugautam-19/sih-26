"""
scripts/train_ctu.py

End-to-end training and evaluation script for the Predictive Cyber Defence World Model
on the official CTU-IDSEVAL-6 (CTU-13) dataset.
Runs on NVIDIA GeForce RTX 4050 GPU with Mixed Precision (AMP FP16),
providing live status checkpoints at every epoch.
"""

from __future__ import annotations
import os
import sys
import time
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime

# Prevent Windows OpenMP conflict
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Force UTF-8 stdout
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import numpy as np
import torch

from src.training.train import train
from src.data.ctu_adapter import prepare_ctu_idseval_dataset
from src.eval.metrics import full_evaluation_report

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

REGISTRY_PATH = REPO_ROOT / "TRAINING_REGISTRY.json"
CHECKPOINTS_DIR = REPO_ROOT / "models" / "checkpoints"
REPORTS_DIR = REPO_ROOT / "reports"


def train_ctu(
    data_path: str | Path,
    epochs: int = 25,
    batch_size: int = 32,
    lr: float = 5e-4,
    samples_per_capture: int = 12000,
    device_str: str = "auto",
):
    CHECKPOINTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Device Setup
    if device_str == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    else:
        device = device_str

    log.info("=" * 70)
    log.info("🚀 PREDICTIVE CYBER DEFENCE WORLD MODEL — CTU-IDSEVAL-6 (CTU-13) TRAINING")
    log.info("=" * 70)
    if device == "cuda" or (device == "auto" and torch.cuda.is_available()):
        gpu_name = torch.cuda.get_device_name(0)
        gpu_vram = torch.cuda.get_device_properties(0).total_memory / (1024 ** 3)
        torch.backends.cudnn.benchmark = True
        log.info(f"⚡ Hardware Accelerator: {gpu_name} ({gpu_vram:.2f} GB VRAM)")
        log.info(f"⚡ Precision: Mixed Precision (AMP FP16) | Tensor Cores Active")

    # 2. Ingest & Prepare CTU Dataset
    t0_data = time.time()
    dataset = prepare_ctu_idseval_dataset(data_path, max_samples_per_capture=samples_per_capture)
    imb = dataset.imbalance_report()
    log.info(f"📊 CTU Dataset Sequences: {len(dataset):,} total | {imb['malicious']} attack ({imb['malicious_pct']:.1f}%) | {imb['benign']} benign")

    # 3. Train Model using Canonical World Model Trainer
    log.info(f"🏁 Initiating {epochs}-Epoch World Model Training on {device.upper()} (Batch Size: {batch_size})")
    model, test_raw, history = train(
        dataset=dataset,
        checkpoint_dir=str(CHECKPOINTS_DIR),
        num_epochs=epochs,
        batch_size=batch_size,
        lr=lr,
        device_str=device,
        seed=42,
    )

    # 4. Save dedicated CTU checkpoint
    ctu_ckpt_path = CHECKPOINTS_DIR / "worldmodel_ctu_idseval.pt"
    torch.save(model.state_dict(), ctu_ckpt_path)
    log.info(f"💾 Saved dedicated model weights to: {ctu_ckpt_path}")

    # 5. Compute Full Evaluation Report on Held-Out Test Set
    log.info("📊 Computing comprehensive test evaluation metrics...")
    eval_report = full_evaluation_report(
        y_true_infil=test_raw["infil_targets"],
        y_pred_infil_prob=test_raw["infil_preds"],
        stage_true=test_raw["stage_targets"],
        stage_pred=test_raw["stage_preds"],
        model_name="World Model (CTU-IDSEVAL-6 / CTU-13)",
    )

    # 6. Save Report and Update Registry
    best_val_loss = min((h["val_loss_total"] for h in history if "val_loss_total" in h), default=0.0)
    best_f1 = max((h["val_infil_f1"] for h in history if "val_infil_f1" in h), default=0.0)

    report_data = {
        "timestamp": datetime.now().isoformat(),
        "dataset": "CTU-IDSEVAL-6 (CTU-13)",
        "source_path": str(data_path),
        "epochs": epochs,
        "best_val_loss": round(float(best_val_loss), 4),
        "best_val_f1": round(float(best_f1), 4),
        "test_metrics": eval_report,
        "checkpoint": str(ctu_ckpt_path),
        "history": history,
    }

    report_path = REPORTS_DIR / "ctu_training_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)
    log.info(f"💾 Saved full report to: {report_path}")

    if REGISTRY_PATH.exists():
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            reg = json.load(f)
    else:
        reg = {"version": "1.0", "trained_datasets": {}}

    ctu_key = "ctu_idseval_6_complete_benchmark"
    reg["trained_datasets"][ctu_key] = {
        "dataset_name": "CTU-IDSEVAL-6 (CTU-13)",
        "file_path": str(data_path),
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "checkpoint_path": str(ctu_ckpt_path.relative_to(REPO_ROOT)),
        "epochs": epochs,
        "best_val_loss": round(float(best_val_loss), 4),
        "best_val_f1": round(float(best_f1), 4),
        "test_f1": round(float(eval_report.get("f1", 0.0)), 4),
        "test_precision": round(float(eval_report.get("precision", 0.0)), 4),
        "test_recall": round(float(eval_report.get("recall", 0.0)), 4),
    }
    with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(reg, f, indent=2)
    log.info(f"💾 Updated {REGISTRY_PATH.name} with CTU-IDSEVAL-6 entry!")

    log.info("=" * 70)
    log.info(f"✅ CTU-IDSEVAL-6 WORLD MODEL TRAINING COMPLETE!")
    log.info(f"   Best Val Loss: {best_val_loss:.4f} | Best Infiltration F1: {best_f1:.3f}")
    log.info(f"   Checkpoint: {ctu_ckpt_path}")
    log.info("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train World Model on CTU-IDSEVAL-6")
    parser.add_argument("data_path", default=r"C:\Users\raova\OneDrive\Desktop\SIH TRAINING DATA\21027042", nargs="?", help="Path to CTU folder or zeek.zip")
    parser.add_argument("--epochs", type=int, default=25, help="Epoch count (default: 25)")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size (default: 32)")
    parser.add_argument("--lr", type=float, default=5e-4, help="Learning rate (default: 5e-4)")
    parser.add_argument("--samples-per-capture", type=int, default=12000, help="Max flows per capture")
    parser.add_argument("--device", default="auto", help="auto | cuda | cpu")
    args = parser.parse_args()

    train_ctu(
        data_path=args.data_path,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        samples_per_capture=args.samples_per_capture,
        device_str=args.device,
    )

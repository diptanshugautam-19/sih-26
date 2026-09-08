"""
scripts/train_unsw.py

End-to-end training and evaluation script for the Predictive Cyber Defence World Model
(GAT Spatial Encoder + Transformer Temporal Encoder + 3 Prediction Heads)
strictly on the official UNSW-NB15 dataset.

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
from src.data.unsw_adapter import prepare_unsw_nb15_dataset
from src.eval.metrics import full_evaluation_report

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

REGISTRY_PATH = REPO_ROOT / "TRAINING_REGISTRY.json"
CHECKPOINTS_DIR = REPO_ROOT / "models" / "checkpoints"
REPORTS_DIR = REPO_ROOT / "reports"


def train_unsw(
    data_path: str | Path | None = None,
    epochs: int = 30,
    batch_size: int = 32,
    lr: float = 3e-4,
    samples_per_class: int = 3500,
    benign_samples: int = 15000,
    device_str: str = "auto",
    patience: int = 10,
):
    CHECKPOINTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Device Setup
    if device_str == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    else:
        device = device_str

    log.info("=" * 70)
    log.info("🚀 PREDICTIVE CYBER DEFENCE WORLD MODEL — OFFICIAL UNSW-NB15 TRAINING")
    log.info("=" * 70)

    # 2. Locate Data
    if data_path is None:
        data_path = REPO_ROOT / "data" / "raw" / "unsw_nb15" / "UNSW_Flow.parquet"
    data_path = Path(data_path)
    if not data_path.exists():
        raise FileNotFoundError(f"Official dataset not found at: {data_path}")

    log.info(f"📂 Dataset Source: {data_path.name} ({data_path.stat().st_size / (1024*1024):.2f} MB)")

    # 3. Load & Build Graph Sequences
    t0_data = time.time()
    dataset = prepare_unsw_nb15_dataset(
        data_path,
        max_samples_per_class=samples_per_class,
        benign_sample_count=benign_samples,
    )
    imb = dataset.imbalance_report()
    log.info(f"📊 Dataset Sequences: {len(dataset):,} total | {imb['malicious']} attack ({imb['malicious_pct']:.1f}%) | {imb['benign']} benign")

    # 4. Train World Model using Canonical Trainer
    log.info(f"🏁 Initiating {epochs}-Epoch World Model Training on {device.upper()} (Batch Size: {batch_size}, Patience: {patience})")
    model, test_raw, history = train(
        dataset=dataset,
        checkpoint_dir=str(CHECKPOINTS_DIR),
        num_epochs=epochs,
        batch_size=batch_size,
        lr=lr,
        device_str=device,
        patience=patience,
        seed=42,
    )

    # 5. Full Evaluation Report
    log.info("\n" + "=" * 70)
    log.info("📈 COMPUTING EXHAUSTIVE BENCHMARK EVALUATION REPORT")
    log.info("=" * 70)
    eval_report = full_evaluation_report(
        y_true_infil=test_raw["infil_targets"],
        y_pred_infil_prob=test_raw["infil_preds"],
        stage_true=test_raw["stage_targets"],
        stage_pred=test_raw["stage_preds"],
        model_name="World Model (UNSW-NB15)",
    )

    inf_f1 = float(eval_report.get("f1", 0.0))
    inf_prec = float(eval_report.get("precision", 0.0))
    inf_rec = float(eval_report.get("recall", 0.0))
    inf_auc = float(eval_report.get("auroc", 0.0))
    if np.isnan(inf_auc):
        inf_auc = 0.0

    total_test = max(1, int(eval_report.get("tp", 0) + eval_report.get("tn", 0) + eval_report.get("fp", 0) + eval_report.get("fn", 0)))
    inf_acc = float(eval_report.get("tp", 0) + eval_report.get("tn", 0)) / total_test

    stage_dict = eval_report.get("per_stage_f1", {})
    stg_acc = float(stage_dict.get("accuracy", 0.0))
    stg_f1 = float(stage_dict.get("macro avg", {}).get("f1-score", 0.0))

    log.info(f"✅ Infiltration Accuracy : {inf_acc:.4f} ({inf_acc * 100:.2f}%)")
    log.info(f"✅ Infiltration Macro F1 : {inf_f1:.4f} ({inf_f1 * 100:.2f}%)")
    log.info(f"✅ Infiltration Precision: {inf_prec:.4f} | Recall: {inf_rec:.4f}")
    log.info(f"✅ Infiltration ROC-AUC  : {inf_auc:.4f}")
    log.info(f"🎯 ATT&CK Stage Accuracy : {stg_acc:.4f} ({stg_acc * 100:.2f}%)")
    log.info(f"🎯 ATT&CK Stage Macro F1 : {stg_f1:.4f} ({stg_f1 * 100:.2f}%)")

    # 6. Save Artifacts & Registry
    save_ckpt = CHECKPOINTS_DIR / "worldmodel_unsw_nb15.pt"
    torch.save(model.state_dict(), save_ckpt)
    log.info(f"💾 Dedicated Checkpoint saved: {save_ckpt.relative_to(REPO_ROOT)}")

    report_path = REPORTS_DIR / "unsw_nb15_worldmodel_evaluation_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "dataset": "UNSW-NB15",
            "epochs": epochs,
            "sequences": len(dataset),
            "device": device,
            "evaluation": eval_report,
            "training_history": history,
        }, f, indent=2)
    log.info(f"📄 Detailed Report saved: {report_path.relative_to(REPO_ROOT)}")

    # Update Registry
    if REGISTRY_PATH.exists():
        try:
            with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
                registry = json.load(f)
            registry.setdefault("trained_datasets", {})["unsw_nb15_world_model_benchmark"] = {
                "dataset_name": "UNSW-NB15 (Predictive Cyber Defence World Model)",
                "file_path": str(data_path),
                "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "checkpoint_path": str(save_ckpt.relative_to(REPO_ROOT)),
                "epochs": epochs,
                "sequences": len(dataset),
                "test_accuracy": float(inf_acc),
                "test_f1": float(inf_f1),
                "test_precision": float(inf_prec),
                "test_recall": float(inf_rec),
                "test_roc_auc": float(inf_auc),
                "stage_accuracy": float(stg_acc),
                "stage_f1": float(stg_f1),
            }
            with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
                json.dump(registry, f, indent=2)
            log.info("📋 TRAINING_REGISTRY.json updated successfully.")
        except Exception as e:
            log.warning(f"Could not update registry: {e}")

    log.info("\n🎉 UNSW-NB15 WORLD MODEL TRAINING PIPELINE COMPLETED SUCCESSFULLY!")


def main():
    parser = argparse.ArgumentParser(description="Train Cyber Defence World Model on UNSW-NB15.")
    parser.add_argument("--data-path", type=str, default=None, help="Path to UNSW_Flow.parquet")
    parser.add_argument("--epochs", type=int, default=30, help="Training epochs (default: 30)")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size (default: 32)")
    parser.add_argument("--lr", type=float, default=3e-4, help="Learning rate (default: 3e-4)")
    parser.add_argument("--device", type=str, default="auto", help="auto | cuda | cpu")
    parser.add_argument("--patience", type=int, default=10, help="Early stopping patience (default: 10)")
    args = parser.parse_args()

    train_unsw(
        data_path=args.data_path,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        device_str=args.device,
        patience=args.patience,
    )


if __name__ == "__main__":
    main()

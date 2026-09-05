"""
scripts/run_training.py

One-command training script for the Predictive Cyber Defence World Model.
Run this script — it handles every step automatically:
  1. Loads + cleans the CIC-IDS2018 / CTU-13 CSV
  2. Adds pseudo-MITRE labels
  3. Converts timestamp column to Unix float
  4. Builds the PyTorch dataset (windows + graphs)
  5. Trains the World Model with AdamW + cosine LR
  6. Saves best checkpoint to models/best_model.pt
  7. Trains the Logistic Regression baseline
  8. Prints the final comparison benchmark table

Usage:
    python scripts/run_training.py data/raw/your_file.csv
    python scripts/run_training.py data/raw/your_file.csv --epochs 30 --device cpu
"""

# Ensure project root is on sys.path regardless of how the script is invoked
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Force UTF-8 output on Windows (prevents cp1252 UnicodeEncodeError on emoji/arrows)
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import argparse
import logging
import sys
import time
from pathlib import Path
import pandas as pd
import numpy as np
import torch

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Train the Cyber Defence World Model end-to-end.")
    parser.add_argument("csv_path",       help="Path to CIC-IDS2018 or CTU-13 CSV file")
    parser.add_argument("--epochs",       type=int,   default=25,    help="Training epochs (default: 25)")
    parser.add_argument("--batch-size",   type=int,   default=8,     help="Batch size (default: 8)")
    parser.add_argument("--lr",           type=float, default=5e-4,  help="Learning rate (default: 5e-4)")
    parser.add_argument("--device",       default="auto",            help="auto | cpu | cuda (default: auto)")
    parser.add_argument("--checkpoint-dir", default="models",       help="Where to save .pt files")
    parser.add_argument("--seed",         type=int,   default=42)
    parser.add_argument("--max-rows",     type=int,   default=None,  help="Limit rows for quick smoke test")
    args = parser.parse_args()

    csv_path = Path(args.csv_path)
    if not csv_path.exists():
        log.error(f"File not found: {csv_path}")
        sys.exit(1)

    # ──────────────────────────────────────────────
    # STEP 1 — Load & clean
    # ──────────────────────────────────────────────
    log.info(f"📂 Loading {csv_path.name} ...")
    df = pd.read_csv(csv_path, low_memory=False, nrows=args.max_rows)
    log.info(f"   Loaded {len(df):,} rows × {len(df.columns)} columns")

    from src.data.clean_cicids import clean_dataframe
    df = clean_dataframe(df)
    log.info(f"   After cleaning: {len(df):,} rows")

    # ──────────────────────────────────────────────
    # STEP 2 — Convert timestamp to Unix float
    # ──────────────────────────────────────────────
    if "timestamp" in df.columns:
        if pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
            df["timestamp"] = df["timestamp"].astype(np.int64) / 1e9
        elif df["timestamp"].dtype == object:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df = df.dropna(subset=["timestamp"])
            df["timestamp"] = df["timestamp"].astype(np.int64) / 1e9
    else:
        log.error("No 'timestamp' column found. Aborting.")
        sys.exit(1)

    log.info(f"   Time range: {df['timestamp'].min():.1f} → {df['timestamp'].max():.1f} ({(df['timestamp'].max() - df['timestamp'].min()):.1f}s)")

    # ──────────────────────────────────────────────
    # STEP 3 — Add pseudo-MITRE labels
    # ──────────────────────────────────────────────
    log.info("🏷️  Annotating with pseudo-MITRE labels ...")
    from src.labels.pseudo_labeler import annotate_dataframe_with_pseudo_labels
    df = annotate_dataframe_with_pseudo_labels(df)
    mal_pct = (df["mitre_stage_id"] > 0).mean() * 100
    log.info(f"   Malicious traffic: {mal_pct:.1f}%")

    # ──────────────────────────────────────────────
    # STEP 4 — Build PyTorch dataset
    # ──────────────────────────────────────────────
    log.info("🔨 Building graph-sequence dataset (this may take 30–120 seconds) ...")
    t0 = time.time()
    from src.data.dataset import CyberDefenceDataset
    from src.data.windowing import WindowConfig

    cfg = WindowConfig(window_size=5.0, stride=2.5, seq_len=10, horizon_k=4)
    dataset = CyberDefenceDataset(df, cfg=cfg)
    elapsed = time.time() - t0

    report = dataset.imbalance_report()
    log.info(f"   Built {report['total_sequences']} sequences in {elapsed:.1f}s")
    log.info(f"   Malicious sequences: {report['malicious']} ({report['malicious_pct']:.1f}%)")

    if len(dataset) < 10:
        log.warning(
            f"Only {len(dataset)} sequences found. Your CSV may be too short (need ≥ 60s of traffic). "
            "Try --max-rows None and use a full day CSV."
        )

    # ──────────────────────────────────────────────
    # STEP 5 — Train World Model
    # ──────────────────────────────────────────────
    log.info("🧠 Starting World Model training ...")
    from src.training.train import train

    model, test_raw, history = train(
        dataset=dataset,
        checkpoint_dir=args.checkpoint_dir,
        num_epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        device_str=args.device,
        seed=args.seed,
    )

    # ──────────────────────────────────────────────
    # STEP 6 — Evaluate World Model
    # ──────────────────────────────────────────────
    log.info("📊 Computing World Model evaluation metrics ...")
    from src.eval.metrics import full_evaluation_report

    wm_report = full_evaluation_report(
        y_true_infil=test_raw["infil_targets"],
        y_pred_infil_prob=test_raw["infil_preds"],
        stage_true=test_raw["stage_targets"],
        stage_pred=test_raw["stage_preds"],
        model_name="World Model (GNN + Transformer)",
    )

    # ──────────────────────────────────────────────
    # STEP 7 — Train & Evaluate Logistic Baseline
    # ──────────────────────────────────────────────
    log.info("📉 Training Logistic Regression baseline ...")
    from src.models.baselines.logistic import PerFlowLogisticBaseline

    # Use same 70/15/15 split by index (deterministic)
    rng = np.random.default_rng(args.seed)
    idx = rng.permutation(len(df))
    n_train = int(0.7 * len(df))
    n_val   = int(0.15 * len(df))
    train_df = df.iloc[idx[:n_train]].copy()
    test_df  = df.iloc[idx[n_train + n_val:]].copy()

    lr_model = PerFlowLogisticBaseline(seed=args.seed)
    lr_model.fit(train_df)
    lr_report = lr_model.evaluate(test_df)

    # ──────────────────────────────────────────────
    # STEP 8 — Print Benchmark Table
    # ──────────────────────────────────────────────
    print("\n" + "="*70)
    print("  BENCHMARK RESULTS — World Model vs. Logistic Regression Baseline")
    print("="*70)
    print(f"{'Metric':<28} {'World Model':>18} {'LR Baseline':>16}")
    print("-"*70)

    metrics = ["f1", "precision", "recall", "fpr", "auroc", "brier_score", "ece"]
    labels  = ["F1 Score", "Precision", "Recall", "FPR (False Positive Rate)",
               "AUROC", "Brier Score (↓ better)", "ECE (↓ better)"]

    for m, label in zip(metrics, labels):
        wm_val = wm_report.get(m, float("nan"))
        lr_val = lr_report.get(m, float("nan"))
        wm_str = f"{wm_val:.4f}" if not (isinstance(wm_val, float) and wm_val != wm_val) else "N/A"
        lr_str = f"{lr_val:.4f}" if not (isinstance(lr_val, float) and lr_val != lr_val) else "N/A"
        print(f"  {label:<26} {wm_str:>18} {lr_str:>16}")

    print("-"*70)

    if "lead_time" in wm_report and wm_report["lead_time"].get("lead_time_seconds") is not None:
        lt = wm_report["lead_time"]["lead_time_seconds"]
        print(f"\n  ⏱️  Lead-Time (advance warning): {lt:.1f}s before attack onset")

    print(f"\n  📁 Best model saved: {Path(args.checkpoint_dir) / 'best_model.pt'}")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()

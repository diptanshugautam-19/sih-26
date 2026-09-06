"""
scripts/train_dataset_with_registry.py

Handles:
1. Strict checking against TRAINING_REGISTRY.json and DATASET_TRAINING_CHECKLIST.md using SHA-256 hash.
2. Skipping already trained datasets to prevent duplicate training.
3. End-to-end cleaning, windowing, and training of the Cyber Defence World Model.
4. Updating checkpoints and saving trained status.
"""

from __future__ import annotations
import os
import sys
import json
import time
import hashlib
import logging
from pathlib import Path
from datetime import datetime

# Set repo root
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# UTF-8 encoding support
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import numpy as np
import pandas as pd
import torch

from src.data.clean_cicids import clean_dataframe
from src.labels.pseudo_labeler import annotate_dataframe_with_pseudo_labels
from src.data.windowing import WindowConfig
from src.data.dataset import CyberDefenceDataset
from src.training.train import train

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

REGISTRY_PATH = REPO_ROOT / "TRAINING_REGISTRY.json"
CHECKLIST_PATH = REPO_ROOT / "DATASET_TRAINING_CHECKLIST.md"
CHECKPOINTS_DIR = REPO_ROOT / "models" / "checkpoints"


def compute_sha256(file_path: Path) -> str:
    """Computes SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def load_registry() -> dict:
    if REGISTRY_PATH.exists():
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"version": "1.0", "trained_datasets": {}}


def save_registry(reg: dict):
    with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(reg, f, indent=2)


def mark_checklist_item(filename: str, checkpoint_tag: str, trained_date: str):
    if not CHECKLIST_PATH.exists():
        return
    text = CHECKLIST_PATH.read_text(encoding="utf-8")
    lines = text.splitlines()
    new_lines = []
    for line in lines:
        if filename in line and "[ ] PENDING" in line:
            parts = [p.strip() for p in line.split("|") if p]
            if len(parts) >= 6:
                line = f"| [x] COMPLETED | `{filename}` | {parts[2]} | {parts[3]} | `{checkpoint_tag}` | {trained_date} |"
        new_lines.append(line)
    CHECKLIST_PATH.write_text("\n".join(new_lines), encoding="utf-8")


def train_single_dataset(csv_path: Path, epochs: int = 10, batch_size: int = 32, lr: float = 5e-4):
    CHECKPOINTS_DIR.mkdir(parents=True, exist_ok=True)
    reg = load_registry()

    if torch.cuda.is_available():
        gpu_name = torch.cuda.get_device_name(0)
        gpu_mem_gb = torch.cuda.get_device_properties(0).total_memory / (1024 ** 3)
        log.info(f"GPU Acceleration ACTIVE: {gpu_name} ({gpu_mem_gb:.2f} GB VRAM) | Batch Size: {batch_size}")
    else:
        log.warning(f"CUDA NOT available. Training on CPU with Batch Size: {batch_size}")

    log.info(f"Checking dataset: {csv_path.name} ...")
    file_sha256 = compute_sha256(csv_path)
    log.info(f"SHA-256: {file_sha256}")

    if file_sha256 in reg["trained_datasets"]:
        entry = reg["trained_datasets"][file_sha256]
        log.warning(f"⏩ ALREADY TRAINED: {csv_path.name} was trained on {entry.get('trained_at')}.")
        log.warning(f"Checkpoint located at: {entry.get('checkpoint_path')}. Skipping duplicate training.")
        return

    checkpoint_filename = f"worldmodel_{csv_path.stem}.pt"
    checkpoint_path = CHECKPOINTS_DIR / checkpoint_filename

    # Step 1: Load and clean
    log.info(f"Loading raw telemetry from: {csv_path.name}")
    try:
        df = pd.read_csv(csv_path, low_memory=False)
    except UnicodeDecodeError:
        log.warning(f"UTF-8 decode failed for {csv_path.name}, falling back to latin-1 encoding.")
        df = pd.read_csv(csv_path, low_memory=False, encoding="latin-1")
    log.info(f"Loaded {len(df):,} raw flows.")

    df = clean_dataframe(df)
    log.info(f"Cleaned flows: {len(df):,} remaining.")

    # Parse timestamps with intra-minute sequence distribution
    if "timestamp" in df.columns:
        if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df = df.dropna(subset=["timestamp"])
        
        # In CIC-IDS2018 CSV exports, timestamps are given at minute granularity.
        # Spread flows proportionally across the 60-second span to preserve chronological
        # intra-minute flow order and construct continuous 5-second temporal snapshot sequences.
        minute_counts = df.groupby("timestamp").cumcount()
        minute_totals = df.groupby("timestamp")["timestamp"].transform("count")
        ts_base = df["timestamp"].astype(np.int64) / 1e9
        df["timestamp"] = ts_base + (minute_counts / minute_totals) * 59.9

    # Step 2: Annotate labels
    log.info("Annotating pseudo-MITRE stages...")
    df = annotate_dataframe_with_pseudo_labels(df)
    mal_pct = (df["mitre_stage_id"] > 0).mean() * 100
    log.info(f"Attack flow percentage: {mal_pct:.2f}%")

    # Step 3: Build graph dataset
    log.info("Constructing dynamic graph sequence windows...")
    win_cfg = WindowConfig(window_size=5.0, stride=2.5, seq_len=10, horizon_k=4)
    dataset = CyberDefenceDataset(df, cfg=win_cfg)
    log.info(f"Total graph sequences constructed: {len(dataset):,}")

    if len(dataset) < 4:
        log.error("Dataset has too few temporal sequences to train effectively.")
        return

    # Step 4: Run training using repository's standard train function
    model, test_raw, history = train(
        dataset=dataset,
        checkpoint_dir=str(CHECKPOINTS_DIR),
        num_epochs=epochs,
        batch_size=batch_size,
        lr=lr,
        device_str="auto"
    )

    # Save dedicated model checkpoint tagged for this dataset
    torch.save(model.state_dict(), checkpoint_path)
    log.info(f"Model saved to: {checkpoint_path}")

    trained_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Step 5: Update registry and checklist
    reg["trained_datasets"][file_sha256] = {
        "filename": csv_path.name,
        "file_size_bytes": csv_path.stat().st_size,
        "sha256": file_sha256,
        "trained_at": trained_date,
        "checkpoint_path": str(checkpoint_path.relative_to(REPO_ROOT)),
        "epochs": epochs,
        "batch_size": batch_size,
        "num_sequences": len(dataset),
        "val_loss": float(history["val_loss"][-1]) if "val_loss" in history and history["val_loss"] else None
    }
    save_registry(reg)
    mark_checklist_item(csv_path.name, checkpoint_filename, trained_date)
    log.info(f"Successfully recorded {csv_path.name} in registry & checklist!")


def train_all_in_folder(folder_path: Path, epochs: int = 5, batch_size: int = 32):
    csv_files = sorted(list(folder_path.glob("*.csv")))
    log.info(f"Found {len(csv_files)} CSV datasets in {folder_path}")
    for idx, csv_file in enumerate(csv_files, 1):
        log.info(f"\n[{idx}/{len(csv_files)}] Processing {csv_file.name} ...")
        try:
            train_single_dataset(csv_file, epochs=epochs, batch_size=batch_size)
        except Exception as e:
            log.error(f"Error training {csv_file.name}: {e}", exc_info=True)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str, help="Path to traffic CSV or directory of CSVs")
    parser.add_argument("--epochs", type=int, default=5, help="Epochs to train per dataset")
    parser.add_argument("--batch-size", type=int, default=None, help="Batch size (default: 32 on GPU, 64 with --max-vram, 8 on CPU)")
    parser.add_argument("--max-vram", action="store_true", help="Maximize GPU VRAM utilization (uses batch size 64-128)")
    args = parser.parse_args()
    
    # Auto-tune batch size for GPU/VRAM
    if args.batch_size is not None:
        effective_batch_size = args.batch_size
    elif args.max_vram:
        effective_batch_size = 64 if torch.cuda.is_available() else 8
    else:
        effective_batch_size = 32 if torch.cuda.is_available() else 8

    target_path = Path(args.path)
    if target_path.is_dir():
        train_all_in_folder(target_path, epochs=args.epochs, batch_size=effective_batch_size)
    else:
        train_single_dataset(target_path, epochs=args.epochs, batch_size=effective_batch_size)

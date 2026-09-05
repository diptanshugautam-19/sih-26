"""
scripts/download_real_cicids.py

Downloads the official real-world CSE-CIC-IDS2018 Infiltration dataset
(Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv ~ 199 MB)
from the public repository into data/raw/.
"""

import os
import sys
import time
import urllib.request
from pathlib import Path

DATA_URL = "https://huggingface.co/datasets/c01dsnap/CIC-IDS2018/resolve/main/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv"
OUT_DIR = Path("data/raw")
OUT_FILE = OUT_DIR / "cic_ids_2018_infiltration.csv"


def download_with_progress(url: str, out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists() and out_path.stat().st_size > 10_000_000:
        print(f"[INFO] File already exists: {out_path} ({out_path.stat().st_size / 1024 / 1024:.1f} MB)")
        return

    print("[INFO] Downloading real CSE-CIC-IDS2018 Infiltration dataset (~200 MB)...")
    print(f"[INFO] URL: {url}")
    print(f"[INFO] Target: {out_path}")

    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    t0 = time.time()
    with urllib.request.urlopen(req) as resp, open(out_path, "wb") as out:
        total_size = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        chunk_size = 1024 * 1024  # 1 MB

        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            out.write(chunk)
            downloaded += len(chunk)
            mb_done = downloaded / 1024 / 1024
            mb_total = total_size / 1024 / 1024
            pct = (downloaded / total_size * 100) if total_size else 0
            elapsed = time.time() - t0
            speed = mb_done / max(elapsed, 0.1)
            sys.stdout.write(f"\r  Progress: {mb_done:.1f} / {mb_total:.1f} MB ({pct:.1f}%) -- {speed:.2f} MB/s")
            sys.stdout.flush()

    print(f"\n[OK] Successfully downloaded real dataset to {out_path}!")


if __name__ == "__main__":
    download_with_progress(DATA_URL, OUT_FILE)

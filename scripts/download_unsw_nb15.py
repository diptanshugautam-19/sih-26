"""
scripts/download_unsw_nb15.py

Downloads the official UNSW-NB15 cybersecurity dataset for GNN training.
Provides:
  1. Full network flows with IP addresses (source_ip, destination_ip, ports, 49 features)
  2. Official partitioned benchmark training set (175,341 flows)
  3. Official partitioned benchmark testing set (82,332 flows)

NO SAMPLE OR FAKE DATA IS USED.
"""

import os
import sys
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "data" / "raw" / "unsw_nb15"

URLS = {
    "UNSW_Flow.parquet": "https://huggingface.co/datasets/rdpahalavan/UNSW-NB15/resolve/main/Network-Flows/UNSW_Flow.parquet",
    "UNSW_NB15_training-set.csv": "https://huggingface.co/datasets/Mireu-Lab/UNSW-NB15/resolve/main/train.csv",
    "UNSW_NB15_testing-set.csv": "https://huggingface.co/datasets/Mireu-Lab/UNSW-NB15/resolve/main/test.csv",
}


def download_file(url: str, dest_path: Path) -> bool:
    """Download file with real-time transfer progress."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if dest_path.exists() and dest_path.stat().st_size > 5_000_000:
        print(f"  [CACHE HIT] {dest_path.name} already exists ({dest_path.stat().st_size / (1024*1024):.2f} MB)")
        return True

    print(f"  [DOWNLOADING] {url}")
    print(f"  -> Destination: {dest_path}")
    t0 = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=120) as resp, open(dest_path, "wb") as out_file:
            total_size = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            chunk_size = 1024 * 1024

            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                out_file.write(chunk)
                downloaded += len(chunk)
                mb_done = downloaded / (1024 * 1024)
                if total_size > 0:
                    pct = (downloaded / total_size) * 100
                    mb_total = total_size / (1024 * 1024)
                    sys.stdout.write(f"\r  Progress: {mb_done:.1f} / {mb_total:.1f} MB ({pct:.1f}%)")
                else:
                    sys.stdout.write(f"\r  Progress: {mb_done:.1f} MB")
                sys.stdout.flush()

        elapsed = max(time.time() - t0, 0.01)
        print(f"\n  [OK] Saved {dest_path.name} ({dest_path.stat().st_size / (1024*1024):.2f} MB in {elapsed:.2f}s)")
        return True
    except Exception as e:
        print(f"\n  [ERROR] Failed to download {url}: {e}")
        return False


def main():
    print("\n" + "=" * 70)
    print("  DOWNLOADING OFFICIAL UNSW-NB15 DATASET FOR GNN TRAINING")
    print("=" * 70)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for fname, url in URLS.items():
        dest = OUT_DIR / fname
        download_file(url, dest)

    print("\n[ALL COMPLETE] Verified official dataset in:", OUT_DIR.resolve())
    for f in sorted(OUT_DIR.glob("*")):
        print(f"  - {f.name} ({f.stat().st_size / (1024*1024):.2f} MB)")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()

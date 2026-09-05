"""
scripts/generate_1gb_data.py

Generates ~1 GB of structurally realistic synthetic CIC-IDS2018-format CSV.
Produces 5+ phases of network traffic matching real attack progressions:
  - Phase 0 (0-300s):   Benign baseline  (60%)
  - Phase 1 (300-350s): Reconnaissance   (port scan)
  - Phase 2 (350-400s): Initial Access   (brute-force SSH)
  - Phase 3 (400-450s): Lateral Movement (SMB/RDP spread)
  - Phase 4 (450-500s): C2 Beaconing     (periodic callbacks)
  - Phase 5 (500-540s): Exfiltration     (large outbound bursts)

Output: data/raw/synthetic_1gb.csv   (~1 GB)
"""

from __future__ import annotations
import os
import sys
import time
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Tuple

SEED     = 42
OUT_PATH = Path("data/raw/synthetic_1gb.csv")
TARGET_GB = 1.0

rng = np.random.default_rng(SEED)

# ── IP pools ──────────────────────────────────────────────────────────────────
INTERNAL_IPS  = [f"192.168.{s}.{h}" for s in range(1, 5) for h in range(10, 30)]
EXTERNAL_IPS  = ["8.8.8.8", "1.1.1.1", "203.0.113.5", "198.51.100.12", "172.16.0.1"]
ATTACKER_IPS  = ["45.33.32.156", "198.20.70.114", "104.21.0.99"]
C2_IPS        = ["185.220.101.34", "91.108.56.190", "45.147.228.198"]

COMMON_PORTS  = [80, 443, 53, 22, 25, 110, 143, 8080, 3306, 5432]
SCAN_PORTS    = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443, 1433, 3306]
C2_PORTS      = [443, 8080, 4444, 1234, 31337]

# Realistic CIC-IDS2018 column names so clean_cicids.py recognises them
COLUMNS = [
    "Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol",
    "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Flow Byts/s", "Flow Pkts/s", "SYN Flag Cnt", "ACK Flag Cnt",
    "FIN Flag Cnt", "RST Flag Cnt", "Flow IAT Mean", "Flow IAT Std",
    "Label",
]


def _ts(t_start: float, n: int, span: float) -> np.ndarray:
    """Unix timestamps in [t_start, t_start+span), as datetime strings."""
    return pd.to_datetime(
        t_start + rng.uniform(0, span, n), unit="s"
    ).strftime("%Y-%m-%d %H:%M:%S.%f")


def make_benign(n: int, t_start: float) -> pd.DataFrame:
    src = rng.choice(INTERNAL_IPS, n)
    dst = rng.choice(INTERNAL_IPS + EXTERNAL_IPS, n)
    return pd.DataFrame({
        "Timestamp":       _ts(t_start, n, 300.0),
        "Src IP":          src,
        "Dst IP":          dst,
        "Src Port":        rng.integers(1024, 65535, n),
        "Dst Port":        rng.choice(COMMON_PORTS, n),
        "Protocol":        rng.choice([6, 17], n),
        "Tot Fwd Pkts":    rng.integers(1, 80, n),
        "Tot Bwd Pkts":    rng.integers(1, 60, n),
        "TotLen Fwd Pkts": rng.integers(64, 65535, n),
        "TotLen Bwd Pkts": rng.integers(64, 32768, n),
        "Flow Byts/s":     rng.uniform(100, 80_000, n),
        "Flow Pkts/s":     rng.uniform(1, 300, n),
        "SYN Flag Cnt":    rng.integers(0, 2, n),
        "ACK Flag Cnt":    rng.integers(0, 8, n),
        "FIN Flag Cnt":    rng.integers(0, 2, n),
        "RST Flag Cnt":    rng.integers(0, 1, n),
        "Flow IAT Mean":   rng.uniform(0.005, 1.0, n),
        "Flow IAT Std":    rng.uniform(0, 0.5, n),
        "Label":           "Benign",
    })


def make_recon(n: int, t_start: float) -> pd.DataFrame:
    """Port scan: many ports, low bytes, many RST/SYN, fast IAT."""
    attacker = rng.choice(ATTACKER_IPS, n)
    victim   = rng.choice(INTERNAL_IPS, n)
    return pd.DataFrame({
        "Timestamp":       _ts(t_start, n, 50.0),
        "Src IP":          attacker,
        "Dst IP":          victim,
        "Src Port":        rng.integers(1024, 65535, n),
        "Dst Port":        rng.choice(SCAN_PORTS + list(range(1, 1024)), n),
        "Protocol":        6,
        "Tot Fwd Pkts":    rng.integers(1, 3, n),   # minimal probes
        "Tot Bwd Pkts":    rng.integers(0, 1, n),
        "TotLen Fwd Pkts": rng.integers(40, 100, n),
        "TotLen Bwd Pkts": rng.integers(0, 60, n),
        "Flow Byts/s":     rng.uniform(200, 5_000, n),
        "Flow Pkts/s":     rng.uniform(500, 5_000, n),
        "SYN Flag Cnt":    rng.integers(1, 5, n),
        "ACK Flag Cnt":    rng.integers(0, 1, n),
        "FIN Flag Cnt":    rng.integers(0, 1, n),
        "RST Flag Cnt":    rng.integers(1, 5, n),
        "Flow IAT Mean":   rng.uniform(0.00005, 0.005, n),
        "Flow IAT Std":    rng.uniform(0, 0.001, n),
        "Label":           "PortScan",
    })


def make_brute_force(n: int, t_start: float) -> pd.DataFrame:
    """SSH brute force: port 22, many SYN-ACK retries."""
    attacker = rng.choice(ATTACKER_IPS, n)
    victim   = rng.choice(INTERNAL_IPS[:5], n)
    return pd.DataFrame({
        "Timestamp":       _ts(t_start, n, 50.0),
        "Src IP":          attacker,
        "Dst IP":          victim,
        "Src Port":        rng.integers(1024, 65535, n),
        "Dst Port":        22,
        "Protocol":        6,
        "Tot Fwd Pkts":    rng.integers(5, 30, n),
        "Tot Bwd Pkts":    rng.integers(3, 20, n),
        "TotLen Fwd Pkts": rng.integers(200, 1500, n),
        "TotLen Bwd Pkts": rng.integers(100, 800, n),
        "Flow Byts/s":     rng.uniform(1_000, 20_000, n),
        "Flow Pkts/s":     rng.uniform(20, 200, n),
        "SYN Flag Cnt":    rng.integers(3, 15, n),
        "ACK Flag Cnt":    rng.integers(2, 10, n),
        "FIN Flag Cnt":    rng.integers(0, 2, n),
        "RST Flag Cnt":    rng.integers(1, 6, n),
        "Flow IAT Mean":   rng.uniform(0.01, 0.2, n),
        "Flow IAT Std":    rng.uniform(0, 0.1, n),
        "Label":           "Brute Force -Web",
    })


def make_lateral_movement(n: int, t_start: float) -> pd.DataFrame:
    """Internal east-west SMB/RDP traffic between compromised hosts."""
    src = rng.choice(INTERNAL_IPS[:5], n)   # compromised hosts
    dst = rng.choice(INTERNAL_IPS[5:], n)   # new victims
    return pd.DataFrame({
        "Timestamp":       _ts(t_start, n, 50.0),
        "Src IP":          src,
        "Dst IP":          dst,
        "Src Port":        rng.integers(1024, 65535, n),
        "Dst Port":        rng.choice([445, 3389, 135, 139], n),
        "Protocol":        6,
        "Tot Fwd Pkts":    rng.integers(20, 200, n),
        "Tot Bwd Pkts":    rng.integers(10, 100, n),
        "TotLen Fwd Pkts": rng.integers(500, 50_000, n),
        "TotLen Bwd Pkts": rng.integers(200, 20_000, n),
        "Flow Byts/s":     rng.uniform(5_000, 150_000, n),
        "Flow Pkts/s":     rng.uniform(50, 800, n),
        "SYN Flag Cnt":    rng.integers(1, 4, n),
        "ACK Flag Cnt":    rng.integers(5, 30, n),
        "FIN Flag Cnt":    rng.integers(0, 3, n),
        "RST Flag Cnt":    rng.integers(0, 2, n),
        "Flow IAT Mean":   rng.uniform(0.001, 0.05, n),
        "Flow IAT Std":    rng.uniform(0, 0.02, n),
        "Label":           "Infilteration",
    })


def make_c2_beaconing(n: int, t_start: float) -> pd.DataFrame:
    """C2 beaconing: periodic, regular IAT, HTTPS-like port, small payloads."""
    bot = rng.choice(INTERNAL_IPS[:8], n)
    c2  = rng.choice(C2_IPS, n)
    # Periodic beaconing — very regular IAT
    regular_iat = rng.uniform(28, 32, n)     # ~30s beacon interval
    return pd.DataFrame({
        "Timestamp":       _ts(t_start, n, 50.0),
        "Src IP":          bot,
        "Dst IP":          c2,
        "Src Port":        rng.integers(1024, 65535, n),
        "Dst Port":        rng.choice(C2_PORTS, n),
        "Protocol":        6,
        "Tot Fwd Pkts":    rng.integers(2, 8, n),    # small periodic
        "Tot Bwd Pkts":    rng.integers(1, 5, n),
        "TotLen Fwd Pkts": rng.integers(100, 500, n),
        "TotLen Bwd Pkts": rng.integers(50, 300, n),
        "Flow Byts/s":     rng.uniform(50, 2_000, n),
        "Flow Pkts/s":     rng.uniform(0.03, 0.1, n),  # low rate = periodic
        "SYN Flag Cnt":    rng.integers(1, 2, n),
        "ACK Flag Cnt":    rng.integers(1, 4, n),
        "FIN Flag Cnt":    rng.integers(1, 2, n),
        "RST Flag Cnt":    rng.integers(0, 1, n),
        "Flow IAT Mean":   regular_iat,
        "Flow IAT Std":    rng.uniform(0, 0.5, n),  # very regular
        "Label":           "Bot",
    })


def make_exfil(n: int, t_start: float) -> pd.DataFrame:
    """Exfiltration: large outbound to external, asymmetric forward bytes."""
    src = rng.choice(INTERNAL_IPS[:5], n)
    dst = rng.choice(C2_IPS + EXTERNAL_IPS, n)
    return pd.DataFrame({
        "Timestamp":       _ts(t_start, n, 40.0),
        "Src IP":          src,
        "Dst IP":          dst,
        "Src Port":        rng.integers(1024, 65535, n),
        "Dst Port":        rng.choice([443, 80, 21, 22], n),
        "Protocol":        6,
        "Tot Fwd Pkts":    rng.integers(200, 2000, n),  # heavy upload
        "Tot Bwd Pkts":    rng.integers(2, 10, n),       # low ack-only return
        "TotLen Fwd Pkts": rng.integers(100_000, 10_000_000, n),
        "TotLen Bwd Pkts": rng.integers(100, 5_000, n),
        "Flow Byts/s":     rng.uniform(500_000, 10_000_000, n),
        "Flow Pkts/s":     rng.uniform(200, 2_000, n),
        "SYN Flag Cnt":    rng.integers(1, 2, n),
        "ACK Flag Cnt":    rng.integers(50, 500, n),
        "FIN Flag Cnt":    rng.integers(1, 2, n),
        "RST Flag Cnt":    rng.integers(0, 1, n),
        "Flow IAT Mean":   rng.uniform(0.0001, 0.01, n),
        "Flow IAT Std":    rng.uniform(0, 0.005, n),
        "Label":           "DoS attacks-Hulk",
    })


def generate(target_gb: float = 1.0) -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    target_bytes = int(target_gb * 1024**3)

    # Phase proportions: 60% benign, 40% attack split across 5 stages
    # We'll write in chunks and track file size

    CHUNK = 100_000   # rows per chunk
    CHUNK_TYPES = {
        "benign":   (0.60, make_benign),
        "recon":    (0.08, make_recon),
        "bruteforce":(0.08, make_brute_force),
        "lateral":  (0.08, make_lateral_movement),
        "c2":       (0.08, make_c2_beaconing),
        "exfil":    (0.08, make_exfil),
    }

    # Phase start times (Unix)
    T_BASE = 1_700_000_000.0
    PHASE_T = {
        "benign":    T_BASE,
        "recon":     T_BASE + 300,
        "bruteforce":T_BASE + 350,
        "lateral":   T_BASE + 400,
        "c2":        T_BASE + 450,
        "exfil":     T_BASE + 500,
    }

    phases = list(CHUNK_TYPES.keys())
    weights = np.array([CHUNK_TYPES[p][0] for p in phases])
    weights /= weights.sum()

    first_write = True
    bytes_written = 0
    total_rows = 0
    t0 = time.time()

    print(f"[*] Generating ~{target_gb:.1f} GB of synthetic traffic data ...")
    print(f"    Output: {OUT_PATH}")

    while bytes_written < target_bytes:
        # Pick a phase for this chunk
        phase = rng.choice(phases, p=weights)
        fn    = CHUNK_TYPES[phase][1]
        t_s   = PHASE_T[phase]

        chunk_df = fn(CHUNK, t_s)

        if first_write:
            chunk_df.to_csv(OUT_PATH, index=False, mode="w")
            first_write = False
        else:
            chunk_df.to_csv(OUT_PATH, index=False, mode="a", header=False)

        bytes_written = OUT_PATH.stat().st_size
        total_rows   += len(chunk_df)
        pct = bytes_written / target_bytes * 100

        elapsed = time.time() - t0
        rate    = bytes_written / 1024**2 / max(elapsed, 0.1)  # MB/s

        print(
            f"\r   {pct:5.1f}%  |  {bytes_written/1024**2:7.1f} MB  |  "
            f"{total_rows:>10,} rows  |  {rate:.1f} MB/s",
            end="", flush=True
        )

    elapsed = time.time() - t0
    size_mb = OUT_PATH.stat().st_size / 1024**2
    print(f"\n\n[DONE] {size_mb:.1f} MB | {total_rows:,} rows | {elapsed:.1f}s")
    print(f"\nNow run:")
    print(f"  python scripts/run_training.py {OUT_PATH} --epochs 25")


if __name__ == "__main__":
    generate(TARGET_GB)

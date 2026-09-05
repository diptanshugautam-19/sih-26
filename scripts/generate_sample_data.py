"""
scripts/generate_sample_data.py

Generates a synthetic but structurally realistic CSV for smoke-testing
the training pipeline without needing to download CIC-IDS2018.

Produces ~5 minutes of traffic with benign + simulated attack phases.
Output: data/raw/synthetic_test.csv
"""

import os
import numpy as np
import pandas as pd
from pathlib import Path

N_BENIGN  = 8_000
N_ATTACK  = 2_000
SEED      = 42
OUT_PATH  = Path("data/raw/synthetic_test.csv")

rng = np.random.default_rng(SEED)

def make_benign(n):
    t_start = 1_700_000_000.0
    return pd.DataFrame({
        "Timestamp":    pd.to_datetime(t_start + rng.uniform(0, 240, n), unit="s"),
        "Src IP":       rng.choice(["192.168.1.10", "192.168.1.11", "192.168.1.12", "10.0.0.5"], n),
        "Dst IP":       rng.choice(["192.168.1.1", "8.8.8.8", "1.1.1.1"], n),
        "Src Port":     rng.integers(1024, 65535, n),
        "Dst Port":     rng.choice([80, 443, 53, 22], n),
        "Protocol":     rng.choice([6, 17], n),
        "Tot Fwd Pkts": rng.integers(1, 50, n),
        "Tot Bwd Pkts": rng.integers(1, 30, n),
        "TotLen Fwd Pkts": rng.integers(64, 65535, n),
        "TotLen Bwd Pkts": rng.integers(64, 32768, n),
        "Flow Byts/s":  rng.uniform(100, 50000, n),
        "Flow Pkts/s":  rng.uniform(1, 200, n),
        "SYN Flag Cnt": rng.integers(0, 2, n),
        "ACK Flag Cnt": rng.integers(0, 5, n),
        "FIN Flag Cnt": rng.integers(0, 2, n),
        "RST Flag Cnt": rng.integers(0, 1, n),
        "Flow IAT Mean": rng.uniform(0.001, 0.5, n),
        "Flow IAT Std":  rng.uniform(0, 0.2, n),
        "Label": "Benign",
    })

def make_attack(n):
    t_start = 1_700_000_240.0  # starts after 4 minutes (240s)
    return pd.DataFrame({
        "Timestamp":    pd.to_datetime(t_start + rng.uniform(0, 60, n), unit="s"),
        "Src IP":       rng.choice(["10.0.0.99"], n),  # single attacker
        "Dst IP":       rng.choice(["192.168.1.10", "192.168.1.11", "192.168.1.12"], n),
        "Src Port":     rng.integers(1024, 65535, n),
        "Dst Port":     rng.choice([22, 445, 3389, 80, 443, 8080], n),
        "Protocol":     6,  # TCP
        "Tot Fwd Pkts": rng.integers(50, 500, n),   # high packet count
        "Tot Bwd Pkts": rng.integers(0, 5, n),       # low response = scan
        "TotLen Fwd Pkts": rng.integers(40, 200, n), # small payloads = scan
        "TotLen Bwd Pkts": rng.integers(0, 100, n),
        "Flow Byts/s":  rng.uniform(50000, 500000, n),
        "Flow Pkts/s":  rng.uniform(200, 2000, n),
        "SYN Flag Cnt": rng.integers(5, 50, n),       # many SYNs
        "ACK Flag Cnt": rng.integers(0, 2, n),
        "FIN Flag Cnt": rng.integers(0, 1, n),
        "RST Flag Cnt": rng.integers(2, 10, n),       # many RSTs (port scan)
        "Flow IAT Mean": rng.uniform(0.0001, 0.01, n), # fast inter-arrival
        "Flow IAT Std":  rng.uniform(0, 0.005, n),
        "Label": "PortScan",
    })

if __name__ == "__main__":
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df = pd.concat([make_benign(N_BENIGN), make_attack(N_ATTACK)], ignore_index=True)
    df = df.sort_values("Timestamp").reset_index(drop=True)
    df.to_csv(OUT_PATH, index=False)
    print(f"[OK] Generated {len(df):,} rows -> {OUT_PATH}")
    print(f"   Benign: {N_BENIGN}, Attack: {N_ATTACK}")
    print(f"\nNow run:\n  python scripts/run_training.py data/raw/synthetic_test.csv --epochs 10 --max-rows 5000")

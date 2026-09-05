"""
src/data/dataset.py

PyTorch Dataset class that converts pre-built graph sequences (from graph_builder +
windowing) into DataLoader-ready batches for training the CyberDefenceWorldModel.

Responsible for:
- Holding a list of (graph_sequence, labels) samples
- Computing graded infiltration targets: y_t = exp(-(t_attack - t) / tau)
- Computing MITRE stage labels per sequence
- Splitting into train / val / test with reproducible seeds
- Reporting class imbalance for focal loss configuration
"""

from __future__ import annotations
import random
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict
import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler

from src.data.graph_builder import (
    PersistentNodeRegistry,
    NetworkGraphSnapshot,
    build_graph_for_window,
)
from src.data.windowing import (
    WindowConfig,
    make_input_windows,
    assign_rows_to_windows,
    build_sequences,
    make_target_windows,
)
from src.labels.pseudo_labeler import infer_pseudo_mitre_stage


TAU_DECAY = 10.0  # Seconds. Controls how sharply y_t decays away from attack onset.


def _graded_infiltration_target(
    t_now: float,
    t_attack: Optional[float],
) -> float:
    """
    Exponential anticipation target:
        y_t = exp(-(t_attack - t_now) / tau)  if t_attack is in the future
        y_t = 1.0                              if t_attack is now or past
        y_t = 0.0                              if no attack annotated

    This forces the model to predict rising probability as the attack approaches,
    rather than snapping from 0 to 1 at the moment of compromise.
    """
    if t_attack is None:
        return 0.0
    delta = t_attack - t_now
    if delta <= 0.0:
        return 1.0
    return float(np.exp(-delta / TAU_DECAY))


@dataclass
class SequenceSample:
    graph_sequence: List[NetworkGraphSnapshot]
    infiltration_target: float         # Graded [0.0 .. 1.0]
    mitre_stage_id: int                # 0-6
    mitre_confidence: float            # pseudo-label confidence
    grounded_targets: torch.Tensor     # [horizon_k, 3] — future port_entropy, syn_ratio, log_bytes
    is_malicious: bool


class CyberDefenceDataset(Dataset):
    """
    Converts a flat timestamped DataFrame into (graph_sequence, targets) pairs
    ready for the CyberDefenceWorldModel training loop.
    """

    def __init__(
        self,
        df: pd.DataFrame,
        cfg: WindowConfig = WindowConfig(),
        min_packets_per_window: int = 2,
    ):
        """
        Args:
            df: Cleaned, timestamped DataFrame with columns:
                  timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                  payload_size, flag_syn, flag_ack, flag_rst, flag_fin,
                  ttl, tcp_window, is_retransmission,
                  [optional] label, mitre_stage_id, mitre_stage_name, mitre_confidence
            cfg: WindowConfig (window_size, stride, seq_len, horizon_k)
            min_packets_per_window: Windows with fewer rows are skipped.
        """
        super().__init__()
        self.cfg = cfg
        self._registry = PersistentNodeRegistry()
        self.samples: List[SequenceSample] = []

        self._build(df, min_packets_per_window)

    # ------------------------------------------------------------------
    def _build(self, df: pd.DataFrame, min_pkts: int) -> None:
        if "timestamp" not in df.columns:
            raise ValueError("DataFrame must have a 'timestamp' column (Unix float).")

        df = df.copy()
        if pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
            df["timestamp"] = df["timestamp"].astype(np.int64) / 1e9
        elif not np.issubdtype(df["timestamp"].dtype, np.number):
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce").astype(np.int64) / 1e9

        df = df.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)
        t_min = float(df["timestamp"].min())
        t_max = float(df["timestamp"].max())

        if t_max - t_min < self.cfg.window_size:
            raise ValueError(
                f"Data span ({t_max - t_min:.1f}s) shorter than window_size ({self.cfg.window_size}s)."
            )

        # 1. Build overlapping input-window grid
        input_windows = make_input_windows(t_min, t_max, self.cfg)
        n_windows = len(input_windows)

        # 2. Vectorized window assignment — stamp each row with its window_id
        #    floor((timestamp - t_min) / stride) gives the primary window index.
        stride = self.cfg.stride
        ts_arr = df["timestamp"].values
        win_ids_arr = np.floor((ts_arr - t_min) / stride).astype(np.int64)
        win_ids_arr = np.clip(win_ids_arr, 0, n_windows - 1)
        df = df.copy()
        df["_win_id"] = win_ids_arr

        # 3. Pre-group rows by window id for O(1) lookups
        win_groups: Dict[int, pd.DataFrame] = {}
        for wid, grp in df.groupby("_win_id"):
            win_groups[int(wid)] = grp

        # 4. Per-window: build graph snapshots
        graphs: Dict[int, Optional[NetworkGraphSnapshot]] = {}
        for wid in range(n_windows):
            win_df = win_groups.get(wid, pd.DataFrame())
            if len(win_df) < min_pkts:
                graphs[wid] = None
                continue
            w_start = float(input_windows.loc[wid, "start"])
            w_end   = float(input_windows.loc[wid, "end"])
            snap = build_graph_for_window(win_df, self._registry, window_id=wid,
                                          start_time=w_start, end_time=w_end)
            graphs[wid] = snap

        # 5. Extract sorted array of malicious timestamps
        mal_ts = np.array([], dtype=float)
        if "mitre_stage_id" in df.columns:
            m = df["mitre_stage_id"] > 0
            if m.any():
                mal_ts = np.sort(df.loc[m, "timestamp"].values)
        elif "label" in df.columns or "Label" in df.columns:
            lbl_col = "label" if "label" in df.columns else "Label"
            from src.labels.attack_mapping import is_malicious
            m = df[lbl_col].apply(is_malicious)
            if m.any():
                mal_ts = np.sort(df.loc[m, "timestamp"].values)

        # 6. Pre-compute per-window MITRE mode + confidence (vectorized)
        win_stage: Dict[int, int]   = {}
        win_conf:  Dict[int, float] = {}
        if "mitre_stage_id" in df.columns:
            for wid, grp in win_groups.items():
                win_stage[wid] = int(grp["mitre_stage_id"].mode().iloc[0]) if not grp.empty else 0
                win_conf[wid]  = float(grp["mitre_confidence"].mean())     if not grp.empty else 0.5

        # 7. Build sequences + attach targets
        sequences = build_sequences(input_windows, self.cfg)
        for seq in sequences:
            seq_win_ids = seq["input_window_ids"]

            # Skip if any required input window is empty
            snaps = [graphs.get(wid) for wid in seq_win_ids]
            if any(s is None for s in snaps):
                continue

            input_start = seq["input_start"]
            input_end   = seq["input_end"]
            target_wins = seq["target_windows"]
            target_end  = float(target_wins["end"].max())

            # Graded infiltration target:
            # 1) If attack already active in input window -> 1.0
            # 2) If attack occurs inside target horizon -> 1.0
            # 3) If attack is approaching in near future -> exp(-delta / TAU_DECAY)
            # 4) Otherwise -> 0.0 (benign sequence)
            infil_target = 0.0
            if len(mal_ts) > 0:
                idx_in = np.searchsorted(mal_ts, input_start)
                if idx_in < len(mal_ts) and mal_ts[idx_in] <= input_end:
                    infil_target = 1.0
                else:
                    idx_fut = np.searchsorted(mal_ts, input_end)
                    if idx_fut < len(mal_ts):
                        next_attack_time = mal_ts[idx_fut]
                        delta = next_attack_time - input_end
                        if delta <= (target_end - input_end):
                            infil_target = 1.0
                        elif delta <= 3.0 * TAU_DECAY:
                            infil_target = float(np.exp(-delta / TAU_DECAY))

            # MITRE stage: mode over last 2 input windows (O(1) dict lookup)
            stage_vals = [win_stage.get(wid, 0) for wid in seq_win_ids[-2:]]
            conf_vals  = [win_conf.get(wid, 0.5) for wid in seq_win_ids[-2:]]
            mitre_stage = int(pd.Series(stage_vals).mode().iloc[0]) if stage_vals else 0
            mitre_conf  = float(np.mean(conf_vals)) if conf_vals else 0.5

            # Grounded telemetry targets from target windows
            grounded = self._build_grounded_targets(df, win_groups, target_wins)

            self.samples.append(SequenceSample(
                graph_sequence=snaps,
                infiltration_target=infil_target,
                mitre_stage_id=mitre_stage,
                mitre_confidence=mitre_conf,
                grounded_targets=grounded,
                is_malicious=(infil_target >= 0.5),
            ))

    def _build_grounded_targets(
        self,
        df: pd.DataFrame,
        win_groups: Dict[int, pd.DataFrame],
        target_wins: pd.DataFrame,
    ) -> torch.Tensor:
        """
        Computes the [horizon_k, 3] ground-truth future telemetry tensor:
            dim 0: destination port entropy
            dim 1: SYN ratio
            dim 2: log1p(total bytes)
        These are the actual measured values in future windows — our supervision signal.
        """
        import math
        t_min_global = df["timestamp"].min()
        targets = []
        for tid in range(self.cfg.horizon_k):
            t_start = float(target_wins.loc[tid, "start"])
            t_end = float(target_wins.loc[tid, "end"])
            win_rows = df[(df["timestamp"] >= t_start) & (df["timestamp"] < t_end)]
            if win_rows.empty:
                targets.append([0.0, 0.0, 0.0])
                continue
            # Port entropy
            ports = win_rows["dst_port"].dropna()
            if len(ports) > 0:
                vc = ports.value_counts(normalize=True)
                entropy = float(-np.sum(vc * np.log2(vc + 1e-12)))
            else:
                entropy = 0.0
            # SYN ratio
            syn = float(win_rows["flag_syn"].sum()) if "flag_syn" in win_rows else 0.0
            total = len(win_rows)
            syn_ratio = syn / max(total, 1)
            # Log bytes
            byte_sum = float(win_rows["payload_size"].sum()) if "payload_size" in win_rows else float(total * 64)
            log_bytes = math.log1p(byte_sum)
            targets.append([entropy, syn_ratio, log_bytes])

        return torch.tensor(targets, dtype=torch.float32)

    # ------------------------------------------------------------------
    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> SequenceSample:
        return self.samples[idx]

    def class_weights(self) -> Tuple[float, float]:
        """Returns (benign_weight, malicious_weight) for weighted sampling."""
        n_mal = sum(1 for s in self.samples if s.is_malicious)
        n_total = len(self.samples)
        n_ben = n_total - n_mal
        if n_mal == 0 or n_ben == 0:
            return 1.0, 1.0
        return n_total / (2 * n_ben), n_total / (2 * n_mal)

    def imbalance_report(self) -> Dict:
        n_mal = sum(1 for s in self.samples if s.is_malicious)
        n_total = len(self.samples)
        return {
            "total_sequences": n_total,
            "malicious": n_mal,
            "benign": n_total - n_mal,
            "malicious_pct": 100.0 * n_mal / max(n_total, 1),
        }


def collate_sequences(batch: List[SequenceSample]):
    """
    Custom collate: returns the raw list + stacked scalar tensors.
    (Full graph batching requires torch_geometric; here we iterate per-sample.)
    """
    return {
        "samples": batch,
        "infiltration_targets": torch.tensor([s.infiltration_target for s in batch], dtype=torch.float32),
        "stage_ids": torch.tensor([s.mitre_stage_id for s in batch], dtype=torch.long),
        "stage_confs": torch.tensor([s.mitre_confidence for s in batch], dtype=torch.float32),
        "grounded_targets": torch.stack([s.grounded_targets for s in batch], dim=0),
        "is_malicious": torch.tensor([s.is_malicious for s in batch], dtype=torch.bool),
    }


def make_dataloaders(
    dataset: CyberDefenceDataset,
    train_frac: float = 0.7,
    val_frac: float = 0.15,
    batch_size: int = 8,
    seed: int = 42,
    weighted_sampler: bool = True,
) -> Tuple[DataLoader, DataLoader, DataLoader]:
    """Splits dataset and returns (train_dl, val_dl, test_dl)."""
    rng = random.Random(seed)
    indices = list(range(len(dataset)))
    rng.shuffle(indices)

    n_train = int(len(indices) * train_frac)
    n_val = int(len(indices) * val_frac)
    train_idx = indices[:n_train]
    val_idx = indices[n_train:n_train + n_val]
    test_idx = indices[n_train + n_val:]

    from torch.utils.data import Subset
    train_ds = Subset(dataset, train_idx)
    val_ds = Subset(dataset, val_idx)
    test_ds = Subset(dataset, test_idx)

    sampler = None
    if weighted_sampler and len(train_idx) > 0:
        ben_w, mal_w = dataset.class_weights()
        weights = [
            mal_w if dataset.samples[i].is_malicious else ben_w
            for i in train_idx
        ]
        sampler = WeightedRandomSampler(weights, num_samples=len(train_idx), replacement=True)

    train_dl = DataLoader(train_ds, batch_size=batch_size,
                          sampler=sampler, shuffle=(sampler is None),
                          collate_fn=collate_sequences)
    val_dl = DataLoader(val_ds, batch_size=batch_size, shuffle=False,
                        collate_fn=collate_sequences)
    test_dl = DataLoader(test_ds, batch_size=batch_size, shuffle=False,
                         collate_fn=collate_sequences)
    return train_dl, val_dl, test_dl

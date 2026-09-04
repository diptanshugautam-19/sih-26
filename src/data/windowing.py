"""
src/data/windowing.py

STAGE 1 (temporal): turns a flat, timestamped packet/flow table into:
  1. a grid of overlapping INPUT windows (5s wide, 2.5s stride)
  2. a mapping of every row to the window(s) it falls in
  3. (input_sequence -> target_sequence) pairs, where each target grid is
     built fresh, anchored to the END of its own input sequence, using a
     NON-overlapping stride — never the same grid the inputs came from.

Responsibility boundary:
    This module does NOT build graphs (graph_builder.py) and does NOT
    decide empty-window policy beyond reporting counts (dataset.py / callers
    decide skip-vs-placeholder). It only answers: "which window(s) does
    this timestamp belong to, and which future windows are the leak-safe
    target for a given input sequence?"

Why target windows can't just be "the next few rows of the input grid":
    The input grid is overlapping (stride < window_size), so window i+1
    shares up to (window_size - stride) seconds of raw traffic with window
    i. If targets were drawn from that same grid, a target window could
    share packets with the LAST input window of its own sequence — the
    model would partly be predicting data it already saw. Building targets
    on an independent, non-overlapping grid anchored at the input
    sequence's end time makes that structurally impossible, not just
    unlikely.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class WindowConfig:
    window_size: float = 5.0   # seconds
    stride: float = 2.5        # seconds (input grid only; targets always use window_size as stride)
    seq_len: int = 10          # input windows per sequence
    horizon_k: int = 4         # target windows per sequence (project range: 3-5)

    def __post_init__(self):
        if self.window_size <= 0 or self.stride <= 0:
            raise ValueError("window_size and stride must be positive.")
        if self.stride > self.window_size:
            raise ValueError(
                f"stride ({self.stride}) > window_size ({self.window_size}) would leave gaps "
                f"with no window coverage at all — not just non-overlapping, actually missing data."
            )
        if self.seq_len < 1 or self.horizon_k < 1:
            raise ValueError("seq_len and horizon_k must be >= 1.")


def make_input_windows(t_min: float, t_max: float, cfg: WindowConfig) -> pd.DataFrame:
    """
    Enumerate the full overlapping input-window grid covering [t_min, t_max].

    Window i covers [t_min + i*stride, t_min + i*stride + window_size).
    Returns a DataFrame indexed by window_id with columns [start, end].
    """
    if t_max < t_min:
        raise ValueError(f"t_max ({t_max}) < t_min ({t_min})")

    span = t_max - t_min
    # Last window whose START still falls within the data span (a window
    # can extend past t_max at the very end — that's fine, it just has
    # fewer packets, same as any other window near a capture boundary).
    n_windows = int(np.floor(span / cfg.stride)) + 1
    window_ids = np.arange(n_windows)
    starts = t_min + window_ids * cfg.stride
    ends = starts + cfg.window_size

    return pd.DataFrame({"window_id": window_ids, "start": starts, "end": ends}).set_index("window_id")


def _vectorized_ranges(lo: np.ndarray, hi: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """
    Given per-item inclusive integer ranges [lo[j], hi[j]], return
    (item_index_repeated, value) covering every (item, value) pair in every
    range — without a Python-level loop over items. Items whose range is
    empty (hi[j] < lo[j]) contribute nothing.

    e.g. lo=[0,2], hi=[1,2] -> item_index=[0,0,1], value=[0,1,2]
    """
    counts = np.maximum(hi - lo + 1, 0)
    total = int(counts.sum())
    if total == 0:
        return np.empty(0, dtype=int), np.empty(0, dtype=int)

    item_index = np.repeat(np.arange(len(lo)), counts)
    # Within each item's run of `count` output rows, produce 0,1,2,...,count-1
    # then add that item's lo[j]. The cumsum-shift trick avoids a Python loop.
    run_starts = np.repeat(np.cumsum(counts) - counts, counts)
    within_run_offset = np.arange(total) - run_starts
    values = np.repeat(lo, counts) + within_run_offset
    return item_index, values


def assign_rows_to_windows(
    timestamps: pd.Series, t_min: float, cfg: WindowConfig, n_windows: int
) -> pd.DataFrame:
    """
    Vectorized: for every row's timestamp, find every input window_id it
    falls into (a row near a boundary can fall into more than one window,
    since the grid overlaps). No Python-level loop over rows.

    Returns a long-format DataFrame with columns [row_index, window_id],
    one row per (original row, window it belongs to) pair. Join this back
    to the source table on row_index, then groupby window_id, to get the
    packets/flows for each window (that's graph_builder.py's job).
    """
    r = timestamps.to_numpy(dtype=float) - t_min
    if np.any(r < 0):
        raise ValueError("Found timestamps before t_min — pass the true minimum timestamp as t_min.")

    # i*stride <= r < i*stride + window_size
    #   => i <= r/stride                         (i_max)
    #   => i >  (r - window_size)/stride          (i_min, strict, so +1 after floor)
    i_max = np.floor(r / cfg.stride).astype(np.int64)
    i_min = np.floor((r - cfg.window_size) / cfg.stride).astype(np.int64) + 1
    i_min = np.maximum(i_min, 0)
    i_max = np.minimum(i_max, n_windows - 1)

    row_pos, window_ids = _vectorized_ranges(i_min, i_max)
    row_index = timestamps.index.to_numpy()[row_pos]
    return pd.DataFrame({"row_index": row_index, "window_id": window_ids})


def make_target_windows(anchor_time: float, cfg: WindowConfig) -> pd.DataFrame:
    """
    Build the K non-overlapping target windows for one sequence, starting
    exactly at anchor_time (the END of that sequence's last input window).
    Stride == window_size here by construction — targets never overlap
    each other, and by starting at the input sequence's end time, they
    can't overlap the inputs either.
    """
    k_ids = np.arange(cfg.horizon_k)
    starts = anchor_time + k_ids * cfg.window_size
    ends = starts + cfg.window_size
    return pd.DataFrame({"target_id": k_ids, "start": starts, "end": ends}).set_index("target_id")


def build_sequences(input_windows: pd.DataFrame, cfg: WindowConfig) -> list[dict]:
    """
    Slide a window of `seq_len` consecutive input-grid windows across the
    full input grid, and attach a freshly-built, non-overlapping target
    grid to each one. Every sequence is independently leakage-checked
    before being included — see the assertion below. This is not a
    performance-sensitive path (one iteration per sequence, not per
    packet), so a plain loop here is fine and keeps the leakage check
    readable and easy to audit.

    Returns a list of dicts:
        {
          "seq_id": int,
          "input_window_ids": list[int],   # length == cfg.seq_len
          "input_start": float, "input_end": float,
          "target_windows": pd.DataFrame,  # target_id -> start, end
        }
    """
    n_windows = len(input_windows)
    sequences = []
    seq_id = 0
    for start_pos in range(0, n_windows - cfg.seq_len + 1):
        window_ids = list(range(start_pos, start_pos + cfg.seq_len))
        input_start = float(input_windows.loc[window_ids[0], "start"])
        input_end = float(input_windows.loc[window_ids[-1], "end"])

        target_windows = make_target_windows(anchor_time=input_end, cfg=cfg)

        # CRITICAL leakage guard — not a style choice, this is the thing
        # tests/test_windowing.py exists to catch. Every target window's
        # start must be >= the input sequence's end. Strict, not "close
        # enough": equality (target starts exactly at input_end) is the
        # intended, allowed case; anything less is a bug.
        assert (target_windows["start"] >= input_end).all(), (
            f"LEAKAGE: sequence {seq_id} has a target window starting before "
            f"its input sequence ends ({input_end}). This must never happen — "
            f"stop and fix window construction, don't suppress this."
        )

        sequences.append({
            "seq_id": seq_id,
            "input_window_ids": window_ids,
            "input_start": input_start,
            "input_end": input_end,
            "target_windows": target_windows,
        })
        seq_id += 1

    return sequences


def window_fill_report(assignment: pd.DataFrame, n_windows: int) -> dict:
    """
    Per the project's data-traps notes: overnight/quiet periods produce
    near-empty windows, and the policy is to skip them (never fabricate
    nodes) while recording the skip rate. This computes that rate so
    callers can log/report it rather than silently dropping data.
    """
    counts = assignment.groupby("window_id").size()
    counts = counts.reindex(range(n_windows), fill_value=0)
    n_empty = int((counts == 0).sum())
    return {
        "n_windows": n_windows,
        "n_empty": n_empty,
        "empty_rate": n_empty / n_windows if n_windows else 0.0,
        "min_count": int(counts.min()) if n_windows else 0,
        "max_count": int(counts.max()) if n_windows else 0,
        "median_count": float(counts.median()) if n_windows else 0.0,
    }

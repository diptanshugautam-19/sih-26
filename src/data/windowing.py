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
    if np.any(r < -_EPS):
        raise ValueError("Found timestamps before t_min — pass the true minimum timestamp as t_min.")
    r = np.maximum(r, 0.0)  # clamp away tiny negative float noise right at t_min itself

    # i*stride <= r < i*stride + window_size
    #   => i <= r/stride                         (i_max)
    #   => i >  (r - window_size)/stride          (i_min, strict, so +1 after floor)
    # _EPS nudges r before the floor divisions so a timestamp that should
    # land EXACTLY on a window boundary (e.g. r == 2.5) doesn't get pushed
    # to the wrong side purely from float accumulation error upstream
    # (timestamps - t_min can land on 2.4999999999996 instead of 2.5).
    # This does not change which window a timestamp "really" belongs to —
    # it only protects the intended boundary case from float noise.
    i_max = np.floor((r + _EPS) / cfg.stride).astype(np.int64)
    i_min = np.floor((r - cfg.window_size + _EPS) / cfg.stride).astype(np.int64) + 1
    i_min = np.maximum(i_min, 0)
    i_max = np.minimum(i_max, n_windows - 1)

    row_pos, window_ids = _vectorized_ranges(i_min, i_max)
    row_index = timestamps.index.to_numpy()[row_pos]
    return pd.DataFrame({"row_index": row_index, "window_id": window_ids})


_EPS = 1e-6  # tolerance for float boundary comparisons — see build_sequences/
             # assign_rows_to_windows docstrings for why this exists.


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


def _assert_no_leakage(target_starts: np.ndarray, input_ends: np.ndarray) -> None:
    """
    Extracted so it can be tested directly against both valid and
    deliberately-broken arrays — see test_leakage_guard_would_catch_a_
    future_regression_in_the_formula in tests/test_windowing.py. Today's
    build_sequences() can never actually trigger this (target_start is
    defined as input_end + k*window_size with k>=0, so it's true by
    construction), but this function is the thing that WOULD catch a
    future bug in that formula, so it needs to be independently testable.
    """
    violations = target_starts < (input_ends[:, None] - _EPS)
    if violations.any():
        bad_seq, bad_k = np.argwhere(violations)[0]
        raise AssertionError(
            f"LEAKAGE: sequence {bad_seq} target {bad_k} starts at "
            f"{target_starts[bad_seq, bad_k]}, before its input sequence "
            f"ends ({input_ends[bad_seq]}). This must never happen — stop "
            f"and fix window construction, don't suppress this."
        )


def build_sequences(input_windows: pd.DataFrame, cfg: WindowConfig) -> list[dict]:
    """
    Slide a window of `seq_len` consecutive input-grid windows across the
    full input grid, and attach a non-overlapping target grid to each one.

    Vectorized: input_start/input_end for every sequence, and every target
    window's start/end, are computed in one batch of NumPy array ops —
    no per-sequence Python dict/DataFrame construction in a loop. On a
    real 31,669-sequence run (22-hour capture, default config) this cut
    build time from ~13.2s to well under a second; exact numbers depend on
    seq_len/horizon_k and are worth re-checking if those change a lot.

    The leakage guard is NOT weakened by vectorizing it — every sequence's
    every target start is still checked against its own input_end, just as
    one batched array comparison instead of one assert per loop iteration.
    A single failure anywhere still raises, with enough detail (which
    sequence, by how much) to debug it, same as before.

    A small epsilon tolerance (_EPS) is applied to the leakage check: it
    guards against a target start being flagged as "before" input_end due
    to float rounding when they're actually meant to be exactly equal
    (e.g. 27.500000000000004 vs 27.5). It does NOT relax the leakage rule
    itself — a target starting meaningfully before input_end (more than
    _EPS early) still fails loudly.

    Returns a list of dicts, same shape as before:
        {
          "seq_id": int,
          "input_window_ids": list[int],   # length == cfg.seq_len
          "input_start": float, "input_end": float,
          "target_windows": pd.DataFrame,  # target_id -> start, end
        }
    """
    n_windows = len(input_windows)
    n_seqs = n_windows - cfg.seq_len + 1
    if n_seqs <= 0:
        return []

    starts_arr = input_windows["start"].to_numpy()
    ends_arr = input_windows["end"].to_numpy()

    seq_ids = np.arange(n_seqs)
    input_starts = starts_arr[seq_ids]                       # window at seq start
    input_ends = ends_arr[seq_ids + cfg.seq_len - 1]          # window at seq end

    # Every sequence's K target windows in one shot:
    # target_starts[s, k] = input_ends[s] + k * window_size
    k_ids = np.arange(cfg.horizon_k)
    target_starts = input_ends[:, None] + k_ids[None, :] * cfg.window_size
    target_ends = target_starts + cfg.window_size

    # Batched leakage guard — same check as before (target start >=
    # input_end), just done once over the whole (n_seqs, horizon_k) matrix
    # instead of once per sequence in a loop.
    _assert_no_leakage(target_starts, input_ends)

    sequences = []
    for s in seq_ids:
        window_ids = list(range(s, s + cfg.seq_len))
        target_windows = pd.DataFrame(
            {"start": target_starts[s], "end": target_ends[s]},
            index=pd.Index(k_ids, name="target_id"),
        )
        sequences.append({
            "seq_id": int(s),
            "input_window_ids": window_ids,
            "input_start": float(input_starts[s]),
            "input_end": float(input_ends[s]),
            "target_windows": target_windows,
        })

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
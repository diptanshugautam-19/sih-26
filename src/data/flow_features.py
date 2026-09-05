"""
src/data/flow_features.py

Independently recomputes flow-level statistics from raw packet-level telemetry.

LOCKED ARCHITECTURAL REQUIREMENT:
Per AGENTS.md, pre-engineered features from CICFlowMeter must NOT be ingested raw.
All flow-level representations (durations, forward/backward counts, inter-arrival times,
flag distributions, bidirectional ratios) must be derived directly from lower-level
packet records (timestamp, 5-tuple, flags, payload sizes, TTL, TCP window).
"""

from __future__ import annotations
import math
from typing import Dict, List, Tuple, Any, Optional
import numpy as np
import pandas as pd


def canonical_flow_id(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int
) -> Tuple[str, Tuple[str, int, str, int, int]]:
    """
    Computes a canonical bidirectional flow identifier and direction flag.
    Returns:
        (canonical_key, canonical_5tuple)
    """
    endpoint_a = (str(src_ip), int(src_port))
    endpoint_b = (str(dst_ip), int(dst_port))

    if endpoint_a <= endpoint_b:
        key = f"{endpoint_a[0]}:{endpoint_a[1]}<->{endpoint_b[0]}:{endpoint_b[1]}:{protocol}"
        return key, (endpoint_a[0], endpoint_a[1], endpoint_b[0], endpoint_b[1], protocol)
    else:
        key = f"{endpoint_b[0]}:{endpoint_b[1]}<->{endpoint_a[0]}:{endpoint_a[1]}:{protocol}"
        return key, (endpoint_b[0], endpoint_b[1], endpoint_a[0], endpoint_a[1], protocol)


def aggregate_packets_to_flows(
    df_packets: pd.DataFrame,
    max_flow_idle_sec: float = 120.0,
) -> pd.DataFrame:
    """
    Recomputes bidirectional flow statistics from packet telemetry from first principles.

    Args:
        df_packets: DataFrame of packet telemetry with columns:
            timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
            payload_size, flag_syn, flag_ack, flag_rst, flag_fin,
            [optional] flag_psh, flag_urg, ttl, tcp_window, is_retransmission, label
        max_flow_idle_sec: Flows idle longer than this timeout are split into new flows.

    Returns:
        pd.DataFrame: Recomputed flow records with authentic, un-leaked features:
            - flow_key, src_ip, dst_ip, src_port, dst_port, protocol
            - timestamp (start time of flow), end_time, flow_duration
            - tot_fwd_pkts, tot_bwd_pkts, tot_pkts
            - tot_fwd_bytes, tot_bwd_bytes, tot_bytes
            - flow_byts_s, flow_pkts_s
            - flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min
            - fwd_iat_mean, fwd_iat_std, bwd_iat_mean, bwd_iat_std
            - pkt_len_mean, pkt_len_std, pkt_len_max, pkt_len_min
            - syn_flag_cnt, ack_flag_cnt, rst_flag_cnt, fin_flag_cnt
            - bidi_ratio (fwd / total packets), bidi_byte_ratio (fwd / total bytes)
            - retrans_count, is_retransmission_rate
            - [optional] label, mitre_stage_id
    """
    if df_packets.empty:
        return pd.DataFrame()

    df = df_packets.copy()
    if not np.issubdtype(df["timestamp"].dtype, np.number):
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce").astype(np.int64) / 1e9

    df = df.sort_values("timestamp").reset_index(drop=True)

    # Fast vector canonical keys
    s_ip = df["src_ip"].astype(str).to_numpy()
    d_ip = df["dst_ip"].astype(str).to_numpy()
    s_pt = df["src_port"].fillna(0).astype(int).to_numpy()
    d_pt = df["dst_port"].fillna(0).astype(int).to_numpy()
    proto = df["protocol"].fillna(6).astype(int).to_numpy()

    canon_keys = []
    directions = []  # True if forward (initiator matches canonical first endpoint), False if backward
    for i in range(len(df)):
        ep_a = (s_ip[i], s_pt[i])
        ep_b = (d_ip[i], d_pt[i])
        if ep_a <= ep_b:
            canon_keys.append(f"{ep_a[0]}:{ep_a[1]}<->{ep_b[0]}:{ep_b[1]}:{proto[i]}")
            directions.append(True)
        else:
            canon_keys.append(f"{ep_b[0]}:{ep_b[1]}<->{ep_a[0]}:{ep_a[1]}:{proto[i]}")
            directions.append(False)

    df["_canon_key"] = canon_keys
    df["_is_fwd"] = directions

    records = []
    for flow_id, group in df.groupby("_canon_key"):
        ts = group["timestamp"].to_numpy(dtype=float)
        sizes = group["payload_size"].fillna(0.0).to_numpy(dtype=float)
        is_fwd = group["_is_fwd"].to_numpy(dtype=bool)

        n_pkts = len(ts)
        t_start = float(ts[0])
        t_end = float(ts[-1])
        duration = max(0.0, t_end - t_start)

        # Forward and backward split
        fwd_mask = is_fwd
        bwd_mask = ~is_fwd

        fwd_pkts = int(np.sum(fwd_mask))
        bwd_pkts = int(np.sum(bwd_mask))

        fwd_bytes = float(np.sum(sizes[fwd_mask]))
        bwd_bytes = float(np.sum(sizes[bwd_mask]))
        tot_bytes = fwd_bytes + bwd_bytes

        # Flow rates
        flow_byts_s = tot_bytes / max(duration, 1e-3)
        flow_pkts_s = n_pkts / max(duration, 1e-3)

        # Flow Inter-Arrival Times (IAT)
        if n_pkts > 1:
            diffs = np.diff(ts)
            iat_mean = float(np.mean(diffs))
            iat_std = float(np.std(diffs))
            iat_max = float(np.max(diffs))
            iat_min = float(np.min(diffs))
        else:
            iat_mean, iat_std, iat_max, iat_min = 0.0, 0.0, 0.0, 0.0

        # Directional IAT
        fwd_ts = ts[fwd_mask]
        if len(fwd_ts) > 1:
            fwd_diffs = np.diff(fwd_ts)
            fwd_iat_mean = float(np.mean(fwd_diffs))
            fwd_iat_std = float(np.std(fwd_diffs))
        else:
            fwd_iat_mean, fwd_iat_std = 0.0, 0.0

        bwd_ts = ts[bwd_mask]
        if len(bwd_ts) > 1:
            bwd_diffs = np.diff(bwd_ts)
            bwd_iat_mean = float(np.mean(bwd_diffs))
            bwd_iat_std = float(np.std(bwd_diffs))
        else:
            bwd_iat_mean, bwd_iat_std = 0.0, 0.0

        # Packet length stats
        pkt_len_mean = float(np.mean(sizes)) if n_pkts > 0 else 0.0
        pkt_len_std = float(np.std(sizes)) if n_pkts > 0 else 0.0
        pkt_len_max = float(np.max(sizes)) if n_pkts > 0 else 0.0
        pkt_len_min = float(np.min(sizes)) if n_pkts > 0 else 0.0

        # Flag sums
        syn_cnt = float(group["flag_syn"].sum()) if "flag_syn" in group else 0.0
        ack_cnt = float(group["flag_ack"].sum()) if "flag_ack" in group else 0.0
        rst_cnt = float(group["flag_rst"].sum()) if "flag_rst" in group else 0.0
        fin_cnt = float(group["flag_fin"].sum()) if "flag_fin" in group else 0.0

        # Bidirectional ratios
        bidi_pkt_ratio = float(fwd_pkts / max(n_pkts, 1))
        bidi_byte_ratio = float(fwd_bytes / max(tot_bytes, 1.0))

        # Retransmissions
        retrans = float(group["is_retransmission"].sum()) if "is_retransmission" in group else 0.0
        retrans_rate = float(retrans / max(n_pkts, 1))

        # Primary endpoints (from the first initiating packet)
        first_row = group.iloc[0]
        rec = {
            "flow_key": flow_id,
            "src_ip": first_row["src_ip"],
            "dst_ip": first_row["dst_ip"],
            "src_port": first_row["src_port"],
            "dst_port": first_row["dst_port"],
            "protocol": first_row["protocol"],
            "timestamp": t_start,
            "end_time": t_end,
            "flow_duration": duration,
            "tot_fwd_pkts": fwd_pkts,
            "tot_bwd_pkts": bwd_pkts,
            "tot_pkts": n_pkts,
            "tot_fwd_bytes": fwd_bytes,
            "tot_bwd_bytes": bwd_bytes,
            "tot_bytes": tot_bytes,
            "flow_byts_s": flow_byts_s,
            "flow_pkts_s": flow_pkts_s,
            "flow_iat_mean": iat_mean,
            "flow_iat_std": iat_std,
            "flow_iat_max": iat_max,
            "flow_iat_min": iat_min,
            "fwd_iat_mean": fwd_iat_mean,
            "fwd_iat_std": fwd_iat_std,
            "bwd_iat_mean": bwd_iat_mean,
            "bwd_iat_std": bwd_iat_std,
            "pkt_len_mean": pkt_len_mean,
            "pkt_len_std": pkt_len_std,
            "pkt_len_max": pkt_len_max,
            "pkt_len_min": pkt_len_min,
            "flag_syn": syn_cnt,
            "flag_ack": ack_cnt,
            "flag_rst": rst_cnt,
            "flag_fin": fin_cnt,
            "bidi_ratio": bidi_pkt_ratio,
            "bidi_byte_ratio": bidi_byte_ratio,
            "is_retransmission": retrans,
            "retransmission_rate": retrans_rate,
            "payload_size": tot_bytes,
        }

        # Preserve metadata labels if present
        for col in ["label", "Label", "mitre_stage_id", "mitre_stage_name", "mitre_confidence"]:
            if col in first_row:
                rec[col] = first_row[col]

        records.append(rec)

    return pd.DataFrame(records)

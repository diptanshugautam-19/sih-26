"""
src/data/graph_builder.py

STAGE 2 (spatial & dynamic graphs):
Turns a 5-second window DataFrame of flows/packets into a PyTorch-compatible Graph.

Key Responsibilities:
1. Persistent Node Vocabulary / Node Memory mapping (stable integer ID per host IP).
2. Node Feature Matrix (X):
   - In-degree, Out-degree
   - Destination Port Entropy (detects wide sweeps vs. focused beaconing)
   - Average TTL & TTL Variance
   - Payload byte volume
3. Edge Feature Matrix (E):
   - Total Bytes
   - SYN flag ratio
   - RST/FIN flag ratio
   - Retransmission count & rate
4. Grounded Future Dynamics Target Computation (Head 1 Ground Truth):
   - Mean destination port entropy in future window
   - Future SYN ratio
   - Future Byte delta
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any, Optional
import math
import numpy as np
import pandas as pd
import torch


class PersistentNodeRegistry:
    """
    Maintains a persistent mapping from IP strings to integer node indices.
    Guarantees that a host IP retains its identity across windows t_1 ... t_10,
    enabling persistent node memory banks.
    """
    def __init__(self):
        self.ip_to_id: Dict[str, int] = {}
        self.id_to_ip: Dict[int, str] = {}

    def get_or_create(self, ip: str) -> int:
        if ip not in self.ip_to_id:
            idx = len(self.ip_to_id)
            self.ip_to_id[ip] = idx
            self.id_to_ip[idx] = ip
        return self.ip_to_id[ip]

    def get(self, ip: str) -> Optional[int]:
        return self.ip_to_id.get(ip, None)

    def size(self) -> int:
        return len(self.ip_to_id)


def _compute_entropy(values: pd.Series | np.ndarray) -> float:
    """Computes Shannon entropy over categorical occurrences (e.g. ports)."""
    if len(values) == 0:
        return 0.0
    val_counts = pd.Series(values).value_counts(normalize=True)
    return float(-np.sum(val_counts * np.log2(val_counts + 1e-12)))


def _is_private_ip(ip_str: str) -> float:
    """RFC 1918 private IPv4 detection (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)."""
    if ip_str.startswith(("10.", "192.168.", "127.")):
        return 1.0
    if ip_str.startswith("172."):
        parts = ip_str.split(".")
        if len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return 1.0
    return 0.0


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Coerce value to float and replace NaN/inf with default."""
    try:
        f = float(val)
        return default if (math.isnan(f) or math.isinf(f)) else f
    except (TypeError, ValueError):
        return default


@dataclass
class NetworkGraphSnapshot:
    """Structured container for a single time window's graph representation."""
    window_id: int
    start_time: float
    end_time: float
    num_nodes: int
    edge_index: torch.Tensor       # Shape: [2, num_edges]
    x: torch.Tensor                # Node features: [num_nodes, 16]
    edge_attr: torch.Tensor        # Edge features: [num_edges, 12]
    node_ips: List[str]            # IP corresponding to each row in x
    grounded_dynamics: torch.Tensor  # [3] -> [port_entropy, syn_ratio, log_bytes]


def build_graph_for_window(
    window_df: pd.DataFrame,
    registry: PersistentNodeRegistry,
    window_id: int = 0,
    start_time: float = 0.0,
    end_time: float = 5.0,
) -> NetworkGraphSnapshot:
    """
    Constructs a PyTorch graph snapshot from all packets/flows in a 5-second window.
    """
    if window_df.empty:
        # Return an empty graph structure
        cur_nodes = registry.size() if registry is not None else 0
        return NetworkGraphSnapshot(
            window_id=window_id,
            start_time=start_time,
            end_time=end_time,
            num_nodes=cur_nodes,
            edge_index=torch.empty((2, 0), dtype=torch.long),
            x=torch.zeros((max(cur_nodes, 1), 16), dtype=torch.float32),
            edge_attr=torch.empty((0, 16), dtype=torch.float32),
            node_ips=[registry.id_to_ip.get(i, f"ip_{i}") for i in range(max(cur_nodes, 1))] if registry else [],
            grounded_dynamics=torch.zeros(3, dtype=torch.float32),
        )

    if registry is None:
        registry = PersistentNodeRegistry()

    # 1. Register active IPs in this window/sequence (scoped, zero ghost nodes)
    src_ips = window_df["src_ip"].astype(str).tolist()
    dst_ips = window_df["dst_ip"].astype(str).tolist()
    for ip in set(src_ips + dst_ips):
        registry.get_or_create(ip)

    total_registered_nodes = registry.size()
    node_ips = [registry.id_to_ip[i] for i in range(total_registered_nodes)]

    wdf = window_df.copy()
    wdf["_src_str"] = wdf["src_ip"].astype(str)
    wdf["_dst_str"] = wdf["dst_ip"].astype(str)

    # Pre-compute bidirectional pair counts for O(1) ratio calculation
    wdf["_pair"] = wdf["_src_str"] + "->" + wdf["_dst_str"]
    pair_counts = wdf["_pair"].value_counts()

    # 2. Aggregate flows by (src_ip, dst_ip) to construct directed edges
    grouped_edges = wdf.groupby(["_src_str", "_dst_str"])

    src_indices = []
    dst_indices = []
    edge_features_list = []

    total_syn_count = 0.0
    total_ack_count = 0.0
    total_bytes_window = 0.0

    for (s_ip, d_ip), edge_rows in grouped_edges:
        s_idx = registry.ip_to_id[str(s_ip)]
        d_idx = registry.ip_to_id[str(d_ip)]
        src_indices.append(s_idx)
        dst_indices.append(d_idx)

        # Edge aggregation statistics
        n_pkts = len(edge_rows)
        bytes_sum = _safe_float(edge_rows["payload_size"].sum() if "payload_size" in edge_rows else n_pkts * 64)
        total_bytes_window += bytes_sum

        syn_flags = _safe_float(edge_rows["flag_syn"].sum() if "flag_syn" in edge_rows else 0.0)
        ack_flags = _safe_float(edge_rows["flag_ack"].sum() if "flag_ack" in edge_rows else 0.0)
        rst_flags = _safe_float(edge_rows["flag_rst"].sum() if "flag_rst" in edge_rows else 0.0)
        fin_flags = _safe_float(edge_rows["flag_fin"].sum() if "flag_fin" in edge_rows else 0.0)

        total_syn_count += syn_flags
        total_ack_count += ack_flags

        retrans = _safe_float(edge_rows["is_retransmission"].sum() if "is_retransmission" in edge_rows else 0.0)

        dst_ports_unique = float(edge_rows["dst_port"].nunique()) if "dst_port" in edge_rows else 1.0
        ttl_mean = _safe_float(edge_rows["ttl"].mean(), 64.0) if "ttl" in edge_rows else 64.0
        ttl_std = _safe_float(edge_rows["ttl"].std(), 0.0) if "ttl" in edge_rows and len(edge_rows) > 1 else 0.0
        win_mean = _safe_float(edge_rows["tcp_window"].mean(), 1024.0) if "tcp_window" in edge_rows else 1024.0
        is_internal = _is_private_ip(str(s_ip))

        # Brief Requirements: Flow Inter-Arrival Time (IAT) statistics
        if "timestamp" in edge_rows.columns and n_pkts > 1:
            edge_ts = np.sort(pd.to_numeric(edge_rows["timestamp"], errors="coerce").dropna().values)
            if len(edge_ts) > 1:
                diffs = np.diff(edge_ts)
                iat_mean = _safe_float(np.mean(diffs), 0.0)
                iat_std  = _safe_float(np.std(diffs), 0.0)
                iat_max  = _safe_float(np.max(diffs), 0.0)
            else:
                iat_mean, iat_std, iat_max = 0.0, 0.0, 0.0
        elif "flow_iat_mean" in edge_rows.columns:
            iat_mean = _safe_float(edge_rows["flow_iat_mean"].mean(), 0.0)
            iat_std  = _safe_float(edge_rows["flow_iat_std"].mean() if "flow_iat_std" in edge_rows else 0.0, 0.0)
            iat_max  = _safe_float(edge_rows["flow_iat_max"].mean() if "flow_iat_max" in edge_rows else 0.0, 0.0)
        else:
            iat_mean, iat_std, iat_max = 0.0, 0.0, 0.0

        # Brief Requirements: Bidirectional flow ratio
        fwd_count = pair_counts.get(f"{s_ip}->{d_ip}", n_pkts)
        bwd_count = pair_counts.get(f"{d_ip}->{s_ip}", 0)
        bidi_ratio = float(fwd_count / max(fwd_count + bwd_count, 1))

        # Edge feature vector (16 dimensions) - zero NaNs guaranteed
        feat = [
            math.log1p(n_pkts),                               # 0: log packet count
            math.log1p(bytes_sum),                            # 1: log byte volume
            syn_flags / max(n_pkts, 1),                       # 2: syn ratio
            ack_flags / max(n_pkts, 1),                       # 3: ack ratio
            rst_flags / max(n_pkts, 1),                       # 4: rst ratio
            fin_flags / max(n_pkts, 1),                       # 5: fin ratio
            retrans / max(n_pkts, 1),                         # 6: retransmission rate
            dst_ports_unique,                                 # 7: unique dst ports
            ttl_mean,                                         # 8: mean ttl
            ttl_std,                                          # 9: ttl std
            win_mean,                                         # 10: mean win
            is_internal,                                      # 11: internal private IP flag
            min(max(iat_mean, 0.0), 60.0),                    # 12: IAT mean (brief req)
            min(max(iat_std, 0.0), 60.0),                     # 13: IAT std (brief req)
            min(max(iat_max, 0.0), 60.0),                     # 14: IAT max (brief req)
            bidi_ratio,                                       # 15: bidirectional flow ratio (brief req)
        ]
        edge_features_list.append(feat)

    if src_indices:
        edge_index = torch.tensor([src_indices, dst_indices], dtype=torch.long)
        edge_attr = torch.tensor(edge_features_list, dtype=torch.float32)
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)
        edge_attr = torch.empty((0, 16), dtype=torch.float32)

    # 3. Compute Node Feature Matrix X [total_nodes, 16] - fully populated
    node_features = np.zeros((total_registered_nodes, 16), dtype=np.float32)

    # Host-level telemetry aggregations
    src_counts = wdf["_src_str"].value_counts()
    dst_counts = wdf["_dst_str"].value_counts()
    bytes_src = wdf.groupby("_src_str")["payload_size"].sum() if "payload_size" in wdf.columns else pd.Series(dtype=float)
    bytes_dst = wdf.groupby("_dst_str")["payload_size"].sum() if "payload_size" in wdf.columns else pd.Series(dtype=float)
    syn_src = wdf.groupby("_src_str")["flag_syn"].sum() if "flag_syn" in wdf.columns else pd.Series(dtype=float)
    ack_src = wdf.groupby("_src_str")["flag_ack"].sum() if "flag_ack" in wdf.columns else pd.Series(dtype=float)
    rst_src = wdf.groupby("_src_str")["flag_rst"].sum() if "flag_rst" in wdf.columns else pd.Series(dtype=float)
    unique_dsts_per_src = wdf.groupby("_src_str")["_dst_str"].nunique()
    unique_srcs_per_dst = wdf.groupby("_dst_str")["_src_str"].nunique()
    retrans_src = wdf.groupby("_src_str")["is_retransmission"].sum() if "is_retransmission" in wdf.columns else pd.Series(dtype=float)
    win_src = wdf.groupby("_src_str")["tcp_window"].mean() if "tcp_window" in wdf.columns else pd.Series(dtype=float)

    # Port entropy per source
    if "dst_port" in wdf.columns:
        port_entropy_per_src = (
            wdf.groupby("_src_str")["dst_port"]
            .apply(lambda s: float(-np.sum(
                (vc := s.value_counts(normalize=True)).values *
                np.log2(vc.values + 1e-12)
            )))
        )
    else:
        port_entropy_per_src = pd.Series(dtype=float)

    # TTL mean & variance per IP
    if "ttl" in wdf.columns:
        ttl_src = wdf.groupby("_src_str")["ttl"].agg(["mean", "var"])
        ttl_dst = wdf.groupby("_dst_str")["ttl"].agg(["mean", "var"])
    else:
        ttl_src = ttl_dst = pd.DataFrame(columns=["mean", "var"])

    for ip_str, ip_id in registry.ip_to_id.items():
        out_deg = float(src_counts.get(ip_str, 0))
        in_deg  = float(dst_counts.get(ip_str, 0))
        port_ent = _safe_float(port_entropy_per_src.get(ip_str, 0.0), 0.0)

        # TTL: prefer src stats, fall back to dst
        if ip_str in ttl_src.index:
            ttl_mean = _safe_float(ttl_src.at[ip_str, "mean"], 64.0)
            ttl_var  = _safe_float(ttl_src.at[ip_str, "var"], 0.0)
        elif ip_str in ttl_dst.index:
            ttl_mean = _safe_float(ttl_dst.at[ip_str, "mean"], 64.0)
            ttl_var  = _safe_float(ttl_dst.at[ip_str, "var"], 0.0)
        else:
            ttl_mean, ttl_var = 64.0, 0.0

        is_priv = _is_private_ip(ip_str)

        node_features[ip_id, 0] = math.log1p(out_deg)                        # 0: log out-degree
        node_features[ip_id, 1] = math.log1p(in_deg)                         # 1: log in-degree
        node_features[ip_id, 2] = port_ent                                   # 2: dst port entropy
        node_features[ip_id, 3] = ttl_mean / 255.0                           # 3: normalised TTL
        node_features[ip_id, 4] = math.log1p(max(ttl_var, 0.0))             # 4: TTL variance
        node_features[ip_id, 5] = is_priv                                    # 5: private network flag
        node_features[ip_id, 6] = math.log1p(_safe_float(bytes_src.get(ip_str, 0.0))) # 6: log bytes sent
        node_features[ip_id, 7] = math.log1p(_safe_float(bytes_dst.get(ip_str, 0.0))) # 7: log bytes received
        node_features[ip_id, 8] = _safe_float(syn_src.get(ip_str, 0.0)) / max(out_deg, 1.0) # 8: SYN ratio sent
        node_features[ip_id, 9] = _safe_float(ack_src.get(ip_str, 0.0)) / max(out_deg, 1.0) # 9: ACK ratio sent
        node_features[ip_id, 10] = _safe_float(rst_src.get(ip_str, 0.0)) / max(out_deg, 1.0) # 10: RST ratio sent
        node_features[ip_id, 11] = float(unique_dsts_per_src.get(ip_str, 0)) # 11: unique peers contacted (scanning)
        node_features[ip_id, 12] = float(unique_srcs_per_dst.get(ip_str, 0)) # 12: unique peers received from
        node_features[ip_id, 13] = _safe_float(bytes_src.get(ip_str, 0.0)) / max(out_deg, 1.0) / 1500.0 # 13: avg pkt size
        node_features[ip_id, 14] = _safe_float(retrans_src.get(ip_str, 0.0)) / max(out_deg, 1.0) # 14: host retrans rate
        node_features[ip_id, 15] = _safe_float(win_src.get(ip_str, 1024.0)) / 65535.0 # 15: norm TCP window

    x = torch.tensor(node_features, dtype=torch.float32)

    # 4. Compute Grounded Telemetry Target for this snapshot
    # [overall_port_entropy, overall_syn_ratio, log_total_bytes]
    all_ports = window_df["dst_port"] if "dst_port" in window_df else pd.Series()
    win_entropy = _safe_float(_compute_entropy(all_ports), 0.0)
    win_syn_ratio = _safe_float(total_syn_count / max(total_syn_count + total_ack_count, 1.0), 0.0)
    win_log_bytes = math.log1p(max(total_bytes_window, 0.0))

    grounded_target = torch.tensor([win_entropy, win_syn_ratio, win_log_bytes], dtype=torch.float32)

    return NetworkGraphSnapshot(
        window_id=window_id,
        start_time=start_time,
        end_time=end_time,
        num_nodes=total_registered_nodes,
        edge_index=edge_index,
        x=x,
        edge_attr=edge_attr,
        node_ips=node_ips,
        grounded_dynamics=grounded_target,
    )

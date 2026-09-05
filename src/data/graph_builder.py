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
        return NetworkGraphSnapshot(
            window_id=window_id,
            start_time=start_time,
            end_time=end_time,
            num_nodes=registry.size(),
            edge_index=torch.empty((2, 0), dtype=torch.long),
            x=torch.zeros((max(registry.size(), 1), 16), dtype=torch.float32),
            edge_attr=torch.empty((0, 12), dtype=torch.float32),
            node_ips=[registry.id_to_ip.get(i, f"ip_{i}") for i in range(max(registry.size(), 1))],
            grounded_dynamics=torch.zeros(3, dtype=torch.float32),
        )

    # 1. Register all active IPs in registry
    src_ips = window_df["src_ip"].astype(str).tolist()
    dst_ips = window_df["dst_ip"].astype(str).tolist()
    for ip in set(src_ips + dst_ips):
        registry.get_or_create(ip)

    total_registered_nodes = registry.size()
    node_ips = [registry.id_to_ip[i] for i in range(total_registered_nodes)]

    # 2. Aggregate flows by (src_ip, dst_ip) to construct directed edges
    grouped_edges = window_df.groupby(["src_ip", "dst_ip"])

    src_indices = []
    dst_indices = []
    edge_features_list = []

    total_syn_count = 0
    total_ack_count = 0
    total_bytes_window = 0

    for (s_ip, d_ip), edge_rows in grouped_edges:
        s_idx = registry.ip_to_id[str(s_ip)]
        d_idx = registry.ip_to_id[str(d_ip)]
        src_indices.append(s_idx)
        dst_indices.append(d_idx)

        # Edge aggregation statistics
        n_pkts = len(edge_rows)
        bytes_sum = float(edge_rows["payload_size"].sum() if "payload_size" in edge_rows else n_pkts * 64)
        total_bytes_window += bytes_sum

        syn_flags = float(edge_rows["flag_syn"].sum() if "flag_syn" in edge_rows else 0)
        ack_flags = float(edge_rows["flag_ack"].sum() if "flag_ack" in edge_rows else 0)
        rst_flags = float(edge_rows["flag_rst"].sum() if "flag_rst" in edge_rows else 0)
        fin_flags = float(edge_rows["flag_fin"].sum() if "flag_fin" in edge_rows else 0)

        total_syn_count += syn_flags
        total_ack_count += ack_flags

        retrans = float(edge_rows["is_retransmission"].sum() if "is_retransmission" in edge_rows else 0)

        # Edge feature vector (12 dimensions)
        feat = [
            math.log1p(n_pkts),                               # 0: log packet count
            math.log1p(bytes_sum),                            # 1: log byte volume
            syn_flags / max(n_pkts, 1),                       # 2: syn ratio
            ack_flags / max(n_pkts, 1),                       # 3: ack ratio
            rst_flags / max(n_pkts, 1),                       # 4: rst ratio
            fin_flags / max(n_pkts, 1),                       # 5: fin ratio
            retrans / max(n_pkts, 1),                         # 6: retransmission rate
            float(edge_rows["dst_port"].nunique() if "dst_port" in edge_rows else 1), # 7: unique dst ports
            float(edge_rows["ttl"].mean() if "ttl" in edge_rows else 64.0),           # 8: mean ttl
            float(edge_rows["ttl"].std() if "ttl" in edge_rows and len(edge_rows) > 1 else 0.0), # 9: ttl std
            float(edge_rows["tcp_window"].mean() if "tcp_window" in edge_rows else 1024.0),     # 10: mean win
            1.0 if (s_ip.startswith("10.") or s_ip.startswith("192.168.")) else 0.0,           # 11: internal
        ]
        edge_features_list.append(feat)

    if src_indices:
        edge_index = torch.tensor([src_indices, dst_indices], dtype=torch.long)
        edge_attr = torch.tensor(edge_features_list, dtype=torch.float32)
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)
        edge_attr = torch.empty((0, 12), dtype=torch.float32)

    # 3. Compute Node Feature Matrix X [total_nodes, 16]
    # Fully vectorized: one groupby per role instead of per-IP filter loops.
    node_features = np.zeros((total_registered_nodes, 16), dtype=np.float32)

    wdf = window_df.copy()
    wdf["_src_str"] = wdf["src_ip"].astype(str)
    wdf["_dst_str"] = wdf["dst_ip"].astype(str)

    # Out-degree (packets sent per source IP)
    src_counts = wdf["_src_str"].value_counts()
    dst_counts = wdf["_dst_str"].value_counts()

    # Port entropy per source: groupby src → list of dst_ports → entropy
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

    # TTL mean & variance per IP (both src and dst)
    if "ttl" in wdf.columns:
        ttl_src = wdf.groupby("_src_str")["ttl"].agg(["mean", "var"])
        ttl_dst = wdf.groupby("_dst_str")["ttl"].agg(["mean", "var"])
    else:
        ttl_src = ttl_dst = pd.DataFrame(columns=["mean", "var"])

    for ip_str, ip_id in registry.ip_to_id.items():
        out_deg = float(src_counts.get(ip_str, 0))
        in_deg  = float(dst_counts.get(ip_str, 0))
        port_ent = float(port_entropy_per_src.get(ip_str, 0.0))

        # TTL: prefer src stats, fall back to dst
        if ip_str in ttl_src.index:
            ttl_mean = float(ttl_src.at[ip_str, "mean"])
            ttl_var  = float(ttl_src.at[ip_str, "var"] or 0.0)
        elif ip_str in ttl_dst.index:
            ttl_mean = float(ttl_dst.at[ip_str, "mean"])
            ttl_var  = float(ttl_dst.at[ip_str, "var"] or 0.0)
        else:
            ttl_mean, ttl_var = 64.0, 0.0

        is_priv = 1.0 if (ip_str.startswith("10.") or ip_str.startswith("192.168.") or ip_str.startswith("172.16.")) else 0.0

        node_features[ip_id, 0] = math.log1p(out_deg)       # 0: log out-degree
        node_features[ip_id, 1] = math.log1p(in_deg)        # 1: log in-degree
        node_features[ip_id, 2] = port_ent                  # 2: dst port entropy
        node_features[ip_id, 3] = ttl_mean / 255.0          # 3: normalised TTL
        node_features[ip_id, 4] = math.log1p(ttl_var)       # 4: TTL variance
        node_features[ip_id, 5] = is_priv                   # 5: private network flag
        # Dimensions 6-15: reserved for dynamic GRU node memory bank

    x = torch.tensor(node_features, dtype=torch.float32)

    # 4. Compute Grounded Telemetry Target for this snapshot
    # [overall_port_entropy, overall_syn_ratio, log_total_bytes]
    all_ports = window_df["dst_port"] if "dst_port" in window_df else pd.Series()
    win_entropy = _compute_entropy(all_ports)
    win_syn_ratio = total_syn_count / max(total_syn_count + total_ack_count, 1.0)
    win_log_bytes = math.log1p(total_bytes_window)

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

"""
src/data module exports.
"""

from src.data.clean_cicids import clean_dataframe, clean_cicids_file
from src.data.graph_builder import (
    PersistentNodeRegistry,
    build_graph_for_window,
    NetworkGraphSnapshot,
)
from src.data.flow_features import (
    canonical_flow_id,
    aggregate_packets_to_flows,
)

# Lazy import for Scapy-dependent modules to eliminate 40s startup delays on Windows
def __getattr__(name: str):
    if name in ("extract_packet_features", "add_flow_level_derived_features"):
        import src.data.packet_features as pf
        return getattr(pf, name)
    if name == "capture_live_telemetry":
        import src.data.live_sniffer as ls
        return getattr(ls, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "clean_dataframe",
    "clean_cicids_file",
    "PersistentNodeRegistry",
    "build_graph_for_window",
    "NetworkGraphSnapshot",
    "extract_packet_features",
    "add_flow_level_derived_features",
    "canonical_flow_id",
    "aggregate_packets_to_flows",
    "capture_live_telemetry",
]

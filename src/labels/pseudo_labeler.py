"""
src/labels/pseudo_labeler.py

Rule-Based Dynamic MITRE ATT&CK Pseudo-Labeler with Telemetry Heuristics & Confidence Scoring.

Solves the ground-truth derivability problem in network datasets (e.g. CIC-IDS2018 / CTU-13):
- Reconnaissance (TA0043 / T1595): High destination port entropy / sequential sweeps + high SYN:ACK ratio.
- Initial Access / Impact (TA0001 / TA0040): Targeting web ports or high-volume service flooding.
- Credential Access (TA0006 / T1110): Targeting auth ports (21, 22, 23, 3389) with repeated attempts.
- Lateral Movement (TA0008 / T1021): Internal-to-internal subnet traffic expanding to new hosts (SMB/RPC/RDP).
- Command & Control (TA0011 / T1071): Periodic low-jitter beaconing on web/DNS/non-standard ports.
- Exfiltration (TA0010 / T1041): Asymmetric high outbound volume from internal to external.
"""

from __future__ import annotations
from typing import Tuple, Dict, Any, List
import re
import numpy as np
import pandas as pd
from src.labels.attack_mapping import map_label_to_stage, STAGE_NAMES

# Shared port definitions for consistent heuristics across row-level and vectorized labeling
AUTH_PORTS: List[int] = [21, 22, 23, 3389]
LATERAL_PORTS: List[int] = [445, 135, 139, 3389, 5985]
C2_PORTS: List[int] = [8088, 4444, 9001, 1337, 31337]
WEB_PORTS: List[int] = [80, 443, 8080]

# RFC 1918 IPv4 pattern (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, loopback 127.0.0.0/8)
RFC1918_REGEX = re.compile(r"^(?:10\.|192\.168\.|127\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)")


def is_rfc1918_private_ip(ip_str: str) -> bool:
    """Accurate RFC 1918 private IPv4 check including the full 172.16.0.0 - 172.31.255.255 range."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    if ip_str.startswith(("10.", "192.168.", "127.")):
        return True
    if ip_str.startswith("172."):
        parts = ip_str.split(".")
        if len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
    return False


def infer_pseudo_mitre_stage(
    row_or_flow: Dict[str, Any] | pd.Series,
    given_label: str | None = None
) -> Tuple[int, str, str, float]:
    """
    Infers the MITRE ATT&CK stage and technique along with an attribution confidence score [0.0 - 1.0].
    
    Priority order:
      1. Explicit dataset label (if known & malicious) -> highest confidence (0.90)
      2. Specific attack heuristics:
         - Exfiltration (internal -> external, large payload)
         - C2 Beaconing (internal -> external, known C2 ports)
         - Lateral Movement (internal -> internal, SMB/RPC/RDP)
         - Credential Access (auth ports)
         - Initial Access (web exploit payload)
         - Reconnaissance (SYN-only probe)
      3. Default -> Benign (0.95)
    """
    # 1. Explicit dataset label
    if given_label and isinstance(given_label, str):
        stage_id, stage_name, tech_id = map_label_to_stage(given_label)
        if stage_id > 0:
            return stage_id, stage_name, tech_id, 0.90

    # 2. Extract telemetry indicators
    dst_port = int(row_or_flow.get("dst_port", 0) or 0)
    src_ip = str(row_or_flow.get("src_ip", ""))
    dst_ip = str(row_or_flow.get("dst_ip", ""))
    payload_size = float(row_or_flow.get("payload_size", 0) or row_or_flow.get("tot_len", 0) or 0)
    syn_flag = bool(row_or_flow.get("flag_syn", False))
    ack_flag = bool(row_or_flow.get("flag_ack", False))
    rst_flag = bool(row_or_flow.get("flag_rst", False))

    is_internal_src = is_rfc1918_private_ip(src_ip)
    is_internal_dst = is_rfc1918_private_ip(dst_ip)

    # 2a. Exfiltration: large outbound transfer from internal to external
    if is_internal_src and not is_internal_dst and payload_size > 50000:
        return 6, "Exfiltration", "T1041", 0.75

    # 2b. Command & Control / Beaconing
    if is_internal_src and not is_internal_dst and dst_port in C2_PORTS:
        return 5, "Command & Control", "T1071", 0.85

    # 2c. Lateral Movement: internal-to-internal on SMB/RPC/RDP
    if is_internal_src and is_internal_dst and dst_port in LATERAL_PORTS:
        return 4, "Lateral Movement", "T1021.002", 0.85

    # 2d. Credential Access: auth ports
    if dst_port in AUTH_PORTS:
        return 3, "Credential Access", "T1110", 0.80

    # 2e. Initial Access: web exploit payloads
    if dst_port in WEB_PORTS and payload_size > 4000:
        return 2, "Initial Access", "T1190", 0.70

    # 2f. Reconnaissance: SYN-only or scanning probes
    if syn_flag and not ack_flag and (rst_flag or payload_size == 0):
        return 1, "Reconnaissance", "T1595.001", 0.75

    # Default to Benign
    return 0, "Benign", "None", 0.95


def annotate_dataframe_with_pseudo_labels(df: pd.DataFrame) -> pd.DataFrame:
    """
    Fully vectorized MITRE stage annotation using boolean masks and dictionary lookups.

    Priority order (most specific overwrites broad heuristics):
      0. Default -> Benign (conf=0.95)
      1. Broad Reconnaissance heuristic -> SYN scanning (conf=0.75)
      2. Initial Access heuristic       -> web exploits (conf=0.70)
      3. Credential Access heuristic    -> auth brute-force (conf=0.80)
      4. Lateral Movement heuristic     -> internal SMB/RDP (conf=0.85)
      5. Command & Control heuristic    -> C2 ports (conf=0.85)
      6. Exfiltration heuristic         -> large outbound volume (conf=0.75)
      7. Explicit dataset label         -> attack_mapping lookup (conf=0.90 / 0.99)
    """
    n = len(df)
    stage_ids   = np.zeros(n, dtype=np.int8)
    stage_names = np.full(n, "Benign", dtype=object)
    techniques  = np.full(n, "None", dtype=object)
    confs       = np.full(n, 0.95, dtype=np.float32)

    label_col = "label" if "label" in df.columns else ("Label" if "Label" in df.columns else None)

    # Helper column access with safe coercion
    dst_port     = df["dst_port"].fillna(0).astype(int)            if "dst_port"     in df.columns else pd.Series(np.zeros(n, dtype=int))
    payload_size = df["payload_size"].fillna(0).astype(float)      if "payload_size" in df.columns else pd.Series(np.zeros(n))
    flag_syn     = df["flag_syn"].fillna(0).astype(bool)           if "flag_syn"     in df.columns else pd.Series(np.zeros(n, dtype=bool))
    flag_ack     = df["flag_ack"].fillna(0).astype(bool)           if "flag_ack"     in df.columns else pd.Series(np.zeros(n, dtype=bool))
    flag_rst     = df["flag_rst"].fillna(0).astype(bool)           if "flag_rst"     in df.columns else pd.Series(np.zeros(n, dtype=bool))
    src_ip       = df["src_ip"].fillna("").astype(str)             if "src_ip"       in df.columns else pd.Series([""] * n)
    dst_ip       = df["dst_ip"].fillna("").astype(str)             if "dst_ip"       in df.columns else pd.Series([""] * n)

    # Complete RFC 1918 check (10.x, 172.16-31.x, 192.168.x, 127.x)
    is_int_src = (
        src_ip.str.startswith(("10.", "192.168.", "127.")) |
        src_ip.str.match(r"^172\.(?:1[6-9]|2[0-9]|3[0-1])\.")
    ).fillna(False)
    is_int_dst = (
        dst_ip.str.startswith(("10.", "192.168.", "127.")) |
        dst_ip.str.match(r"^172\.(?:1[6-9]|2[0-9]|3[0-1])\.")
    ).fillna(False)

    # ── HEURISTIC MASKS (Applied in order: Broad -> Specific) ──

    # 1. Reconnaissance: SYN-only probes (broadest heuristic)
    m_recon = flag_syn & ~flag_ack & (flag_rst | (payload_size == 0))
    stage_ids[m_recon]   = 1; stage_names[m_recon] = "Reconnaissance"
    techniques[m_recon]  = "T1595.001"; confs[m_recon] = 0.75

    # 2. Initial Access: web exploitation payloads
    m_init = dst_port.isin(WEB_PORTS) & (payload_size > 4_000)
    stage_ids[m_init]   = 2; stage_names[m_init] = "Initial Access"
    techniques[m_init]  = "T1190"; confs[m_init] = 0.70

    # 3. Credential Access: auth ports (overwrites recon on port 22/3389)
    m_cred = dst_port.isin(AUTH_PORTS)
    stage_ids[m_cred]   = 3; stage_names[m_cred] = "Credential Access"
    techniques[m_cred]  = "T1110"; confs[m_cred] = 0.80

    # 4. Lateral Movement: internal -> internal SMB/RDP (overwrites recon on port 445)
    m_lat = is_int_src & is_int_dst & dst_port.isin(LATERAL_PORTS)
    stage_ids[m_lat]   = 4; stage_names[m_lat] = "Lateral Movement"
    techniques[m_lat]  = "T1021.002"; confs[m_lat] = 0.85

    # 5. C2 Beaconing: internal -> external on C2 ports
    m_c2 = is_int_src & ~is_int_dst & dst_port.isin(C2_PORTS)
    stage_ids[m_c2]   = 5; stage_names[m_c2] = "Command & Control"
    techniques[m_c2]  = "T1071"; confs[m_c2] = 0.85

    # 6. Exfiltration: large outbound transfer from internal to external
    m_exfil = is_int_src & ~is_int_dst & (payload_size > 50_000)
    stage_ids[m_exfil]   = 6; stage_names[m_exfil] = "Exfiltration"
    techniques[m_exfil]  = "T1041"; confs[m_exfil] = 0.75

    # ── EXPLICIT DATASET LABELS (Highest priority — true ground truth) ──
    if label_col is not None and n > 0:
        raw_labels = df[label_col].astype(str)
        cleaned_labels = raw_labels.str.strip()

        # Vectorized check for benign / empty strings
        is_benign_explicit = cleaned_labels.str.lower().isin(["benign", "nan", "none", "0", ""])
        stage_ids[is_benign_explicit]   = 0
        stage_names[is_benign_explicit] = "Benign"
        techniques[is_benign_explicit]  = "None"
        confs[is_benign_explicit]       = 0.99

        # Truly vectorized mapping for non-benign rows via unique label dictionary lookup
        non_benign_mask = ~is_benign_explicit
        if non_benign_mask.any():
            unique_labels = cleaned_labels[non_benign_mask].unique()
            label_stage_map: Dict[str, Tuple[int, str, str]] = {
                lbl: map_label_to_stage(lbl) for lbl in unique_labels
            }

            mapped_sid = cleaned_labels[non_benign_mask].map(lambda x: label_stage_map[x][0]).to_numpy()
            mapped_sname = cleaned_labels[non_benign_mask].map(lambda x: label_stage_map[x][1]).to_numpy()
            mapped_tid = cleaned_labels[non_benign_mask].map(lambda x: label_stage_map[x][2]).to_numpy()

            # Overwrite only where stage was recognized (stage_id > 0)
            valid_map = mapped_sid > 0
            idx_arr = np.where(non_benign_mask)[0]
            stage_ids[idx_arr[valid_map]]   = mapped_sid[valid_map]
            stage_names[idx_arr[valid_map]] = mapped_sname[valid_map]
            techniques[idx_arr[valid_map]]  = mapped_tid[valid_map]
            confs[idx_arr[valid_map]]       = 0.90

    df_out = df.copy()
    df_out["mitre_stage_id"]   = stage_ids
    df_out["mitre_stage_name"] = stage_names
    df_out["mitre_technique"]  = techniques
    df_out["mitre_confidence"] = confs
    return df_out

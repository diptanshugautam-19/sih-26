"""
attack_mapping.py — Single source of truth for mapping dataset labels to MITRE ATT&CK stages.

Stages:
0: Benign
1: Reconnaissance (T1595)
2: Initial Access / Impact (T1498, T1190)
3: Credential Access (T1110)
4: Lateral Movement (T1021)
5: Command & Control (T1071)
6: Exfiltration (T1041)
"""

from __future__ import annotations
import logging
import re
from typing import Dict, Tuple, Set

logger = logging.getLogger(__name__)

STAGE_NAMES = {
    0: "Benign",
    1: "Reconnaissance",
    2: "Initial Access",
    3: "Credential Access",
    4: "Lateral Movement",
    5: "Command & Control",
    6: "Exfiltration",
}

# Mapping: Dataset Label (normalized lowercase & stripped) -> (Stage_ID, Stage_Name, MITRE_Technique_ID)
RAW_LABEL_TO_ATTACK_STAGE: Dict[str, Tuple[int, str, str]] = {
    # Benign
    "benign": (0, "Benign", "None"),
    "normal": (0, "Benign", "None"),
    "background": (0, "Benign", "None"),

    # Reconnaissance
    "portscan": (1, "Reconnaissance", "T1595.001"),
    "reconnaissance": (1, "Reconnaissance", "T1595"),
    "ipsweep": (1, "Reconnaissance", "T1595.002"),
    "nmap": (1, "Reconnaissance", "T1595"),

    # DoS / DDoS -> Initial Access & Service Impact
    "ddos attacks-loic-http": (2, "Initial Access", "T1498"),
    "ddos attack-loic-udp": (2, "Initial Access", "T1498"),
    "ddos attack-hoic": (2, "Initial Access", "T1498"),
    "dos attacks-slowloris": (2, "Initial Access", "T1498.001"),
    "dos attacks-slowhttptest": (2, "Initial Access", "T1498.001"),
    "dos attacks-hulk": (2, "Initial Access", "T1498"),
    "dos attacks-goldeneye": (2, "Initial Access", "T1498"),
    "ddos": (2, "Initial Access", "T1498"),
    "dos": (2, "Initial Access", "T1498"),

    # Web attacks / Infiltration
    "brute force -web": (2, "Initial Access", "T1190"),
    "brute force -xss": (2, "Initial Access", "T1190"),
    "sql injection": (2, "Initial Access", "T1190"),
    "infilteration": (4, "Lateral Movement", "T1021"),
    "infiltration": (4, "Lateral Movement", "T1021"),

    # Credential Access / Brute Force
    "ftp-bruteforce": (3, "Credential Access", "T1110"),
    "ssh-bruteforce": (3, "Credential Access", "T1110"),
    "ftp-patator": (3, "Credential Access", "T1110.001"),
    "ssh-patator": (3, "Credential Access", "T1110.001"),

    # Botnet / C2 / Exfil (CTU-13 & CIC-IDS2018 Bot)
    "bot": (5, "Command & Control", "T1071.001"),
    "botnet": (5, "Command & Control", "T1071.001"),
    "c&c": (5, "Command & Control", "T1071"),
    "cc": (5, "Command & Control", "T1071"),
    "c&c-torii": (5, "Command & Control", "T1071"),
    "c&c-mirai": (5, "Command & Control", "T1071"),
    "exfiltration": (6, "Exfiltration", "T1041"),
}

# Substring / pattern fallback rules for CTU-13 .binetflow and compound label strings
# Order matters: check benign first, then specific attack patterns
SUBSTRING_RULES: list[Tuple[re.Pattern, Tuple[int, str, str]]] = [
    (re.compile(r"\b(normal|background)\b", re.IGNORECASE), (0, "Benign", "None")),
    (re.compile(r"\b(botnet|c&c|-cc\b|neris|rbot|virut|menti|sogou|murlo)\b", re.IGNORECASE), (5, "Command & Control", "T1071")),
    (re.compile(r"\b(portscan|nmap|ipsweep|scan)\b", re.IGNORECASE), (1, "Reconnaissance", "T1595")),
    (re.compile(r"\b(bruteforce|patator|password)\b", re.IGNORECASE), (3, "Credential Access", "T1110")),
    (re.compile(r"\b(ddos|dos|slowloris|goldeneye|hulk|loic|hoic)\b", re.IGNORECASE), (2, "Initial Access", "T1498")),
    (re.compile(r"\b(infilteration|infiltration|lateral)\b", re.IGNORECASE), (4, "Lateral Movement", "T1021")),
    (re.compile(r"\b(exfil|exfiltration)\b", re.IGNORECASE), (6, "Exfiltration", "T1041")),
]

# Telemetry on unmapped labels to eliminate silent fallthrough bugs
UNMAPPED_LABEL_COUNTS: Dict[str, int] = {}


def get_unmapped_labels() -> Dict[str, int]:
    """Returns telemetry of labels that fell through to Benign default."""
    return dict(UNMAPPED_LABEL_COUNTS)


def reset_unmapped_labels() -> None:
    """Resets the unmapped labels telemetry."""
    UNMAPPED_LABEL_COUNTS.clear()


def normalize_label(label: str) -> str:
    """Safely cleans dataset labels handling trailing whitespace, case, and encoding."""
    if not isinstance(label, str):
        return "benign"
    cleaned = label.strip().lower()
    # If CTU-13 style "flow=From-Botnet...", strip the prefix
    if cleaned.startswith("flow="):
        cleaned = cleaned[5:]
    return cleaned


def map_label_to_stage(label: str) -> Tuple[int, str, str]:
    """
    Given a dataset label string, returns (stage_id, stage_name, mitre_technique).
    Supports exact matching, CTU-13 substring/regex patterns, and tracks unmapped labels.
    """
    cleaned = normalize_label(label)

    # 1. Exact match in standard dictionary
    if cleaned in RAW_LABEL_TO_ATTACK_STAGE:
        return RAW_LABEL_TO_ATTACK_STAGE[cleaned]

    # 2. Pattern / Substring matching (crucial for CTU-13 .binetflow descriptive names)
    for pattern, stage_info in SUBSTRING_RULES:
        if pattern.search(cleaned):
            return stage_info

    # 3. Telemetry tracking for unmapped labels (prevent silent fallthrough)
    if cleaned not in ("benign", "none", "nan", "", "0"):
        cnt = UNMAPPED_LABEL_COUNTS.get(cleaned, 0)
        UNMAPPED_LABEL_COUNTS[cleaned] = cnt + 1
        if cnt == 0:
            logger.warning(
                f"[attack_mapping] Unmapped label encountered: '{label}' (cleaned: '{cleaned}'). "
                f"Defaulting to (0, 'Benign', 'None'). Check if new attack variant needs mapping."
            )

    return (0, "Benign", "None")


def is_malicious(label: str) -> bool:
    """Returns True if the label represents any malicious stage, False for benign."""
    stage_id, _, _ = map_label_to_stage(label)
    return stage_id > 0

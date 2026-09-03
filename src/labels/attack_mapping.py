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

from typing import Dict, Tuple

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


def normalize_label(label: str) -> str:
    """Safely cleans dataset labels handling trailing whitespace, case, and encoding."""
    if not isinstance(label, str):
        return "benign"
    return label.strip().lower()


def map_label_to_stage(label: str) -> Tuple[int, str, str]:
    """
    Given a dataset label string, returns (stage_id, stage_name, mitre_technique).
    Defaults to (0, 'Benign', 'None') if unknown.
    """
    cleaned = normalize_label(label)
    return RAW_LABEL_TO_ATTACK_STAGE.get(cleaned, (0, "Benign", "None"))


def is_malicious(label: str) -> bool:
    """Returns True if the label represents any malicious stage, False for benign."""
    stage_id, _, _ = map_label_to_stage(label)
    return stage_id > 0

"""
scripts/download_capec.py

Downloads the official MITRE CAPEC (Common Attack Pattern Enumeration and Classification)
dataset in multiple formats (STIX 2.1 JSON, Official XML, and Normalized CSV) for
GNN training, attack path modeling, and proactive cyber defense.
"""

import os
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

# Repo root
REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "data" / "raw" / "capec"

URLS = {
    "stix-capec.json": "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json",
    "capec_latest.xml": "https://capec.mitre.org/data/xml/capec_latest.xml",
}


def download_file(url: str, dest_path: Path) -> bool:
    """Download a file with real-time transfer progress."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if dest_path.exists() and dest_path.stat().st_size > 100_000:
        print(f"  [CACHE HIT] {dest_path.name} already exists ({dest_path.stat().st_size / 1024:.1f} KB)")
        return True

    print(f"  [DOWNLOADING] {url}")
    print(f"  -> Destination: {dest_path}")
    t0 = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberDefenceWorldModel/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest_path, "wb") as out_file:
            total_size = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            chunk_size = 256 * 1024

            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                out_file.write(chunk)
                downloaded += len(chunk)
                kb_done = downloaded / 1024
                if total_size > 0:
                    pct = (downloaded / total_size) * 100
                    kb_total = total_size / 1024
                    sys.stdout.write(f"\r  Progress: {kb_done:.1f} / {kb_total:.1f} KB ({pct:.1f}%)")
                else:
                    sys.stdout.write(f"\r  Progress: {kb_done:.1f} KB")
                sys.stdout.flush()

        elapsed = max(time.time() - t0, 0.01)
        print(f"\n  [OK] Saved {dest_path.name} ({dest_path.stat().st_size / 1024:.1f} KB in {elapsed:.2f}s)")
        return True
    except Exception as e:
        print(f"\n  [ERROR] Failed to download {url}: {e}")
        return False


def generate_capec_csv(xml_path: Path, csv_path: Path):
    """Parses capec_latest.xml and produces a normalized capec.csv."""
    import pandas as pd

    print("  [EXTRACTING] Generating normalized capec.csv from official XML...")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    rows = []
    for p in root.findall(".//{*}Attack_Pattern"):
        pid = p.attrib.get("ID", "")
        name = p.attrib.get("Name", "")
        abstraction = p.attrib.get("Abstraction", "Standard")
        status = p.attrib.get("Status", "")

        desc_el = p.find("{*}Description")
        desc = desc_el.text.strip() if desc_el is not None and desc_el.text else ""

        sev_el = p.find("{*}Typical_Severity")
        sev = sev_el.text.strip() if sev_el is not None and sev_el.text else "Unknown"

        lik_el = p.find("{*}Likelihood_Of_Attack")
        lik = lik_el.text.strip() if lik_el is not None and lik_el.text else "Unknown"

        cwes = [w.attrib.get("CWE_ID", "") for w in p.findall(".//{*}Related_Weakness") if w.attrib.get("CWE_ID")]
        related_capecs = [
            f"{r.attrib.get('Nature', '')}:{r.attrib.get('CAPEC_ID', '')}"
            for r in p.findall(".//{*}Related_Attack_Pattern")
            if r.attrib.get("CAPEC_ID")
        ]

        # Execution steps count
        steps = p.findall(".//{*}Attack_Step")
        prereqs = p.findall(".//{*}Prerequisite")

        rows.append({
            "CAPEC_ID": f"CAPEC-{pid}",
            "ID_Num": int(pid) if pid.isdigit() else 0,
            "Name": name,
            "Abstraction": abstraction,
            "Status": status,
            "Typical_Severity": sev,
            "Likelihood_Of_Attack": lik,
            "Execution_Steps_Count": len(steps),
            "Prerequisites_Count": len(prereqs),
            "Related_CWEs": ";".join(cwes),
            "Related_CAPECs": ";".join(related_capecs),
            "Description": desc,
        })

    df = pd.DataFrame(rows)
    df.sort_values(by="ID_Num", inplace=True)
    df.to_csv(csv_path, index=False)
    print(f"  [OK] Generated {csv_path.name} with {len(df)} attack patterns ({csv_path.stat().st_size / 1024:.1f} KB)")


def main():
    print("\n" + "=" * 70)
    print("  DOWNLOADING OFFICIAL MITRE CAPEC DATASET FOR GNN TRAINING")
    print("=" * 70)

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Download STIX 2.1 & XML
    for fname, url in URLS.items():
        dest = OUT_DIR / fname
        download_file(url, dest)

    # 2. Generate CSV
    xml_path = OUT_DIR / "capec_latest.xml"
    csv_path = OUT_DIR / "capec.csv"
    if xml_path.exists():
        generate_capec_csv(xml_path, csv_path)

    print("\n[ALL COMPLETE] Datasets available in:", OUT_DIR.resolve())
    for f in sorted(OUT_DIR.glob("*")):
        print(f"  - {f.name} ({f.stat().st_size / 1024:.1f} KB)")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()

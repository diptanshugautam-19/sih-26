"""
scripts/train_nvd_cve_graph.py

Downloads the official NVD/CVE vulnerability database (JSON feed), converts the raw records
into a PyTorch Geometric Graph (Nodes & Edges), and trains a Graph Neural Network (GNN/GAT)
with real-time status checkpoints at every step.

Pipeline Stages:
  [CHECKPOINT 1/5] Download & Decompress NVD/CVE JSON Feed
  [CHECKPOINT 2/5] Parse CVEs, CWE Weaknesses & Affected Software into Graph Entities
  [CHECKPOINT 3/5] Construct PyTorch Geometric Data Object (Nodes, Edges, Splits)
  [CHECKPOINT 4/5] Initialize Graph Attention Network (GAT) & GPU Acceleration
  [CHECKPOINT 5/5] Train GNN with Per-Epoch Evaluation, VRAM Tracking & Checkpoint Saving
"""

from __future__ import annotations
import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Force UTF-8 on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import time
import json
import lzma
import logging
import argparse
import urllib.request
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from torch_geometric.data import Data
from torch_geometric.nn import GATConv

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 1: DOWNLOAD & CACHE
# ─────────────────────────────────────────────────────────────────────────────
def download_nvd_cve_feed(year: int = 2024, cache_dir: Path | None = None) -> Path:
    """
    Downloads and decompresses the annual NVD CVE JSON feed into cache_dir.
    Uses the verified official NVD JSON mirror (fkie-cad/nvd-json-data-feeds).
    """
    if cache_dir is None:
        cache_dir = REPO_ROOT / "data" / "raw" / "nvd"
    cache_dir.mkdir(parents=True, exist_ok=True)

    json_path = cache_dir / f"CVE-{year}.json"
    xz_path = cache_dir / f"CVE-{year}.json.xz"

    if json_path.exists() and json_path.stat().st_size > 1024 * 1024:
        log.info(f"  [CACHE HIT] Found existing extracted JSON at: {json_path}")
        log.info(f"  Size: {json_path.stat().st_size / (1024*1024):.2f} MB")
        return json_path

    url = f"https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz"
    log.info(f"  Fetching: {url}")
    t0 = time.time()

    req = urllib.request.Request(url, headers={"User-Agent": "CyberDefenceWorldModel/1.0"})
    with urllib.request.urlopen(req, timeout=60) as response, open(xz_path, "wb") as out_file:
        total_length = response.getheader("Content-Length")
        total_bytes = int(total_length) if total_length else None
        downloaded = 0
        chunk_size = 1024 * 1024

        while True:
            chunk = response.read(chunk_size)
            if not chunk:
                break
            downloaded += len(chunk)
            out_file.write(chunk)
            if total_bytes:
                pct = (downloaded / total_bytes) * 100
                print(f"\r  Downloading: {downloaded / (1024*1024):.2f}/{total_bytes / (1024*1024):.2f} MB ({pct:.1f}%)", end="", flush=True)
            else:
                print(f"\r  Downloading: {downloaded / (1024*1024):.2f} MB", end="", flush=True)

    dl_time = time.time() - t0
    print()
    log.info(f"  Download finished in {dl_time:.1f}s ({xz_path.stat().st_size / (1024*1024):.2f} MB)")

    log.info("  Decompressing .xz archive ...")
    t1 = time.time()
    with lzma.open(xz_path, "rb") as f_in, open(json_path, "wb") as f_out:
        while chunk := f_in.read(2 * 1024 * 1024):
            f_out.write(chunk)

    ext_time = time.time() - t1
    log.info(f"  Decompressed to {json_path.name} in {ext_time:.1f}s ({json_path.stat().st_size / (1024*1024):.2f} MB)")
    return json_path


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 2: PARSE RAW JSON INTO GRAPH ENTITIES
# ─────────────────────────────────────────────────────────────────────────────
def parse_nvd_json_to_entities(json_path: Path, max_items: int | None = None) -> dict:
    """
    Parses raw NVD JSON into node features, labels, and entity mappings.
    Extracts:
      - CVE nodes with CVSS 3.1 features (BaseScore, Exploitability, Vector, etc.)
      - CWE weakness nodes
      - CPE software/vendor nodes
      - Bipartite and co-occurrence edges
    """
    log.info(f"  Reading JSON: {json_path.name} ...")
    t0 = time.time()
    with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    cve_items = data.get("cve_items", data.get("CVE_Items", data.get("vulnerabilities", [])))
    if max_items:
        cve_items = cve_items[:max_items]

    log.info(f"  Parsed {len(cve_items):,} raw CVE items in {time.time() - t0:.2f}s")

    node_to_idx = {}
    node_types = []
    features_list = []
    labels_list = []
    cve_node_indices = []

    def get_or_create_node(node_id: str, n_type: str) -> int:
        if node_id not in node_to_idx:
            idx = len(node_to_idx)
            node_to_idx[node_id] = idx
            node_types.append(n_type)
            return idx
        return node_to_idx[node_id]

    src_edges = []
    dst_edges = []

    SEVERITY_MAP = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    AV_MAP = {"NETWORK": 0, "ADJACENT_NETWORK": 1, "ADJACENT": 1, "LOCAL": 2, "PHYSICAL": 3}

    for item in cve_items:
        cve_id = item.get("id") or item.get("cve", {}).get("id")
        if not cve_id:
            continue

        cve_idx = get_or_create_node(cve_id, "CVE")
        cve_node_indices.append(cve_idx)

        # 1. Parse CVSS v3.1 metrics
        metrics = item.get("metrics", {})
        cvss_list = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        
        base_score = 5.0
        base_sev = 1  # Medium default
        exploit_score = 5.0
        impact_score = 5.0
        av_idx = 0     # Network default
        ac_high = 0.0
        pr_idx = 0     # None
        ui_req = 0.0
        scope_changed = 0.0

        if cvss_list and isinstance(cvss_list, list):
            cvss_data = cvss_list[0].get("cvssData", {})
            base_score = float(cvss_data.get("baseScore", 5.0))
            sev_str = str(cvss_data.get("baseSeverity", "MEDIUM")).upper()
            base_sev = SEVERITY_MAP.get(sev_str, 1)

            exploit_score = float(cvss_list[0].get("exploitabilityScore", 5.0))
            impact_score = float(cvss_list[0].get("impactScore", 5.0))

            av_str = str(cvss_data.get("attackVector", "NETWORK")).upper()
            av_idx = AV_MAP.get(av_str, 0)
            ac_high = 1.0 if cvss_data.get("attackComplexity") == "HIGH" else 0.0
            pr_str = str(cvss_data.get("privilegesRequired", "NONE")).upper()
            pr_idx = 0 if pr_str == "NONE" else (1 if pr_str == "LOW" else 2)
            ui_req = 1.0 if cvss_data.get("userInteraction") == "REQUIRED" else 0.0
            scope_changed = 1.0 if cvss_data.get("scope") == "CHANGED" else 0.0

        # Build 18-dim feature vector for this CVE node
        feat = [
            1.0, 0.0, 0.0,                       # 0-2: One-hot node type [CVE, CWE, CPE]
            base_score / 10.0,                   # 3: Normalized CVSS Base Score
            exploit_score / 10.0,                # 4: Normalized Exploitability Score
            impact_score / 10.0,                 # 5: Normalized Impact Score
            1.0 if av_idx == 0 else 0.0,         # 6: Attack Vector Network
            1.0 if av_idx == 1 else 0.0,         # 7: Attack Vector Adjacent
            1.0 if av_idx == 2 else 0.0,         # 8: Attack Vector Local
            1.0 if av_idx == 3 else 0.0,         # 9: Attack Vector Physical
            ac_high,                             # 10: Complexity High
            1.0 if pr_idx == 0 else 0.0,         # 11: Privileges None
            1.0 if pr_idx == 1 else 0.0,         # 12: Privileges Low
            1.0 if pr_idx == 2 else 0.0,         # 13: Privileges High
            ui_req,                              # 14: User Interaction Required
            scope_changed,                       # 15: Scope Changed
            base_score / 10.0 * (1.0 - ac_high), # 16: Effective Exploitability Ratio
            1.0 if base_sev >= 2 else 0.0,       # 17: High/Critical Indicator
        ]
        features_list.append((cve_idx, feat, base_sev))

        # 2. Parse CWE Weaknesses & create edges
        for w in item.get("weaknesses", []):
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwe_idx = get_or_create_node(val, "CWE")
                    src_edges.extend([cve_idx, cwe_idx])
                    dst_edges.extend([cwe_idx, cve_idx])

        # 3. Parse Configurations / Affected CPE products & create edges
        for conf in item.get("configurations", []):
            for node in conf.get("nodes", []):
                for cm in node.get("cpeMatch", []):
                    cpe_crit = cm.get("criteria")
                    if cpe_crit:
                        parts = cpe_crit.split(":")
                        short_prod = f"cpe:{parts[3]}:{parts[4]}" if len(parts) > 4 else cpe_crit[:30]
                        cpe_idx = get_or_create_node(short_prod, "CPE")
                        src_edges.extend([cve_idx, cpe_idx])
                        dst_edges.extend([cpe_idx, cve_idx])

    total_nodes = len(node_to_idx)
    feat_matrix = np.zeros((total_nodes, 18), dtype=np.float32)
    labels = np.zeros(total_nodes, dtype=np.int64)

    # Populate CVE nodes
    for idx, feat, sev in features_list:
        feat_matrix[idx] = feat
        labels[idx] = sev

    # Populate CWE nodes
    for idx, n_type in enumerate(node_types):
        if n_type == "CWE":
            feat_matrix[idx, 1] = 1.0  # is_cwe flag
            labels[idx] = 1            # Medium baseline
        elif n_type == "CPE":
            feat_matrix[idx, 2] = 1.0  # is_cpe flag
            labels[idx] = 1

    return {
        "node_to_idx": node_to_idx,
        "features": feat_matrix,
        "labels": labels,
        "src_edges": src_edges,
        "dst_edges": dst_edges,
        "cve_indices": cve_node_indices,
    }


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 3: BUILD PYTORCH GEOMETRIC DATA OBJECT
# ─────────────────────────────────────────────────────────────────────────────
def build_pyg_graph(parsed: dict, train_ratio: float = 0.7, val_ratio: float = 0.15) -> Data:
    """
    Assembles node features, edge index, targets, and train/val/test masks
    into a torch_geometric.data.Data object.
    """
    x = torch.tensor(parsed["features"], dtype=torch.float32)
    y = torch.tensor(parsed["labels"], dtype=torch.long)

    if parsed["src_edges"]:
        edge_index = torch.tensor([parsed["src_edges"], parsed["dst_edges"]], dtype=torch.long)
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)

    total_nodes = x.size(0)
    cve_indices = np.array(parsed["cve_indices"])

    # Create masks over CVE nodes (evaluation focuses on predicting vulnerability severity)
    np.random.seed(42)
    perm = np.random.permutation(cve_indices)
    n_train = int(len(perm) * train_ratio)
    n_val = int(len(perm) * val_ratio)

    train_cve = perm[:n_train]
    val_cve = perm[n_train:n_train + n_val]
    test_cve = perm[n_train + n_val:]

    train_mask = torch.zeros(total_nodes, dtype=torch.bool)
    val_mask = torch.zeros(total_nodes, dtype=torch.bool)
    test_mask = torch.zeros(total_nodes, dtype=torch.bool)

    train_mask[train_cve] = True
    val_mask[val_cve] = True
    test_mask[test_cve] = True

    data = Data(x=x, edge_index=edge_index, y=y)
    data.train_mask = train_mask
    data.val_mask = val_mask
    data.test_mask = test_mask

    return data


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 4: GRAPH ATTENTION NETWORK (GAT) MODEL
# ─────────────────────────────────────────────────────────────────────────────
class CVEGNNClassifier(nn.Module):
    """
    Multi-Head Graph Attention Network for Vulnerability Knowledge Graphs.
    Propagates attention weights across CVEs, CWE taxonomies, and software configurations.
    """
    def __init__(self, in_channels: int = 18, hidden_channels: int = 64, num_classes: int = 4, heads: int = 4, dropout: float = 0.2):
        super().__init__()
        self.conv1 = GATConv(in_channels, hidden_channels // heads, heads=heads, dropout=dropout)
        self.ln1 = nn.LayerNorm(hidden_channels)
        self.conv2 = GATConv(hidden_channels, hidden_channels // heads, heads=heads, dropout=dropout)
        self.ln2 = nn.LayerNorm(hidden_channels)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_channels, 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, num_classes),
        )

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        h1 = F.elu(self.conv1(x, edge_index))
        h1 = self.ln1(h1)
        h2 = F.elu(self.conv2(h1, edge_index))
        h2 = self.ln2(h2)
        logits = self.classifier(h2)
        return logits


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 5: TRAINING LOOP WITH GPU AND CHECKPOINTS
# ─────────────────────────────────────────────────────────────────────────────
def train_nvd_gnn(
    data: Data,
    epochs: int = 10,
    lr: float = 1e-3,
    hidden_dim: int = 64,
    heads: int = 4,
    device_str: str = "auto",
    checkpoint_dir: Path | None = None,
):
    if checkpoint_dir is None:
        checkpoint_dir = REPO_ROOT / "models" / "checkpoints"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)

    if device_str == "auto":
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    else:
        device = torch.device(device_str)

    log.info(f"\n{'='*70}")
    log.info("  NVD / CVE VULNERABILITY GRAPH NEURAL NETWORK — TRAINING")
    if device.type == "cuda":
        gpu_name = torch.cuda.get_device_name(device)
        vram_gb = torch.cuda.get_device_properties(device).total_memory / (1024**3)
        log.info(f"  Hardware: {gpu_name} ({vram_gb:.2f} GB VRAM) | AMP FP16: Enabled")
        torch.backends.cudnn.benchmark = True
    else:
        log.info(f"  Hardware: CPU Mode")
    log.info(f"  Nodes: {data.num_nodes:,} | Edges: {data.num_edges:,} | Features: {data.num_node_features}")
    log.info(f"  Split -> Train: {data.train_mask.sum().item():,} | Val: {data.val_mask.sum().item():,} | Test: {data.test_mask.sum().item():,}")
    log.info(f"{'='*70}\n")

    model = CVEGNNClassifier(
        in_channels=data.num_node_features,
        hidden_channels=hidden_dim,
        num_classes=4,
        heads=heads,
    ).to(device)

    data = data.to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    criterion = nn.CrossEntropyLoss()
    scaler = torch.amp.GradScaler("cuda") if device.type == "cuda" else None

    best_val_loss = float("inf")
    best_ckpt_path = checkpoint_dir / "nvd_cve_gat_best.pt"
    latest_ckpt_path = checkpoint_dir / "nvd_cve_gat_latest.pt"

    history = []

    for epoch in range(1, epochs + 1):
        t0 = time.time()
        model.train()
        optimizer.zero_grad()

        use_amp = (device.type == "cuda")
        with torch.amp.autocast(device_type="cuda", dtype=torch.float16, enabled=use_amp):
            out = model(data.x, data.edge_index)
            loss = criterion(out[data.train_mask], data.y[data.train_mask])

        if scaler is not None and use_amp:
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()
        else:
            loss.backward()
            optimizer.step()

        # Validation
        model.eval()
        with torch.no_grad():
            with torch.amp.autocast(device_type="cuda", dtype=torch.float16, enabled=use_amp):
                val_out = model(data.x, data.edge_index)
                val_loss = criterion(val_out[data.val_mask], data.y[data.val_mask]).item()

            train_preds = out[data.train_mask].argmax(dim=-1)
            train_acc = (train_preds == data.y[data.train_mask]).float().mean().item() * 100

            val_preds = val_out[data.val_mask].argmax(dim=-1)
            val_acc = (val_preds == data.y[data.val_mask]).float().mean().item() * 100

        elapsed = time.time() - t0

        vram_str = ""
        if device.type == "cuda":
            alloc_mb = torch.cuda.memory_allocated(device) / (1024 * 1024)
            peak_mb = torch.cuda.max_memory_allocated(device) / (1024 * 1024)
            vram_str = f" | VRAM: {alloc_mb:.0f}MB (Peak {peak_mb:.0f}MB)"

        row = {
            "epoch": epoch,
            "train_loss": loss.item(),
            "train_acc": train_acc,
            "val_loss": val_loss,
            "val_acc": val_acc,
            "elapsed_s": elapsed,
        }
        history.append(row)

        print(
            f"Epoch [{epoch:02d}/{epochs:02d}] "
            f"Train Loss: {loss.item():.4f} (Acc: {train_acc:.1f}%) | "
            f"Val Loss: {val_loss:.4f} (Acc: {val_acc:.1f}%) | "
            f"Time: {elapsed:.2f}s{vram_str}"
        )

        # Save latest checkpoint
        torch.save({
            "epoch": epoch,
            "model_state_dict": model.state_dict(),
            "optimizer_state_dict": optimizer.state_dict(),
            "val_loss": val_loss,
            "val_acc": val_acc,
        }, latest_ckpt_path)

        # Save best checkpoint
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), best_ckpt_path)
            print(f"   --> [STATUS CHECKPOINT] Saved new best model to {best_ckpt_path.name} (Val Loss: {val_loss:.4f})")

    # Final Test Evaluation
    model.load_state_dict(torch.load(best_ckpt_path))
    model.eval()
    with torch.no_grad():
        test_out = model(data.x, data.edge_index)
        test_loss = criterion(test_out[data.test_mask], data.y[data.test_mask]).item()
        test_preds = test_out[data.test_mask].argmax(dim=-1)
        test_acc = (test_preds == data.y[data.test_mask]).float().mean().item() * 100

    log.info(f"\n{'='*70}")
    log.info("  NVD / CVE GNN TRAINING COMPLETE")
    log.info(f"  Best Val Loss : {best_val_loss:.4f}")
    log.info(f"  Test Accuracy : {test_acc:.2f}% (Loss: {test_loss:.4f})")
    log.info(f"  Best Model Checkpoint: {best_ckpt_path.relative_to(REPO_ROOT)}")
    log.info(f"{'='*70}\n")

    report_path = REPO_ROOT / "reports" / "nvd_cve_training_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "nodes": data.num_nodes,
            "edges": data.num_edges,
            "epochs": epochs,
            "best_val_loss": best_val_loss,
            "test_accuracy": test_acc,
            "checkpoint": str(best_ckpt_path.relative_to(REPO_ROOT)),
            "history": history,
        }, f, indent=2)
    log.info(f"  Execution report saved to: {report_path.relative_to(REPO_ROOT)}\n")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN CLI ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Download NVD/CVE Database and Train Graph Neural Network.")
    parser.add_argument("--year", type=int, default=2024, help="Annual NVD CVE feed year (default: 2024)")
    parser.add_argument("--epochs", type=int, default=10, help="Training epochs (default: 10)")
    parser.add_argument("--max-items", type=int, default=None, help="Limit CVE items for quick test (default: all)")
    parser.add_argument("--device", type=str, default="auto", help="auto | cuda | cpu (default: auto)")
    parser.add_argument("--download-only", action="store_true", help="Only download and extract JSON feed")
    args = parser.parse_args()

    print("\n" + "#"*70)
    print("  NVD / CVE VULNERABILITY GRAPH PIPELINE WITH STEP CHECKPOINTS")
    print("#"*70 + "\n")

    # Step 1 Checkpoint
    print("--> [CHECKPOINT 1/5] Downloading & caching NVD/CVE database JSON ...")
    json_path = download_nvd_cve_feed(year=args.year)
    print(f"    [CHECKPOINT 1/5 COMPLETE] Ready: {json_path}\n")

    if args.download_only:
        print("Download-only completed.")
        return

    # Step 2 Checkpoint
    print("--> [CHECKPOINT 2/5] Parsing CVEs, CWEs, and software configs into graph entities ...")
    parsed = parse_nvd_json_to_entities(json_path, max_items=args.max_items)
    print(f"    [CHECKPOINT 2/5 COMPLETE] Extracted {len(parsed['node_to_idx']):,} entities ({len(parsed['cve_indices']):,} CVEs, {len(parsed['src_edges']):,} edges)\n")

    # Step 3 Checkpoint
    print("--> [CHECKPOINT 3/5] Converting entities into PyTorch Geometric Graph (Nodes & Edges) ...")
    data = build_pyg_graph(parsed)
    print(f"    [CHECKPOINT 3/5 COMPLETE] PyG Graph constructed: {data.num_nodes:,} nodes, {data.num_edges:,} edges, 18 features\n")

    # Step 4 & 5 Checkpoint
    print("--> [CHECKPOINT 4/5] Initializing Graph Attention Network (GAT) with GPU acceleration ...")
    print("--> [CHECKPOINT 5/5] Starting GNN training loop with per-epoch status checkpoints ...")
    train_nvd_gnn(
        data=data,
        epochs=args.epochs,
        device_str=args.device,
    )
    print("All pipeline checkpoints completed successfully!\n")


if __name__ == "__main__":
    main()

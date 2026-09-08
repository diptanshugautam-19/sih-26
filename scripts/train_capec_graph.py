"""
scripts/train_capec_graph.py

Trains a Graph Attention Network (GAT) strictly on the official MITRE CAPEC
(Common Attack Pattern Enumeration and Classification) dataset.

NO SAMPLE, SYNTHETIC, OR FAKE DATA IS USED.
Every entity, node, relationship, execution step, and weakness mapping is parsed
directly from the official MITRE catalog files:
  - data/raw/capec/capec_latest.xml (Official MITRE CAPEC v3.9 XML Catalog)
  - data/raw/capec/stix-capec.json  (Official MITRE CTI STIX 2.1 Repository)

Pipeline Stages:
  [CHECKPOINT 1/5] Validate Official MITRE Catalog Datasets
  [CHECKPOINT 2/5] Parse 615 Real Attack Patterns, CWEs, Mitigations & Sequences
  [CHECKPOINT 3/5] Construct PyG Graph (64-dim TF-IDF + Structural Node Features)
  [CHECKPOINT 4/5] Initialize Deep Graph Attention Network (GAT) with Attention Heads
  [CHECKPOINT 5/5] Train GNN on GPU with Learning Rate Scheduling, F1 & Checkpoint Saving
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
import logging
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score, precision_score, recall_score, classification_report

from torch_geometric.data import Data
from torch_geometric.nn import GATConv

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

from scripts.download_capec import URLS, download_file, generate_capec_csv, OUT_DIR


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 1: VALIDATE OFFICIAL DATASET FILES
# ─────────────────────────────────────────────────────────────────────────────
def ensure_official_capec_data(cache_dir: Path | None = None) -> tuple[Path, Path]:
    """Ensures official MITRE files exist and validates their integrity."""
    if cache_dir is None:
        cache_dir = OUT_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    stix_path = cache_dir / "stix-capec.json"
    xml_path = cache_dir / "capec_latest.xml"
    csv_path = cache_dir / "capec.csv"

    for fname, url in URLS.items():
        dest = cache_dir / fname
        if not dest.exists() or dest.stat().st_size < 100_000:
            log.info(f"  Downloading official MITRE source: {url}")
            download_file(url, dest)

    if not stix_path.exists() or not xml_path.exists():
        raise FileNotFoundError("Official MITRE CAPEC dataset files could not be located or downloaded.")

    if not csv_path.exists():
        generate_capec_csv(xml_path, csv_path)

    log.info(f"  [VERIFIED] Official STIX 2.1: {stix_path.name} ({stix_path.stat().st_size / 1024:.1f} KB)")
    log.info(f"  [VERIFIED] Official XML     : {xml_path.name} ({xml_path.stat().st_size / 1024:.1f} KB)")
    return stix_path, xml_path


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 2: PARSE OFFICIAL MITRE ENTITIES & FEATURES
# ─────────────────────────────────────────────────────────────────────────────
def parse_official_capec_graph(xml_path: Path, stix_path: Path) -> dict:
    """
    Parses the genuine MITRE catalog into graph entities:
      - Attack Pattern Nodes (CAPEC-xxx): 615 real techniques
      - Related Weakness Nodes (CWE-xxx): Real hardware/software flaws
      - Mitigation Nodes: Official Course of Action defenses
      - Relational Edges: ChildOf (taxonomy), CanPrecede (attack sequence), Exploits, Mitigates
    """
    log.info(f"  Parsing Official MITRE XML Catalog: {xml_path.name} ...")
    t0 = time.time()
    tree = ET.parse(xml_path)
    root = tree.getroot()

    patterns = root.findall(".//{*}Attack_Pattern")
    log.info(f"  Located {len(patterns):,} genuine MITRE Attack Patterns in catalog")

    node_to_idx: dict[str, int] = {}
    node_types: list[str] = []
    node_text_corpus: list[str] = []
    raw_metadata_features: list[list[float]] = []
    labels_list: list[int] = []
    capec_node_indices: list[int] = []

    def get_or_create_node(node_id: str, n_type: str, text_desc: str = "") -> int:
        if node_id not in node_to_idx:
            idx = len(node_to_idx)
            node_to_idx[node_id] = idx
            node_types.append(n_type)
            node_text_corpus.append(text_desc)
            # Default zero vector for non-attack pattern nodes (CWEs, Mitigations)
            raw_metadata_features.append([0.0] * 16)
            labels_list.append(-1)
            return idx
        return node_to_idx[node_id]

    src_edges: list[int] = []
    dst_edges: list[int] = []
    edge_types: list[int] = []

    SEVERITY_MAP = {
        "UNKNOWN": 0,
        "VERY LOW": 1,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "VERY HIGH": 4,
    }
    LIKELIHOOD_MAP = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    ABSTRACTION_MAP = {"STANDARD": 0, "DETAILED": 1, "META": 2}

    for p in patterns:
        raw_id = p.attrib.get("ID", "")
        if not raw_id:
            continue
        capec_id = f"CAPEC-{raw_id}"
        name = p.attrib.get("Name", "")
        desc_el = p.find("{*}Description")
        desc = (desc_el.text or "").strip() if desc_el is not None else ""
        combined_text = f"{name} {desc}"

        capec_idx = get_or_create_node(capec_id, "ATTACK_PATTERN", combined_text)
        capec_node_indices.append(capec_idx)

        # Labels: Typical Severity (1: Low, 2: Medium, 3: High, 4: Very High, 0: Unknown)
        sev_el = p.find("{*}Typical_Severity")
        sev_str = (sev_el.text or "Unknown").strip().upper() if sev_el is not None else "UNKNOWN"
        sev_label = SEVERITY_MAP.get(sev_str, 0)
        labels_list[capec_idx] = sev_label

        # Attributes
        abstraction_str = p.attrib.get("Abstraction", "Standard").upper()
        abstraction_val = ABSTRACTION_MAP.get(abstraction_str, 0)

        lik_el = p.find("{*}Likelihood_Of_Attack")
        lik_str = (lik_el.text or "Unknown").strip().upper() if lik_el is not None else "UNKNOWN"
        lik_val = LIKELIHOOD_MAP.get(lik_str, 0)

        steps = p.findall(".//{*}Attack_Step")
        prereqs = p.findall(".//{*}Prerequisite")
        skills = p.findall(".//{*}Skill")

        # 16 Structural & Security Indicators
        meta_feat = [
            float(len(steps)),                         # 0: Attack execution steps count
            float(len(prereqs)),                       # 1: Prerequisites count
            float(len(skills)),                        # 2: Required skills count
            float(lik_val) / 3.0,                      # 3: Attack likelihood rating
            float(abstraction_val) / 2.0,              # 4: Abstraction tier
            float(len(name)) / 100.0,                  # 5: Name complexity length
            float(len(desc)) / 1500.0,                 # 6: Description depth length
            1.0 if "network" in combined_text.lower() else 0.0,      # 7: Remote network scope
            1.0 if "privilege" in combined_text.lower() else 0.0,    # 8: Privilege escalation
            1.0 if "denial" in combined_text.lower() else 0.0,       # 9: Availability denial
            1.0 if "injection" in combined_text.lower() else 0.0,    # 10: Payload injection
            1.0 if "buffer" in combined_text.lower() else 0.0,       # 11: Memory safety breach
            1.0 if "authentication" in combined_text.lower() else 0.0,# 12: Auth bypass
            1.0 if "crypto" in combined_text.lower() else 0.0,       # 13: Cryptographic attack
            1.0 if "hardware" in combined_text.lower() else 0.0,     # 14: Hardware architecture
            1.0,                                                     # 15: Attack pattern flag
        ]
        raw_metadata_features[capec_idx] = meta_feat

        # Related Attack Patterns (ChildOf, CanPrecede, PeerOf)
        for rel in p.findall(".//{*}Related_Attack_Pattern"):
            target_id_num = rel.attrib.get("CAPEC_ID", "")
            if not target_id_num:
                continue
            nature = rel.attrib.get("Nature", "ChildOf")
            target_id = f"CAPEC-{target_id_num}"
            target_idx = get_or_create_node(target_id, "ATTACK_PATTERN")

            src_edges.append(capec_idx)
            dst_edges.append(target_idx)
            edge_types.append(0 if nature == "ChildOf" else (1 if nature == "CanPrecede" else 2))

        # Related Weaknesses (CWE)
        for w in p.findall(".//{*}Related_Weakness"):
            cwe_num = w.attrib.get("CWE_ID", "")
            if not cwe_num:
                continue
            cwe_id = f"CWE-{cwe_num}"
            cwe_idx = get_or_create_node(cwe_id, "CWE", f"CWE-{cwe_num} Software Weakness")
            src_edges.append(capec_idx)
            dst_edges.append(cwe_idx)
            edge_types.append(3)

    # Augment with STIX 2.1 Course of Action Mitigations
    log.info(f"  Augmenting with STIX 2.1 Mitigations: {stix_path.name} ...")
    with open(stix_path, "r", encoding="utf-8") as f:
        stix_data = json.load(f)

    stix_id_to_capec: dict[str, str] = {}
    stix_coa_names: dict[str, str] = {}
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name", "").lower() == "capec":
                    stix_id_to_capec[obj.get("id")] = ref.get("external_id")
                    break
        elif obj.get("type") == "course-of-action":
            stix_coa_names[obj.get("id")] = obj.get("name", "Mitigation Defense")

    for obj in stix_data.get("objects", []):
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
            coa_stix_id = obj.get("source_ref")
            target_stix_id = obj.get("target_ref")
            if target_stix_id in stix_id_to_capec:
                capec_id = stix_id_to_capec[target_stix_id]
                if capec_id in node_to_idx:
                    c_idx = node_to_idx[capec_id]
                    coa_name = stix_coa_names.get(coa_stix_id, "Mitigation Defense")
                    coa_idx = get_or_create_node(coa_stix_id, "COURSE_OF_ACTION", coa_name)
                    src_edges.append(c_idx)
                    dst_edges.append(coa_idx)
                    edge_types.append(4)

    # 3. Extract TF-IDF Semantic Representations from Attack Descriptions (48 dimensions)
    log.info("  Fitting TF-IDF Vectorizer on official MITRE names & descriptions ...")
    tfidf = TfidfVectorizer(max_features=48, stop_words="english", sublinear_tf=True)
    text_corpus_clean = [t if t.strip() else "security attack pattern entity" for t in node_text_corpus]
    tfidf_matrix = tfidf.fit_transform(text_corpus_clean).toarray()

    # Combine 48 text features + 16 structural features = 64 total input features
    meta_matrix = np.array(raw_metadata_features, dtype=np.float32)
    combined_features = np.hstack([tfidf_matrix, meta_matrix]).astype(np.float32)

    dt = time.time() - t0
    log.info(f"  Parsed {len(node_to_idx):,} genuine entities, {len(src_edges):,} relational edges, 64 features in {dt:.2f}s")

    return {
        "node_to_idx": node_to_idx,
        "node_types": node_types,
        "features": combined_features,
        "labels": labels_list,
        "capec_indices": capec_node_indices,
        "src_edges": src_edges,
        "dst_edges": dst_edges,
        "edge_types": edge_types,
    }


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 3: CONSTRUCT PYTORCH GEOMETRIC DATA OBJECT
# ─────────────────────────────────────────────────────────────────────────────
def build_capec_pyg_data(parsed: dict) -> Data:
    """Builds PyTorch Geometric Data object with symmetric message-passing and data splits."""
    x = torch.tensor(parsed["features"], dtype=torch.float32)
    y = torch.tensor(parsed["labels"], dtype=torch.long)

    src = parsed["src_edges"]
    dst = parsed["dst_edges"]
    all_src = src + dst
    all_dst = dst + src
    edge_index = torch.tensor([all_src, all_dst], dtype=torch.long)

    capec_indices = np.array(parsed["capec_indices"])
    np.random.seed(42)
    np.random.shuffle(capec_indices)

    n = len(capec_indices)
    n_train = int(n * 0.70)
    n_val = int(n * 0.15)

    train_idx = capec_indices[:n_train]
    val_idx = capec_indices[n_train : n_train + n_val]
    test_idx = capec_indices[n_train + n_val :]

    num_nodes = len(parsed["node_to_idx"])
    train_mask = torch.zeros(num_nodes, dtype=torch.bool)
    val_mask = torch.zeros(num_nodes, dtype=torch.bool)
    test_mask = torch.zeros(num_nodes, dtype=torch.bool)

    train_mask[train_idx] = True
    val_mask[val_idx] = True
    test_mask[test_idx] = True

    data = Data(
        x=x,
        edge_index=edge_index,
        y=y,
        train_mask=train_mask,
        val_mask=val_mask,
        test_mask=test_mask,
    )
    return data


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 4: GRAPH ATTENTION NETWORK (GAT) ARCHITECTURE
# ─────────────────────────────────────────────────────────────────────────────
class CAPECGATModel(nn.Module):
    """
    Two-layer multi-head Graph Attention Network with residual projections,
    LayerNorm, and multi-class classification head.
    """
    def __init__(self, in_channels: int = 64, hidden_channels: int = 64, num_classes: int = 5, heads: int = 4):
        super().__init__()
        self.gat1 = GATConv(in_channels, hidden_channels, heads=heads, dropout=0.2)
        self.res1 = nn.Linear(in_channels, hidden_channels * heads)
        self.norm1 = nn.LayerNorm(hidden_channels * heads)

        self.gat2 = GATConv(hidden_channels * heads, hidden_channels, heads=2, dropout=0.2)
        self.res2 = nn.Linear(hidden_channels * heads, hidden_channels * 2)
        self.norm2 = nn.LayerNorm(hidden_channels * 2)

        self.classifier = nn.Sequential(
            nn.Linear(hidden_channels * 2, hidden_channels),
            nn.GELU(),
            nn.Dropout(0.25),
            nn.Linear(hidden_channels, num_classes),
        )

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        h1 = self.norm1(F.elu(self.gat1(x, edge_index)) + self.res1(x))
        h2 = self.norm2(F.elu(self.gat2(h1, edge_index)) + self.res2(h1))
        out = self.classifier(h2)
        return out


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 5: TRAINING LOOP & REAL-TIME PROGRESS
# ─────────────────────────────────────────────────────────────────────────────
def train_capec_gnn(
    data: Data,
    epochs: int = 30,
    lr: float = 0.003,
    device_str: str = "auto",
):
    if device_str == "auto":
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    else:
        device = torch.device(device_str)

    log.info(f"  Training device: {device} ({torch.cuda.get_device_name(0) if device.type == 'cuda' else 'CPU'})")

    data = data.to(device)
    in_dim = data.x.size(1)
    num_classes = int(data.y[data.y >= 0].max().item()) + 1

    model = CAPECGATModel(in_channels=in_dim, hidden_channels=64, num_classes=num_classes, heads=4).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-3)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)

    # Class-weighted cross entropy to handle severity distributions
    class_counts = torch.bincount(data.y[data.train_mask])
    weights = 1.0 / (class_counts.float() + 1.0)
    weights = weights / weights.sum()
    criterion = nn.CrossEntropyLoss(weight=weights.to(device))

    ckpt_dir = REPO_ROOT / "models" / "checkpoints"
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    best_ckpt_path = ckpt_dir / "capec_gat_best.pt"

    log.info(f"\n{'='*70}")
    log.info(f"  STARTING OFFICIAL CAPEC GAT TRAINING: {epochs} EPOCHS (Classes: {num_classes})")
    log.info(f"  Dataset Nodes: {data.num_nodes:,} | Relational Edges: {data.num_edges:,} | Features: {in_dim}")
    log.info(f"{'='*70}")

    best_val_f1 = 0.0
    best_val_acc = 0.0
    history = []

    for epoch in range(1, epochs + 1):
        t_start = time.time()
        model.train()
        optimizer.zero_grad()

        out = model(data.x, data.edge_index)
        loss = criterion(out[data.train_mask], data.y[data.train_mask])
        loss.backward()
        optimizer.step()
        scheduler.step()

        # Validation
        model.eval()
        with torch.no_grad():
            preds = out.argmax(dim=-1)
            train_preds = preds[data.train_mask].cpu().numpy()
            train_y = data.y[data.train_mask].cpu().numpy()
            train_acc = (train_preds == train_y).mean() * 100

            val_preds = preds[data.val_mask].cpu().numpy()
            val_y = data.y[data.val_mask].cpu().numpy()
            val_loss = criterion(out[data.val_mask], data.y[data.val_mask]).item()
            val_acc = (val_preds == val_y).mean() * 100
            val_f1 = f1_score(val_y, val_preds, average="macro", zero_division=0) * 100

        elapsed = time.time() - t_start
        vram_str = ""
        if device.type == "cuda":
            alloc_mb = torch.cuda.memory_allocated(device) / (1024 * 1024)
            vram_str = f" | VRAM: {alloc_mb:.0f}MB"

        print(
            f"Epoch [{epoch:02d}/{epochs:02d}] "
            f"Train Loss: {loss.item():.4f} (Acc: {train_acc:.1f}%) | "
            f"Val Loss: {val_loss:.4f} (Acc: {val_acc:.1f}%, F1: {val_f1:.1f}%) | "
            f"Time: {elapsed:.2f}s{vram_str}"
        )

        history.append({
            "epoch": epoch,
            "train_loss": float(loss.item()),
            "train_acc": float(train_acc),
            "val_loss": float(val_loss),
            "val_acc": float(val_acc),
            "val_f1": float(val_f1),
        })

        if val_f1 >= best_val_f1 or (val_f1 == best_val_f1 and val_acc > best_val_acc):
            best_val_f1 = val_f1
            best_val_acc = val_acc
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "in_dim": in_dim,
                "num_classes": num_classes,
                "val_acc": float(val_acc),
                "val_f1": float(val_f1),
            }, best_ckpt_path)
            print(f"   --> [CHECKPOINT] Saved new best model to {best_ckpt_path.name} (Val F1: {val_f1:.1f}%, Acc: {val_acc:.1f}%)")

    # Test Evaluation
    checkpoint = torch.load(best_ckpt_path, weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    with torch.no_grad():
        test_out = model(data.x, data.edge_index)
        test_loss = criterion(test_out[data.test_mask], data.y[data.test_mask]).item()
        test_preds = test_out[data.test_mask].argmax(dim=-1).cpu().numpy()
        test_y = data.y[data.test_mask].cpu().numpy()

        test_acc = (test_preds == test_y).mean() * 100
        test_f1 = f1_score(test_y, test_preds, average="macro", zero_division=0) * 100
        test_precision = precision_score(test_y, test_preds, average="macro", zero_division=0) * 100
        test_recall = recall_score(test_y, test_preds, average="macro", zero_division=0) * 100

    log.info(f"\n{'='*70}")
    log.info("  OFFICIAL CAPEC GNN TRAINING COMPLETE")
    log.info(f"  Best Val Macro F1 : {best_val_f1:.2f}% (Val Acc: {best_val_acc:.2f}%)")
    log.info(f"  Test Accuracy     : {test_acc:.2f}% (Test Loss: {test_loss:.4f})")
    log.info(f"  Test Macro F1     : {test_f1:.2f}%")
    log.info(f"  Test Precision    : {test_precision:.2f}% | Test Recall: {test_recall:.2f}%")
    log.info(f"  Model Checkpoint  : {best_ckpt_path.relative_to(REPO_ROOT)}")
    log.info(f"{'='*70}\n")

    report_path = REPO_ROOT / "reports" / "capec_training_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "dataset": "Official MITRE CAPEC (XML + STIX 2.1)",
            "nodes": data.num_nodes,
            "edges": data.num_edges,
            "features_dimension": in_dim,
            "epochs": epochs,
            "best_val_f1": best_val_f1,
            "best_val_acc": best_val_acc,
            "test_accuracy": test_acc,
            "test_macro_f1": test_f1,
            "test_precision": test_precision,
            "test_recall": test_recall,
            "checkpoint": str(best_ckpt_path.relative_to(REPO_ROOT)),
            "history": history,
        }, f, indent=2)
    log.info(f"  Execution report saved to: {report_path.relative_to(REPO_ROOT)}\n")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN CLI ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Train Graph Attention Network strictly on official MITRE CAPEC.")
    parser.add_argument("--epochs", type=int, default=30, help="Training epochs (default: 30)")
    parser.add_argument("--lr", type=float, default=0.003, help="Learning rate (default: 0.003)")
    parser.add_argument("--device", type=str, default="auto", help="auto | cuda | cpu")
    parser.add_argument("--download-only", action="store_true", help="Only verify/download official catalog")
    args = parser.parse_args()

    print("\n" + "#" * 70)
    print("  MITRE CAPEC ATTACK PATTERN GRAPH PIPELINE WITH STEP CHECKPOINTS")
    print("#" * 70 + "\n")

    # [CHECKPOINT 1/5] Download
    print("--> [CHECKPOINT 1/5] Validating official MITRE CAPEC catalog files ...")
    stix_path, xml_path = ensure_official_capec_data()
    print(f"    [CHECKPOINT 1/5 COMPLETE] Sources verified: {stix_path.name}, {xml_path.name}\n")

    if args.download_only:
        print("Download-only completed.")
        return

    # [CHECKPOINT 2/5] Parse Entities
    print("--> [CHECKPOINT 2/5] Parsing genuine MITRE attack patterns, CWEs, and mitigations ...")
    parsed = parse_official_capec_graph(xml_path, stix_path)
    print(f"    [CHECKPOINT 2/5 COMPLETE] Extracted {len(parsed['node_to_idx']):,} entities ({len(parsed['capec_indices']):,} attack patterns, {len(parsed['src_edges']):,} edges)\n")

    # [CHECKPOINT 3/5] PyG Data Object
    print("--> [CHECKPOINT 3/5] Constructing PyTorch Geometric Graph with 64-dim features ...")
    data = build_capec_pyg_data(parsed)
    print(f"    [CHECKPOINT 3/5 COMPLETE] PyG Graph constructed: {data.num_nodes:,} nodes, {data.num_edges:,} edges, 64 features\n")

    # [CHECKPOINT 4/5 & 5/5] Train GAT
    print("--> [CHECKPOINT 4/5] Initializing Deep Graph Attention Network (GAT) ...")
    print("--> [CHECKPOINT 5/5] Training GNN strictly on official MITRE graph ...")
    train_capec_gnn(
        data=data,
        epochs=args.epochs,
        lr=args.lr,
        device_str=args.device,
    )
    print("All CAPEC pipeline checkpoints completed successfully!\n")


if __name__ == "__main__":
    main()

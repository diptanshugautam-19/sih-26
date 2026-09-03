# PROJECT MEMORY — Predictive Cyber Defence World Model
**Project:** World Model (GNN + Transformer) for Network Infiltration Prediction  
**Challenge:** NCIIPC — AI World Models for Proactive Cyber Defence  

---

## 1. PROJECT IDENTITY
- **One-line pitch:** A world model that learns network state-transition dynamics $P(S_{t+1} \mid S_t)$ from traffic telemetry, rolls out $K$ steps ahead, predicts infiltration probability + MITRE ATT&CK stage, with attention-based explanations.
- **What this is NOT:** a per-flow binary classifier. Every design decision must preserve temporal/structural modelling.
- **Core thesis:** Infiltrations are processes unfolding over time. We model the trajectory, not the packet.

---

## 2. LOCKED ARCHITECTURE DECISIONS
| Decision | Value | Rationale |
| :--- | :--- | :--- |
| **Time window** | 5 seconds, fixed | Balance detail/context; expose as config, show ablation |
| **Input window stride** | 2.5 s (50% overlap) | Captures attacks crossing window boundaries |
| **Target window** | NON-OVERLAPPING with last input window | CRITICAL: prevents target leakage. Target starts where last input window ends |
| **Graph per window** | 1 (nodes=hosts, edges=aggregated flows) | Structural representation |
| **GNN** | GATConv (PyG) | Attention weights -> explainability for free |
| **Temporal model** | Transformer Encoder | Learns sequence of graph embeddings |
| **Sequence length** | 10 graphs (inputs, stride 2.5s ≈ 27.5s real span) | Real span is 27.5s, not 50s |
| **Prediction horizon** | K = 3–5 future windows (non-overlapping) | Meets "K-step forward simulation" requirement |
| **Prediction heads** | (a) next-state reconstruction, (b) infiltration probability, (c) ATT&CK stage classifier | Three outputs from one pooled temporal representation |
| **Primary dataset** | CIC-IDS2018 (flow CSVs) | Scale + attack diversity |
| **Secondary dataset** | CTU-13 (NetFlow + PCAP) | Packet-level features; smaller, cleaner |
| **Explainability** | GAT attention (primary) + SHAP on feature head (secondary) | No black-box outputs |
| **Baselines** | (1) Logistic regression per-flow, (2) GNN-only single-frame ablation | Isolates temporal contribution & meets brief requirement |
| **Generalisation test** | Hold out entire attack types (e.g., Slowloris days), evaluate on unseen attacks | Out-of-distribution robustness |
| **UI** | Streamlit, fully offline | Strict offline evaluation constraint |
| **Python** | 3.10 or 3.11 | PyG compatibility |

---

## 3. API CONTRACT (Backend <-> Frontend)
```json
POST /predict multipart: CSV file
-> {
  "timeline": [ {"t": 0.0, "infiltration_prob": 0.85, "stage": "Lateral Movement", "stage_conf": 0.92} ],
  "current_stage": "Lateral Movement",
  "mitre_technique": "T1021",
  "forecast_K": 4,
  "top_features": [ {"name": "syn_rate", "contribution": 0.31} ],
  "flagged_edges": [ {"src": "10.0.0.5", "dst": "172.16.0.10", "attn": 0.42} ],
  "ood_score": 0.71
}

GET /health -> {"status": "ok", "model_loaded": true}
```

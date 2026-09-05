# PROJECT ARCHITECTURE & MEMORY — AI Cyber Defence World Model

## 1. System Overview
This project implements an **AI World Model for Proactive Cyber Defence**. Instead of evaluating individual packets or isolated NetFlow lines as a binary classifier, it constructs a sequence of dynamic host-communication graphs over time and learns network state-transition dynamics $P(S_{t+1} \mid S_t)$. It projects $K$ steps into the future to forecast infiltration attempts, predict MITRE ATT&CK stages, estimate uncertainty via MC Dropout, and simulate counterfactual defender interventions (action masking) in sub-50ms.

---

## 2. Pipeline & Architecture Specs

### A. Data Preprocessing & Windowing
- **Input Telemetry:** PCAP captures or CIC-IDS2018 / NetFlow CSVs.
- **Window Slicing:** 5.0-second fixed window with 2.5-second stride (50% overlap).
- **Sequence Length:** 10 snapshots ($\approx 27.5$s total historical span).
- **Forecast Horizon:** $K = 4$ non-overlapping future windows ($\approx 20$s forward projection).
- **Strict Anti-Leakage Rule:** Target calculation strictly starts after the 10th snapshot window closes.

### B. Spatial Representation (Dynamic GNN + Memory Bank)
- **Module:** `DynamicGATWithMemory` (`src/models/dynamic_gnn.py`)
- **Features:** 16 node features (degrees, port entropy, TTL, byte volume) and 12 edge features (byte counts, TCP flags, inter-arrival time).
- **Persistent IP Registry:** `PersistentNodeRegistry` maps IP strings to stable IDs across all windows.
- **Node Memory:** GRU-based node memory bank ($h_v^{(t)} = \text{GRU}(h_v^{(t-1)}, m_v)$) maintaining state for quiet or dormant nodes.
- **Explainability:** Multi-head GAT attention weights ($\alpha_{ij}$) pinpoint critical attack edges.

### C. Temporal World Model (Causal Sequence Transformer)
- **Module:** `CausalTemporalTransformer` (`src/models/temporal.py`)
- **Structure:** 3-layer Transformer Encoder, GELU activation, learnable positional embeddings.
- **Causality:** Strictly masked lower-triangular causal attention preventing lookahead bias.

### D. Multi-Task Output Heads
- **Module:** `MultiTaskWorldModelHeads` (`src/models/heads.py`)
- **Head 1 (Grounded Dynamics):** Predicts future telemetry metrics (port entropy, SYN ratio, log bytes) across $K$ future steps.
- **Head 2 (Infiltration Risk):** Sigmoid output representing graded probability of infiltration.
- **Head 3 (MITRE Progression):** 7-class classifier (Benign, Recon, Initial Access, Credential Access, Lateral Movement, C2, Exfiltration).
- **Head 4 (Host Risk Attribution):** Node-level risk scoring identifying victim/targeted IPs.

---

## 3. Training & Optimization

### Training Objectives (`src/training/losses.py`)
Losses are dynamically balanced using Kendall, Gal & Cipolla (2018) homoscedastic uncertainty weighting:
$$\mathcal{L}_{\text{total}} = \sum_i \left[ \frac{1}{2\sigma_i^2}\mathcal{L}_i + \log\sigma_i \right]$$
- **$\mathcal{L}_{\text{dyn}}$:** Mean Squared Error on future grounded telemetry.
- **$\mathcal{L}_{\text{infil}}$:** Focal Binary Cross-Entropy (gamma=2.0) with label smoothing to counter $\approx 80\%$ benign class imbalance.
- **$\mathcal{L}_{\text{stage}}$:** Confidence-weighted Cross-Entropy scaled by pseudo-label confidence scores.

### Optimizer & Schedule
- **Optimizer:** AdamW ($\text{lr} = 5 \times 10^{-4}$, $\text{weight\_decay} = 10^{-4}$).
- **Scheduler:** Cosine annealing with early stopping on validation loss.

---

## 4. Baselines for Comparison (`src/models/baselines/`)
1. **Per-Flow Tabular Baseline (`logistic.py`):** Per-flow classifier (Logistic Regression/XGBoost) on raw tabular data to demonstrate why stateless flow classification fails on multi-stage campaigns.
2. **Single-Frame GNN (`gnn_only.py`):** Static GNN evaluating only the latest snapshot without temporal sequence modeling, proving the value of the Transformer temporal dynamics.

---

## 5. UI & Offline SOC Dashboard (`frontend/streamlit_app/`)
- Fully functional offline Streamlit cockpit.
- **Panel 1 (Dynamic Graph Sandbox):** Interactive PyVis/Plotly network topology visualizer with glowing GAT attention edges.
- **Panel 2 (Predictive Timeline):** Lead-time counter (seconds of advance warning), trajectory graphs, and Monte Carlo dropout uncertainty bands.
- **Panel 3 (Counterfactual Action Center):** Instant node/edge isolation action mask simulation evaluating risk mitigation before executing containment.

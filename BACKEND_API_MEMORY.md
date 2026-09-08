# BACKEND API & DATA CONTRACT SPECIFICATION FOR FRONTEND AGENT
**Target Consumer:** Frontend AI Agent / UI Developers  
**System:** AI Cyber Defence World Model (VASHIKARAN)  
**Base URLs:**
- **Python ML Inference Backend (FastAPI)**: `http://localhost:8000`
- **Node / Express Gateway & State Server**: `http://localhost:3000`

---

## 1. Architecture & Dual-Backend Overview

The system consists of two interconnected backend layers:

1. **Python AI/ML World Model Backend (`src/api/` on port 8000)**:
   - Hosts the PyTorch GAT + Causal Temporal Transformer model.
   - Computes $P(S_{t+1} \mid S_t)$ graph state transitions, $K$-step forward rollouts, Monte Carlo Dropout uncertainty, and counterfactual action masks.
   - Ingests raw NetFlow/PCAP CSV telemetry via `POST /predict`.

2. **Frontend Aggregator / Mock-State Gateway (`frontend/server.ts` on port 3000)**:
   - Hosts the Express REST API that serves live topology graphs, MITRE ATT&CK kill chain progression, alert streams, and counterfactual policy deployment directly to the browser.
   - Can proxy requests or operate fully standalone offline.

---

## 2. API Endpoints Reference

### LAYER A: Python FastAPI Inference Engine (`:8000`)

#### 1. `GET /health`
- **Description:** Verifies service health, model weights load status, and compute device.
- **Request:** None
- **Response Schema:**
```json
{
  "status": "ok",
  "model_loaded": true,
  "device": "cpu", // or "cuda"
  "version": "1.0.0"
}
```

---

#### 2. `POST /predict`
- **Description:** Ingests CSV network telemetry (flows/packets), partitions into 5s sliding windows (2.5s stride), constructs graph sequence, runs GAT + Transformer inference, and returns timeline forecast and spatial edge attention.
- **Content-Type:** `multipart/form-data`
- **Form Fields:** `file` (CSV file with columns: `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, flags, bytes, etc.)
- **Response Schema (`PredictResponse`):**
```json
{
  "timeline": [
    {
      "t": 105.0,
      "infiltration_prob": 0.74,
      "stage": "Lateral Movement",
      "stage_conf": 0.82
    },
    {
      "t": 110.0,
      "infiltration_prob": 0.81,
      "stage": "Lateral Movement",
      "stage_conf": 0.86
    }
  ],
  "current_stage": "Lateral Movement",
  "mitre_technique": "T1021 (Lateral Movement)",
  "forecast_K": 4,
  "top_features": [
    { "name": "syn_ratio", "contribution": 0.34 },
    { "name": "port_entropy", "contribution": 0.28 },
    { "name": "flow_bytes", "contribution": 0.21 },
    { "name": "ack_ratio", "contribution": 0.17 }
  ],
  "flagged_edges": [
    {
      "src": "10.0.0.22",
      "dst": "10.0.0.15",
      "attn": 0.924
    },
    {
      "src": "185.220.101.4",
      "dst": "10.0.0.22",
      "attn": 0.881
    }
  ],
  "ood_score": 0.12,
  "uncertainty_std": 0.058,
  "lead_time_seconds": 15.2
}
```

---

#### 3. `POST /counterfactual`
- **Description:** Evaluates a hypothetical defensive intervention on the active graph sequence (action masking without physical hardware isolation) and recalculates risk delta in sub-50ms.
- **Headers:** `Content-Type: application/json`
- **Request Body (`CounterfactualRequest`):**
```json
{
  "action": "isolate_host", // or "block_port"
  "target": "10.0.0.22",    // IP or port (e.g. "445")
  "current_risk": 0.94
}
```
- **Response Schema (`CounterfactualResponse`):**
```json
{
  "action": "isolate_host",
  "target": "10.0.0.22",
  "original_risk": 0.94,
  "recalculated_risk": 0.12,
  "risk_reduction": 0.82,
  "stage_after_action": "Benign"
}
```

---

#### 4. `GET /metrics`
- **Description:** Model vs. Baseline benchmark comparison table.
- **Response Schema:**
```json
{
  "status": "ok",
  "benchmark_summary": {
    "world_model": {
      "f1": 0.941,
      "precision": 0.952,
      "recall": 0.931,
      "fpr": 0.018,
      "auroc": 0.974,
      "brier_score": 0.058,
      "lead_time_seconds": 15.2
    },
    "logistic_baseline": {
      "f1": 0.682,
      "precision": 0.651,
      "recall": 0.718,
      "fpr": 0.145,
      "auroc": 0.742,
      "brier_score": 0.221,
      "lead_time_seconds": 0.0
    }
  }
}
```

---

### LAYER B: Live SOC Gateway & Topology Endpoints (`:3000`)

These are the endpoints consumed by the React SOC frontend to render interactive graphs and dashboards.

#### 1. `GET /api/network`
- **Description:** Fetches the full interactive topological state (hosts, communication edges, compromised nodes, and the primary predicted target).
- **Response Schema:**
```json
{
  "hosts": [
    {
      "id": "c2-ext",
      "name": "C2-EXT",
      "ip": "185.220.101.4",
      "role": "External Adversary C2 Node",
      "segment": "dmz",
      "status": "compromised", // 'compromised' | 'targeted' | 'elevated' | 'normal' | 'isolated'
      "x": 8,                  // coordinate %
      "y": 72,
      "openPorts": [443, 8443],
      "attentionScore": 0.96,
      "os": "Unknown Linux (Bulletproof ASN)",
      "inboundEdges": 0,
      "outboundEdges": 2
    },
    {
      "id": "app-07",
      "name": "APP-07",
      "ip": "10.0.0.22",
      "role": "Internal API Gateway & Auth",
      "segment": "dmz",
      "status": "compromised",
      "x": 32,
      "y": 68,
      "openPorts": [80, 443, 8080, 5432],
      "attentionScore": 0.88,
      "os": "Ubuntu LTS 22.04",
      "inboundEdges": 2,
      "outboundEdges": 3
    },
    {
      "id": "srv-dc01",
      "name": "SRV-DC01",
      "ip": "10.0.0.15",
      "role": "Primary Domain Controller",
      "segment": "corporate",
      "status": "targeted",
      "x": 52,
      "y": 28,
      "openPorts": [53, 88, 135, 389, 445, 636],
      "attentionScore": 0.94,
      "os": "Windows Server 2022 Core",
      "inboundEdges": 4,
      "outboundEdges": 3
    }
  ],
  "edges": [
    {
      "id": "e-app07-dc01",
      "source": "app-07",
      "target": "srv-dc01",
      "type": "attack", // 'attack' | 'elevated' | 'normal'
      "weight": 0.92,
      "port": 445,
      "protocol": "SMB / PsExec",
      "attention": 0.92
    }
  ],
  "attackedNodes": [ /* List of compromised Host objects */ ],
  "predictedNextTarget": {
    "hostId": "srv-dc01",
    "name": "SRV-DC01",
    "role": "Primary Domain Controller",
    "ip": "10.0.0.15",
    "segment": "corporate",
    "os": "Windows Server 2022 Core",
    "probabilityPercent": 94.2,
    "timeToAttackSeconds": 18.5,
    "timeToAttackLabel": "+18.5s",
    "predictedAttackVector": "SMB / PsExec Remote Execution from APP-07",
    "primarySourceId": "app-07",
    "primarySourceName": "APP-07",
    "incomingPort": 445,
    "protocol": "SMB / TCP",
    "mitreTactic": "TA0008 (Lateral Movement)",
    "mitreTacticCode": "TA0008",
    "probabilityIssues": [
      {
        "id": "iss-1",
        "factor": "High Port 445 (SMB) Traffic Density",
        "description": "Exploit payloads targeting administrative SMB shares detected.",
        "impactScore": 92,
        "severity": "critical",
        "category": "protocol_flaw"
      }
    ],
    "recommendedMitigations": [
      "Quarantine APP-07 immediately",
      "Block Port 445 on SRV-DC01"
    ]
  },
  "windowSeq": 842,
  "isolatedHostIds": [],
  "blockedPorts": {},
  "lastUpdated": "2026-09-09T01:50:00.000Z",
  "activeCapture": null
}
```

---

#### 2. `GET /api/telemetry`
- **Description:** High-level executive KPI metrics for dashboard status cards.
- **Response Schema:**
```json
{
  "infiltrationRisk": 94,
  "riskTrend": "12",
  "leadTime": "+18.5s",
  "leadTimeDelta": "+3.2s",
  "predictedStage": "Lateral movement",
  "mitreTactic": "TA0008 (Lateral Movement)",
  "modelConfidence": 94.2,
  "uncertainty": 5.8,
  "portEntropy": 3.2,
  "synRatio": 0.94,
  "logByteVolume": 12.6
}
```

---

#### 3. `GET /api/forecast`
- **Description:** $K$-step forward infiltration trajectory points (with Monte Carlo 95% CI upper/lower bounds) and MITRE ATT&CK kill-chain stage progression.
- **Response Schema:**
```json
{
  "points": [
    { "timeLabel": "-30s", "seconds": -30, "actual": 40, "baseline": 40, "ciUpper": 46, "ciLower": 34 },
    { "timeLabel": "-20s", "seconds": -20, "actual": 58, "baseline": 58, "ciUpper": 64, "ciLower": 52 },
    { "timeLabel": "-10s", "seconds": -10, "actual": 77, "baseline": 77, "ciUpper": 83, "ciLower": 71 },
    { "timeLabel": "NOW", "seconds": 0, "isNow": true, "actual": 94, "baseline": 94, "counterfactual": 94, "ciUpper": 98, "ciLower": 90 },
    { "timeLabel": "+10s", "seconds": 10, "baseline": 98, "counterfactual": 26, "ciUpper": 100, "ciLower": 88 },
    { "timeLabel": "+20s", "seconds": 20, "baseline": 99, "counterfactual": 21, "ciUpper": 100, "ciLower": 86 },
    { "timeLabel": "+30s", "seconds": 30, "baseline": 100, "counterfactual": 15, "ciUpper": 100, "ciLower": 84 },
    { "timeLabel": "+60s", "seconds": 60, "baseline": 100, "counterfactual": 11, "ciUpper": 100, "ciLower": 82 }
  ],
  "killChainStages": [
    { "step": 1, "name": "Reconnaissance", "status": "completed", "tacticId": "TA0043" },
    { "step": 2, "name": "Weaponization", "status": "completed", "tacticId": "TA0042" },
    { "step": 3, "name": "Delivery & Exploit", "status": "completed", "tacticId": "TA0001" },
    { "step": 4, "name": "Lateral Movement", "status": "active", "tacticId": "TA0008" },
    { "step": 5, "name": "Target Action / Infiltration", "status": "upcoming", "tacticId": "TA0040" }
  ],
  "portEntropy": 3.2,
  "synRatio": 0.94,
  "logByteVolume": 12.6,
  "currentRisk": 94,
  "isMitigated": false
}
```

---

#### 4. `GET /api/explainability?edgeId=e-app07-dc01`
- **Description:** Returns the GAT attention coefficient ($\alpha_{ij}$) and SHAP telemetry feature importance breakdown for a specified network communication edge.
- **Response Schema:**
```json
{
  "edgeId": "e-app07-dc01",
  "sourceId": "app-07",
  "sourceName": "APP-07",
  "sourceIp": "10.0.0.22",
  "targetId": "srv-dc01",
  "targetName": "SRV-DC01",
  "targetIp": "10.0.0.15",
  "protocol": "SMB / PsExec",
  "port": 445,
  "attention": 0.92,
  "mitreTactic": "TA0008 (Lateral Movement)",
  "mitreTacticCode": "TA0008",
  "predictedStage": "Lateral movement",
  "riskScore": 94,
  "riskTrend": "12",
  "leadTime": "+18.5s",
  "leadTimeDelta": "+3.2s",
  "portEntropy": 3.2,
  "synRatio": 0.94,
  "logByteVolume": 12.6,
  "summary": "Spatial graph attention model evaluated link from APP-07 to SRV-DC01 on Port 445 (SMB / PsExec) with 0.92 attention weight.",
  "features": [
    {
      "id": "f-1",
      "code": "GNN_ATTN_WEIGHT",
      "label": "Graph Attention Link Weight (0.92)",
      "percentage": 35,
      "severity": "high"
    },
    {
      "id": "f-2",
      "code": "PORT_VULNERABILITY",
      "label": "Destination Port 445 (SMB / PsExec) Attack Vector",
      "percentage": 28,
      "severity": "high"
    },
    {
      "id": "f-3",
      "code": "SESSION_BURST",
      "label": "Anomalous Connection Density & SYN Asymmetry",
      "percentage": 20,
      "severity": "medium"
    },
    {
      "id": "f-4",
      "code": "SUB_TOPOLOGY_PATH",
      "label": "Network Traversal Path (dmz -> corporate)",
      "percentage": 14,
      "severity": "low"
    }
  ]
}
```

---

#### 5. `GET /api/alerts`
- **Description:** Real-time stream of parsed security alerts with severity, source, target, and message.
- **Response Schema:**
```json
[
  {
    "id": "alt-target",
    "timestamp": "01:50:32",
    "severity": "critical",
    "source": "APP-07",
    "target": "SRV-DC01 (10.0.0.15)",
    "message": "SMB / PsExec Remote Execution from APP-07",
    "port": 445
  }
]
```

---

#### 6. Defensive Action & Mitigation Endpoints

- **`POST /api/actions/isolate`**:
  - Body: `{"hostId": "app-07", "isolate": true}`
  - Effect: Quarantines the host, severs all topology edges, and recalculates the next predicted victim.
  
- **`POST /api/actions/block-port`**:
  - Body: `{"hostId": "srv-dc01", "port": 445}`
  - Effect: Blocks inbound traffic on that specific service port.

- **`POST /api/actions/simulate`**:
  - Body: `{"actionType": "isolate_host", "targetId": "app-07", "port": 445}`
  - Response: Returns hypothetical `{ simulatedRisk, deltaPts }` without committing changes.

- **`POST /api/actions/deploy`**:
  - Body: `{"actionType": "isolate_host", "targetId": "app-07"}`
  - Effect: Enacts the simulated policy permanently into active network topology.

- **`POST /api/actions/reset`**:
  - Resets all isolations and port blocks back to initial state.

---

#### 7. Capture Upload & Replay Endpoints

- **`GET /api/captures/presets`**:
  - Returns list of forensic scenario templates:
    - `preset-apt29`: APT-29 Kerberoast & DC lateral traversal (`.pcap`)
    - `preset-eternalblue`: MS17-010 Ring0 exploit (`.pcapng`)
    - `preset-scada`: Industrial Modbus coil override (`.pcap`)
    - `preset-c2tunnel`: Zero-Day C2 HTTPS Beacon (`.pcap`)
- **`POST /api/captures/load-preset`**:
  - Body: `{"presetId": "preset-eternalblue"}`
- **`POST /api/upload-capture`**:
  - Body: `{"fileName": "attack.pcap", "fileType": "pcap", "fileContent": "<base64>", "fileSize": 1048576}`
  - Effect: Backend parses nodes and edges dynamically from the PCAP.
- **`POST /api/captures/reset`**:
  - Resets back to live default network stream.

---

## 3. Recommended Frontend Integration Strategy

When another frontend agent connects to these backends:
1. **Network Topology View**: Poll `GET /api/network` every 5 seconds. Bind `hosts` and `edges` to the graph canvas.
2. **Forecast View**: Call `GET /api/forecast`. Render SVG/Canvas chart using `points` array:
   - Past curve: from `timeLabel: "-30s"` up to `isNow: true`.
   - Forecast projection: from `isNow: true` through `"+60s"`.
   - Confidence bounds: fill polygon between `ciUpper` and `ciLower`.
3. **What-If Sandbox**: Call `POST /api/actions/simulate` on dropdown selection change to immediately show $\Delta\text{Risk}$ reduction.
4. **Attribution Panel**: Call `GET /api/explainability?edgeId={id}` whenever an operator clicks a highlighted attack line.

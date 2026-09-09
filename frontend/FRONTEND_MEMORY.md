# FRONTEND ARCHITECTURE & MEMORY — VASHIKARAN SOC Cockpit

## 1. Overview
The frontend is a mission-critical, low-latency, offline-capable **Predictive Cyber Defence SOC Cockpit** (codename: **VASHIKARAN**). It connects to the AI World Model backend to provide security operators with real-time network topology visualization, $K$-step forward infiltration trajectory projections, GAT attention edge-attribution explainability, and counterfactual "What-If" mitigation planning.

- **URL**: `http://localhost:3000`
- **Tech Stack**: React 19, TypeScript, Vite, Tailwind CSS v4, Motion (framer-motion), Lucide React.
- **Server Runtime**: Express + Vite SPA middleware in dev mode (`frontend/server.ts`), compiled via `tsx` or `esbuild`.

---

## 2. Directory Structure & Key Files

```
frontend/
├── package.json               # Scripts: dev (tsx server.ts), build, start, lint
├── server.ts                  # In-memory mock & proxy Express server + Vite middleware
├── vite.config.ts             # Vite configuration with @tailwindcss/vite & React plugin
├── public/
│   └── vashikaran_chakra_logo.svg
├── src/
│   ├── App.tsx                # Main controller: tab routing, state management, audio, polling
│   ├── main.tsx               # DOM entry point
│   ├── index.css              # Global styles, Tailwind directives, dark/light theme overrides
│   ├── types.ts               # Core TypeScript definitions (hosts, edges, forecasts, actions)
│   ├── vite-env.d.ts          # Vite client types
│   ├── assets/                # Logos, SVG assets, and imagery
│   ├── components/
│   │   ├── Header.tsx                 # Top bar: live telemetry indicators, theme toggle, capture controls
│   │   ├── MetricCards.tsx            # KPI status tiles: Risk Index, GNN Attention, Window Seq, Lead Time
│   │   ├── MainThreatTopologyView.tsx # Primary multi-stage attack topology cockpit & target risk breakdown
│   │   ├── TopologyGraph.tsx          # SVG-based interactive host-communication graph with GAT edge glow
│   │   ├── TrajectoryForecast.tsx     # K-step infiltration projection chart, MC Dropout CI, MITRE stages
│   │   ├── WhatIfCentre.tsx           # Counterfactual mitigation simulator (isolate host, block port)
│   │   ├── ExplainabilitySection.tsx  # GAT attention & SHAP feature importance breakdown
│   │   ├── CaptureUploadModal.tsx     # Modal for uploading PCAP/NetFlow CSV or loading curated presets
│   │   ├── CaptureUtilityBar.tsx      # Active capture badge and quick preset switchbar
│   │   ├── VashikaranChakraLogo.tsx   # Custom SVG emblem component with rotation animations
│   │   └── HeroSection.tsx            # Sub-banner summary of system status
│   ├── data/
│   │   └── initialData.ts     # Offline fallback datasets, preset captures, mock alert feeds
│   └── utils/
│       ├── api.ts             # REST client wrapper for /api endpoints
│       └── audio.ts           # Web Audio API cyber-tone generator for threat alerts & actions
```

---

## 3. Core Component Architecture

### A. `App.tsx` (Root Orchestrator)
- **Navigation Tabs (`NavigationTab`)**:
  1. `main_topology`: Primary Threat Topology & Infiltration Target View.
  2. `trajectory`: $K$-Step Trajectory Forecast & Kill-Chain progression.
  3. `what_if`: Counterfactual "What-If" Simulation Centre.
  4. `explainability`: GAT Attention Weights & SHAP Feature Explanations.
- **Theme Modes (`AppTheme`)**: `'light'` (default clean white theme), `'slate'` (dark blue-gray), and `'midnight'` (deep cyber dark). Persisted in `localStorage`.
- **Telemetry Loop**: 5-second polling cadence hitting `/api/network`, `/api/telemetry`, and `/api/alerts` with automatic fallback to `initialData.ts` if offline.
- **Audio Alerts**: Real-time auditory warning cues (`playCyberTone`) triggered on critical MITRE stage escalations or mitigation deployment.

### B. `MainThreatTopologyView.tsx`
- Comprehensive threat visualization combining the interactive SVG `TopologyGraph` on the left and a detailed **Predicted Next Target Card** on the right.
- Visualizes:
  - Compromised nodes (Red / Pulsing ring)
  - Next targeted victim (Amber / Orange warning)
  - Isolated nodes (Muted / Slotted with padlock badge)
  - GAT attention edges (colored and sized by attention weight $\alpha_{ij}$)
- Displays root-cause risk factors (`ProbabilityIssue[]`) and suggested one-click mitigation buttons.

### C. `TrajectoryForecast.tsx`
- Plots trajectory $P(\text{Infiltration}_{t+k})$ across $K=4$ future non-overlapping windows ($t+5\text{s}$ through $t+20\text{s}$).
- Renders **Monte Carlo Dropout 95% Confidence Intervals** (shaded upper/lower bounds).
- Displays counterfactual trajectory comparison lines when mitigation policies are simulated.
- Visualizes the 7-step MITRE ATT&CK kill-chain stage progression.

### D. `WhatIfCentre.tsx` (Counterfactual Engine)
- Enables sub-50ms counterfactual testing before enacting network containment policies:
  - **Isolate Host**: Dynamically severs all inbound/outbound edges for a selected node.
  - **Block Port**: Removes edges targeting specific vulnerability ports (e.g. 445 SMB, 8080 HTTP, 3389 RDP).
- Computes risk reduction $\Delta \text{Risk}$ and updates the forecast trajectory in real-time.
- Maintains a persistent session history of deployed vs simulated interventions.

### E. `ExplainabilitySection.tsx`
- Edge-level GAT attention inspector: clicking any edge in the graph displays its full telemetry profile, protocol, port, and top SHAP feature contributions (e.g. SYN Flag Ratio, Port Entropy, Packet Inter-Arrival Variance).

### F. `CaptureUploadModal.tsx` & `CaptureUtilityBar.tsx`
- Drag-and-drop or file upload for `.pcap`, `.pcapng`, `.csv`, `.json`, `.log` files.
- Includes pre-packaged forensic presets:
  - `preset-bruteforce-ssh`: CIC-IDS2018 SSH-Bruteforce scenario.
  - `preset-dos-slowloris`: Slowloris HTTP exhaustion attack.
  - `preset-infil-lateral`: Multi-hop lateral movement campaign.
  - `preset-c2-beacon`: High-entropy beaconing to external C2.

---

## 4. API Endpoints (`frontend/server.ts`)

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/network` | `GET` | Current network graph (hosts, edges, attacked nodes, predicted target, active capture) |
| `/api/telemetry` | `GET` | Aggregate live metrics (risk index, lead time, attention spike, window seq) |
| `/api/alerts` | `GET` | Stream of live security alerts with MITRE stage mapping |
| `/api/forecast` | `GET` | $K$-step forecast points, kill chain stages, entropy, and baseline vs counterfactual risk |
| `/api/explainability` | `GET` | Detailed GAT attention and SHAP feature importance for a specified `edgeId` |
| `/api/simulations` | `GET` | List of simulated counterfactual interventions in memory |
| `/api/actions/isolate` | `POST` | Isolate or un-isolate a specific host by `hostId` |
| `/api/actions/block-port`| `POST` | Block a specific port on a host |
| `/api/actions/simulate` | `POST` | Test hypothetical risk delta for an action |
| `/api/actions/deploy` | `POST` | Commit and deploy a mitigation action permanently to live state |
| `/api/actions/reset` | `POST` | Reset simulations and restores original network topology |
| `/api/captures/presets` | `GET` | Curated offline dataset captures |
| `/api/captures/load-preset` | `POST` | Load a curated scenario into active state |
| `/api/upload-capture` | `POST` | Upload user capture file (PCAP/CSV) and parse nodes/edges |
| `/api/captures/reset` | `POST` | Clear uploaded capture and restore baseline state |

---

## 5. Development & Running

### Starting Development Server
From the project root:
```bash
cd frontend
npm run dev
```
Runs `tsx server.ts` on `http://0.0.0.0:3000`, which hosts the Express REST API and attaches the Vite SPA development server.

### Production Build
```bash
cd frontend
npm run build
npm run start
```
Compiles Vite client assets into `frontend/dist/` and bundles `server.ts` into `frontend/dist/server.cjs`.

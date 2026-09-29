import {
  NetworkHost,
  NetworkEdge,
  SimulationRecord,
  ForecastPoint,
  FeatureImportance,
  KillChainStage,
  TelemetryAlert,
  SourceExplainabilityProfile,
  PredictResponse,
  CounterfactualResponse,
  BenchmarkSummary,
  RankedIntervention,
  OODAutoencoderState,
  ModelArchitectureTelemetry
} from '../types';

/* ========================================================================== */
/* SECTION 2 - LAYER B: Interactive Network Graph Sample Topology             */
/* ========================================================================== */

export const INITIAL_HOSTS: NetworkHost[] = [
  {
    id: 'c2-ext',
    name: 'C2-EXT',
    ip: '185.220.101.4',
    role: 'External Adversary C2 Node',
    segment: 'dmz',
    status: 'compromised',
    x: 8,
    y: 72,
    openPorts: [443, 8443],
    attentionScore: 0.96,
    os: 'Unknown Linux (Bulletproof ASN)',
    inboundEdges: 0,
    outboundEdges: 2
  },
  {
    id: 'app-07',
    name: 'APP-07',
    ip: '10.0.0.22',
    role: 'Internal API Gateway & Auth',
    segment: 'dmz',
    status: 'compromised',
    x: 32,
    y: 68,
    openPorts: [80, 443, 8080, 5432],
    attentionScore: 0.88,
    os: 'Ubuntu LTS 22.04',
    inboundEdges: 2,
    outboundEdges: 3
  },
  {
    id: 'srv-dc01',
    name: 'SRV-DC01',
    ip: '10.0.0.15',
    role: 'Primary Domain Controller',
    segment: 'corporate',
    status: 'targeted',
    x: 52,
    y: 28,
    openPorts: [53, 88, 135, 389, 445, 636],
    attentionScore: 0.94,
    os: 'Windows Server 2022 Core',
    inboundEdges: 4,
    outboundEdges: 3
  },
  {
    id: 'ws-042',
    name: 'WS-042',
    ip: '10.0.0.5',
    role: 'Workstation - Finance Dept',
    segment: 'corporate',
    status: 'targeted',
    x: 18,
    y: 30,
    openPorts: [135, 445, 3389],
    attentionScore: 0.74,
    os: 'Windows 11 Enterprise (23H2)',
    inboundEdges: 3,
    outboundEdges: 2
  },
  {
    id: 'db-02',
    name: 'DB-02',
    ip: '10.0.0.31',
    role: 'Customer Ledger & SQL Storage',
    segment: 'corporate',
    status: 'normal',
    x: 82,
    y: 60,
    openPorts: [5432, 9100],
    attentionScore: 0.58,
    os: 'RHEL 9.2 Enterprise',
    inboundEdges: 2,
    outboundEdges: 0
  }
];

export const INITIAL_EDGES: NetworkEdge[] = [
  {
    id: 'e-app07-dc01',
    source: 'app-07',
    target: 'srv-dc01',
    type: 'attack',
    weight: 0.92,
    port: 445,
    protocol: 'SMB / PsExec',
    attention: 0.92
  },
  {
    id: 'e-c2-app07',
    source: 'c2-ext',
    target: 'app-07',
    type: 'attack',
    weight: 0.88,
    port: 443,
    protocol: 'HTTPS / RevShell',
    attention: 0.88
  },
  {
    id: 'e-dc01-ws042',
    source: 'srv-dc01',
    target: 'ws-042',
    type: 'elevated',
    weight: 0.68,
    port: 3389,
    protocol: 'RDP Sync',
    attention: 0.68
  },
  {
    id: 'e-srvdc01-db02',
    source: 'srv-dc01',
    target: 'db-02',
    type: 'elevated',
    weight: 0.61,
    port: 5432,
    protocol: 'DB Client Access',
    attention: 0.61
  },
  {
    id: 'e-ws042-app07',
    source: 'ws-042',
    target: 'app-07',
    type: 'normal',
    weight: 0.35,
    port: 8080,
    protocol: 'HTTP Internal API',
    attention: 0.35
  }
];

/* ========================================================================== */
/* SECTION 2 - LAYER B: 8-Step Timeline Forecast & Monte Carlo 95% CI Bounds  */
/* ========================================================================== */

export const FORECAST_POINTS: ForecastPoint[] = [
  { timeLabel: '-30s', seconds: -30, actual: 40, baseline: 40, ciUpper: 46, ciLower: 34 },
  { timeLabel: '-20s', seconds: -20, actual: 58, baseline: 58, ciUpper: 64, ciLower: 52 },
  { timeLabel: '-10s', seconds: -10, actual: 77, baseline: 77, ciUpper: 83, ciLower: 71 },
  { timeLabel: 'NOW', seconds: 0, isNow: true, actual: 94, baseline: 94, counterfactual: 94, ciUpper: 98, ciLower: 90 },
  { timeLabel: '+10s', seconds: 10, baseline: 98, counterfactual: 26, ciUpper: 100, ciLower: 88 },
  { timeLabel: '+20s', seconds: 20, baseline: 99, counterfactual: 21, ciUpper: 100, ciLower: 86 },
  { timeLabel: '+30s', seconds: 30, baseline: 100, counterfactual: 15, ciUpper: 100, ciLower: 84 },
  { timeLabel: '+60s', seconds: 60, baseline: 100, counterfactual: 11, ciUpper: 100, ciLower: 82 }
];

export const INITIAL_SIMULATIONS: SimulationRecord[] = [
  {
    id: 'sim-init-1',
    actionType: 'isolate_host',
    actionLabel: 'Isolate APP-07 (Gateway)',
    targetId: 'app-07',
    targetLabel: 'APP-07 (10.0.0.22)',
    timeAgo: 'Just now',
    initialRisk: 94,
    simulatedRisk: 12,
    delta: 82,
    timestamp: Date.now() - 60000
  },
  {
    id: 'sim-init-2',
    actionType: 'block_port',
    actionLabel: 'Block Port 445 (SMB) on SRV-DC01',
    targetId: 'srv-dc01',
    targetLabel: 'SRV-DC01 (10.0.0.15)',
    port: 445,
    timeAgo: '5m ago',
    initialRisk: 94,
    simulatedRisk: 22,
    delta: 72,
    timestamp: Date.now() - 300000
  }
];

export const FEATURE_IMPORTANCES: FeatureImportance[] = [
  {
    id: 'f-1',
    code: 'GNN_ATTN_WEIGHT',
    label: 'Graph Attention Link Weight (0.92)',
    percentage: 35,
    severity: 'high'
  },
  {
    id: 'f-2',
    code: 'PORT_VULNERABILITY',
    label: 'Destination Port 445 (SMB / PsExec) Attack Vector',
    percentage: 28,
    severity: 'high'
  },
  {
    id: 'f-3',
    code: 'SESSION_BURST',
    label: 'Anomalous Connection Density & SYN Asymmetry',
    percentage: 20,
    severity: 'medium'
  },
  {
    id: 'f-4',
    code: 'SUB_TOPOLOGY_PATH',
    label: 'Network Traversal Path (dmz -> corporate)',
    percentage: 14,
    severity: 'low'
  }
];

export const SOURCE_EXPLAINABILITY_MAP: Record<string, SourceExplainabilityProfile> = {
  // 1. APP-07 -> SRV-DC01 (Specification Primary Flagged Edge)
  'e-app07-dc01': {
    edgeId: 'e-app07-dc01',
    sourceId: 'app-07',
    sourceName: 'APP-07',
    sourceIp: '10.0.0.22',
    targetId: 'srv-dc01',
    targetName: 'SRV-DC01',
    targetIp: '10.0.0.15',
    protocol: 'SMB / PsExec',
    port: 445,
    attention: 0.92,
    mitreTactic: 'TA0008 (Lateral Movement)',
    mitreTacticCode: 'TA0008',
    predictedStage: 'Lateral movement',
    riskScore: 94,
    riskTrend: '12',
    leadTime: '+18.5s',
    leadTimeDelta: '+3.2s',
    portEntropy: 3.2,
    synRatio: 0.94,
    logByteVolume: 12.6,
    summary: 'Spatial graph attention model evaluated link from APP-07 to SRV-DC01 on Port 445 (SMB / PsExec) with 0.92 attention weight.',
    features: [
      {
        id: 'f-1',
        code: 'GNN_ATTN_WEIGHT',
        label: 'Graph Attention Link Weight (0.92)',
        percentage: 35,
        severity: 'high'
      },
      {
        id: 'f-2',
        code: 'PORT_VULNERABILITY',
        label: 'Destination Port 445 (SMB / PsExec) Attack Vector',
        percentage: 28,
        severity: 'high'
      },
      {
        id: 'f-3',
        code: 'SESSION_BURST',
        label: 'Anomalous Connection Density & SYN Asymmetry',
        percentage: 20,
        severity: 'medium'
      },
      {
        id: 'f-4',
        code: 'SUB_TOPOLOGY_PATH',
        label: 'Network Traversal Path (dmz -> corporate)',
        percentage: 14,
        severity: 'low'
      }
    ]
  },

  // 2. C2-EXT -> APP-07 (External C2 ingress)
  'e-c2-app07': {
    edgeId: 'e-c2-app07',
    sourceId: 'c2-ext',
    sourceName: 'C2-EXT',
    sourceIp: '185.220.101.4',
    targetId: 'app-07',
    targetName: 'APP-07',
    targetIp: '10.0.0.22',
    protocol: 'HTTPS / RevShell',
    port: 443,
    attention: 0.88,
    mitreTactic: 'TA0011 (Command and Control)',
    mitreTacticCode: 'TA0011',
    predictedStage: 'Initial C2 Ingress',
    riskScore: 96,
    riskTrend: '24',
    leadTime: '+22.8s',
    leadTimeDelta: '+5.4s',
    portEntropy: 1.8,
    synRatio: 0.99,
    logByteVolume: 28.4,
    summary: 'Direct inbound encrypted C2 telemetry stream detected from external Tor/bulletproof host C2-EXT establishing a malleable reverse shell on APP-07.',
    features: [
      { id: 'f-c2-1', code: 'dst_port: 443 (HTTPS C2)', label: 'Cobalt Strike beaconing', percentage: 48, severity: 'high' },
      { id: 'f-c2-2', code: 'beacon_jitter: 14.2%', label: 'Malleable C2 profile', percentage: 26, severity: 'high' },
      { id: 'f-c2-3', code: 'ja3_mismatch: 0.96', label: 'Unrecognized TLS client', percentage: 16, severity: 'medium' },
      { id: 'f-c2-4', code: 'ingress_burst: 1.8k/s', label: 'Payload dropper stream', percentage: 10, severity: 'low' }
    ]
  },

  // 3. SRV-DC01 -> WS-042 (Reverse RDP pivot)
  'e-dc01-ws042': {
    edgeId: 'e-dc01-ws042',
    sourceId: 'srv-dc01',
    sourceName: 'SRV-DC01',
    sourceIp: '10.0.0.15',
    targetId: 'ws-042',
    targetName: 'WS-042',
    targetIp: '10.0.0.5',
    protocol: 'RDP Sync',
    port: 3389,
    attention: 0.68,
    mitreTactic: 'TA0006 (Privilege Escalation)',
    mitreTacticCode: 'TA0006',
    predictedStage: 'Privilege Escalation & RDP',
    riskScore: 76,
    riskTrend: '8',
    leadTime: '+14.1s',
    leadTimeDelta: '+1.9s',
    portEntropy: 2.7,
    synRatio: 0.88,
    logByteVolume: 8.9,
    summary: 'Reverse lateral pivot observed from Domain Controller to Finance workstation WS-042 via interactive RDP with ticket reuse.',
    features: [
      { id: 'f-dc-1', code: 'dst_port: 3389 (RDP)', label: 'Unauthorized remote desk', percentage: 39, severity: 'high' },
      { id: 'f-dc-2', code: 'auth_ticket: Kerberos RC4', label: 'Overpass-the-Hash vector', percentage: 31, severity: 'high' },
      { id: 'f-dc-3', code: 'session_concurrency: 7', label: 'Anomalous admin burst', percentage: 19, severity: 'medium' },
      { id: 'f-dc-4', code: 'pipe_name: \\pipe\\spoolss', label: 'Print Spooler RPC probe', percentage: 11, severity: 'low' }
    ]
  },

  // 4. SRV-DC01 -> DB-02 (Database exfiltration staging)
  'e-srvdc01-db02': {
    edgeId: 'e-srvdc01-db02',
    sourceId: 'srv-dc01',
    sourceName: 'SRV-DC01',
    sourceIp: '10.0.0.15',
    targetId: 'db-02',
    targetName: 'DB-02',
    targetIp: '10.0.0.31',
    protocol: 'DB Client Access',
    port: 5432,
    attention: 0.61,
    mitreTactic: 'TA0010 (Exfiltration)',
    mitreTacticCode: 'TA0010',
    predictedStage: 'Exfiltration Staging',
    riskScore: 62,
    riskTrend: '5',
    leadTime: '+9.5s',
    leadTimeDelta: '+1.1s',
    portEntropy: 2.1,
    synRatio: 0.81,
    logByteVolume: 48.2,
    summary: 'High-volume PostgreSQL queries executed from Domain Controller service account dumping customer tables on DB-02.',
    features: [
      { id: 'f-db-1', code: 'dst_port: 5432 (PostgreSQL)', label: 'High-volume query spike', percentage: 45, severity: 'high' },
      { id: 'f-db-2', code: 'table_scan_rows: 840K', label: 'Customer data dump', percentage: 29, severity: 'high' },
      { id: 'f-db-3', code: 'svc_acct_reuse: true', label: 'Service account misuse', percentage: 15, severity: 'medium' },
      { id: 'f-db-4', code: 'outbound_data: 48MB', label: 'Exfiltration staging buffer', percentage: 11, severity: 'low' }
    ]
  },

  // 5. WS-042 -> APP-07 (Internal API reconnaissance)
  'e-ws042-app07': {
    edgeId: 'e-ws042-app07',
    sourceId: 'ws-042',
    sourceName: 'WS-042',
    sourceIp: '10.0.0.5',
    targetId: 'app-07',
    targetName: 'APP-07',
    targetIp: '10.0.0.22',
    protocol: 'HTTP Internal API',
    port: 8080,
    attention: 0.35,
    mitreTactic: 'TA0043 (Reconnaissance)',
    mitreTacticCode: 'TA0043',
    predictedStage: 'Internal Reconnaissance',
    riskScore: 48,
    riskTrend: '3',
    leadTime: '+31.2s',
    leadTimeDelta: '+6.8s',
    portEntropy: 4.1,
    synRatio: 0.75,
    logByteVolume: 5.3,
    summary: 'Finance workstation WS-042 issuing high-frequency REST API calls with mutated auth tokens toward gateway APP-07.',
    features: [
      { id: 'f-ws-1', code: 'dst_port: 8080 (REST API)', label: 'JWT token fuzzing / IDOR', percentage: 36, severity: 'high' },
      { id: 'f-ws-2', code: 'http_500_ratio: 0.72', label: 'Internal API error burst', percentage: 30, severity: 'high' },
      { id: 'f-ws-3', code: 'agent: Python-requests', label: 'Automated scanner signature', percentage: 20, severity: 'medium' },
      { id: 'f-ws-4', code: 'req_burst: 120 req/s', label: 'Rate limit violation', percentage: 14, severity: 'low' }
    ]
  }
};

export const getExplainabilityForEdge = (edge: NetworkEdge): SourceExplainabilityProfile => {
  if (SOURCE_EXPLAINABILITY_MAP[edge.id]) {
    return SOURCE_EXPLAINABILITY_MAP[edge.id];
  }
  // Fallback if custom edge
  return {
    edgeId: edge.id,
    sourceId: edge.source,
    sourceName: edge.source.toUpperCase(),
    sourceIp: '10.0.0.x',
    targetId: edge.target,
    targetName: edge.target.toUpperCase(),
    targetIp: '10.0.0.y',
    protocol: edge.protocol,
    port: edge.port,
    attention: edge.attention,
    mitreTactic: 'TA0008 (Lateral Movement)',
    mitreTacticCode: 'TA0008',
    predictedStage: 'Lateral Propagation',
    riskScore: Math.round(edge.attention * 100),
    riskTrend: '5',
    leadTime: '+15.0s',
    leadTimeDelta: '+2.0s',
    portEntropy: 2.5,
    synRatio: 0.85,
    logByteVolume: 10.0,
    summary: `Observed network interaction from source ${edge.source.toUpperCase()} to ${edge.target.toUpperCase()} via port ${edge.port}.`,
    features: [
      { id: 'f-gen-1', code: `dst_port: ${edge.port} (${edge.protocol})`, label: 'Active connection', percentage: 40, severity: 'high' },
      { id: 'f-gen-2', code: `attention_weight: ${edge.attention.toFixed(2)}`, label: 'Spatial attention anomaly', percentage: 30, severity: 'high' },
      { id: 'f-gen-3', code: 'flow_type: ' + edge.type, label: 'Graph link categorization', percentage: 20, severity: 'medium' },
      { id: 'f-gen-4', code: 'syn_state: established', label: 'Transport level metric', percentage: 10, severity: 'low' }
    ]
  };
};

export const getExplainabilityForSource = (sourceHostId: string): SourceExplainabilityProfile => {
  const matchingKey = Object.keys(SOURCE_EXPLAINABILITY_MAP).find(
    (key) => SOURCE_EXPLAINABILITY_MAP[key].sourceId === sourceHostId
  );
  if (matchingKey) {
    return SOURCE_EXPLAINABILITY_MAP[matchingKey];
  }
  return SOURCE_EXPLAINABILITY_MAP['e-app07-dc01'];
};

export const KILL_CHAIN_STAGES: KillChainStage[] = [
  { step: 1, name: 'Reconnaissance', status: 'completed', tacticId: 'TA0043' },
  { step: 2, name: 'Resource Development', status: 'completed', tacticId: 'TA0042' },
  { step: 3, name: 'Initial Access', status: 'completed', tacticId: 'TA0001' },
  { step: 4, name: 'Execution & C2', status: 'active', tacticId: 'TA0002 / TA0011' },
  { step: 5, name: 'Lateral Movement', status: 'upcoming', tacticId: 'TA0008' }
];

export const INITIAL_ALERTS: TelemetryAlert[] = [
  {
    id: 'alt-target',
    timestamp: '01:50:32',
    severity: 'critical',
    source: 'APP-07',
    target: 'SRV-DC01 (10.0.0.15)',
    message: 'SMB / PsExec Remote Execution from APP-07',
    port: 445
  },
  {
    id: 'alt-c2',
    timestamp: '01:48:15',
    severity: 'high',
    source: 'C2-EXT (185.220.101.4)',
    target: 'APP-07 (10.0.0.22)',
    message: 'Encrypted C2 reverse shell telemetry beacon active on port 443',
    port: 443
  },
  {
    id: 'alt-recon',
    timestamp: '01:42:00',
    severity: 'medium',
    source: 'WS-042 (10.0.0.5)',
    target: 'SRV-DC01 (10.0.0.15)',
    message: 'Anomalous SYN handshake asymmetry targeting RPC endpoints',
    port: 135
  }
];

/* ========================================================================== */
/* SECTION 1 & 2 - LAYER A: Python ML World Model Sample Data from Spec       */
/* ========================================================================== */

export const ML_PREDICT_SAMPLE: PredictResponse = {
  timeline: [
    {
      t: 105.0,
      infiltration_prob: 0.74,
      stage: 'Lateral Movement',
      stage_conf: 0.82
    },
    {
      t: 110.0,
      infiltration_prob: 0.81,
      stage: 'Lateral Movement',
      stage_conf: 0.86
    }
  ],
  current_stage: 'Lateral Movement',
  mitre_technique: 'T1021 (Lateral Movement)',
  forecast_K: 4,
  top_features: [
    { name: 'syn_ratio', contribution: 0.34 },
    { name: 'port_entropy', contribution: 0.28 },
    { name: 'flow_bytes', contribution: 0.21 },
    { name: 'ack_ratio', contribution: 0.17 }
  ],
  flagged_edges: [
    {
      src: '10.0.0.22',
      dst: '10.0.0.15',
      attn: 0.924
    },
    {
      src: '185.220.101.4',
      dst: '10.0.0.22',
      attn: 0.881
    }
  ],
  ood_score: 0.12,
  uncertainty_std: 0.058,
  lead_time_seconds: 15.2
};

export const INITIAL_COUNTERFACTUAL_SAMPLE: CounterfactualResponse = {
  action: 'isolate_host',
  target: '10.0.0.22 (APP-07)',
  original_risk: 0.94,
  recalculated_risk: 0.12,
  risk_reduction: 0.82,
  business_disruption_cost: 0.14,
  net_defense_score: 0.68,
  stage_after_action: 'Benign',
  latency_ms: 18.6,
  collateral_severed_edges: 3,
  severed_connections_summary: 'Severed 3 lateral links (10.0.0.22 <-> 10.0.0.15, 10.0.0.5, 10.0.0.72) halting traversal'
};

export const INITIAL_RANKED_INTERVENTIONS: RankedIntervention[] = [
  {
    rank: 1,
    action: 'isolate_host',
    actionLabel: 'Isolate Host',
    target: '10.0.0.22',
    targetLabel: 'APP-07 (Compromised API Gateway)',
    riskReduction: 0.82,
    businessDisruptionCost: 0.14,
    netDefenseScore: 0.68,
    latencyMs: 18.6,
    collateralSeveredEdges: 3,
    projectedStage: 'Benign',
    recommended: true,
    rationale: 'Decouples primary pivot bridge, collapses lateral traversal towards SRV-DC01 while preserving internal corporate subnets.',
    details: 'Mathematically removes APP-07 edge weights, dropping risk from 0.94 to 0.12 in 18.6ms.'
  },
  {
    rank: 2,
    action: 'block_port',
    actionLabel: 'Block Port',
    target: '445',
    targetLabel: 'Port 445 (SMB) across DMZ Boundary',
    riskReduction: 0.61,
    businessDisruptionCost: 0.08,
    netDefenseScore: 0.53,
    latencyMs: 14.2,
    collateralSeveredEdges: 1,
    projectedStage: 'Internal Recon',
    recommended: false,
    rationale: 'Stops DCE/RPC & SMB pipe exploitation; leaves secondary HTTP/8080 API vector partially open.',
    details: 'Drops SMB propagation risk to 0.33 with minimal collateral impact on non-file traffic.'
  },
  {
    rank: 3,
    action: 'segment_subnet',
    actionLabel: 'Segment Subnet',
    target: '10.0.0.0/24',
    targetLabel: 'Cut Subnet 10.0.0.0/24 from 192.168.1.0/24',
    riskReduction: 0.76,
    businessDisruptionCost: 0.28,
    netDefenseScore: 0.48,
    latencyMs: 22.4,
    collateralSeveredEdges: 8,
    projectedStage: 'Containment Zone',
    recommended: false,
    rationale: 'Prevents cross-subnet lateral penetration, but incurs higher business disruption by severing finance API sync.',
    details: 'Isolates entire DMZ subnet from Corporate VLAN, severing 8 active data pipes.'
  },
  {
    rank: 4,
    action: 'honeypot_divert',
    actionLabel: 'Honeypot Divert',
    target: '10.0.99.100',
    targetLabel: 'Reroute C2 Flow to Decoy Sink (10.0.99.100)',
    riskReduction: 0.52,
    businessDisruptionCost: 0.05,
    netDefenseScore: 0.47,
    latencyMs: 19.1,
    collateralSeveredEdges: 0,
    projectedStage: 'Deception Trap',
    recommended: false,
    rationale: 'Silently traps external C2 in honeypot sandbox without alerting threat actor; internal pivot requires secondary mitigation.',
    details: 'Reroutes flow table entries to isolated high-interaction deception container.'
  },
  {
    rank: 5,
    action: 'rate_limit',
    actionLabel: 'Rate Limit',
    target: '8080',
    targetLabel: 'Rate Limit 0.5x on Port 8080 & SYN Flows',
    riskReduction: 0.38,
    businessDisruptionCost: 0.04,
    netDefenseScore: 0.34,
    latencyMs: 11.8,
    collateralSeveredEdges: 0,
    projectedStage: 'Lateral Movement',
    recommended: false,
    rationale: 'Mitigates buffer exhaustion and dampens SYN flood packet dynamics, but does not eradicate authenticated credential spray.',
    details: 'Applies token bucket dampening to suppress volume spikes by 50%.'
  }
];

export const INITIAL_OOD_STATE: OODAutoencoderState = {
  oodScore: 0.12,
  reconstructionError: 0.048,
  reconstructionThreshold: 0.150,
  isZeroDayAnomaly: false,
  homoscedasticUncertaintySigma: 0.042,
  latentBottleneckDim: 32,
  zeroDayAlertMessage: 'Latent space reconstruction nominal. Topology flow vectors match known training manifold.'
};

export const INITIAL_MODEL_ARCHITECTURE: ModelArchitectureTelemetry = {
  edgeDropoutRate: 0.15,
  denseAttentionCollapsePrevented: true,
  vectorizedFlowSpeedup: '14.8x speedup (np.where + np.char.add)',
  flowAggregationLatencyMs: 7.8,
  inferenceEngineCli: 'Standalone dpkt CLI (scripts/run_inference.py - no Scapy hang)',
  avgCounterfactualLatencyMs: 18.2
};

export const BENCHMARK_SUMMARY_SAMPLE: BenchmarkSummary = {
  world_model: {
    f1: 0.941,
    precision: 0.952,
    recall: 0.931,
    fpr: 0.018,
    auroc: 0.974,
    brier_score: 0.058,
    lead_time_seconds: 15.2
  },
  logistic_baseline: {
    f1: 0.682,
    precision: 0.651,
    recall: 0.718,
    fpr: 0.145,
    auroc: 0.742,
    brier_score: 0.221,
    lead_time_seconds: 0.0
  }
};

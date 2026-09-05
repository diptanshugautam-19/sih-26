import {
  NetworkHost,
  NetworkEdge,
  SimulationRecord,
  ForecastPoint,
  FeatureImportance,
  KillChainStage,
  TelemetryAlert,
  SourceExplainabilityProfile
} from '../types';

export const INITIAL_HOSTS: NetworkHost[] = [
  {
    id: 'ws-042',
    name: 'WS-042',
    ip: '10.0.0.5',
    role: 'Workstation - Finance Dept',
    segment: 'corporate',
    status: 'targeted',
    x: 12,
    y: 28,
    openPorts: [135, 445, 3389],
    attentionScore: 0.78,
    os: 'Windows 11 Enterprise (23H2)',
    inboundEdges: 3,
    outboundEdges: 2
  },
  {
    id: 'srv-dc01',
    name: 'SRV-DC01',
    ip: '10.0.0.15',
    role: 'Primary Domain Controller',
    segment: 'corporate',
    status: 'compromised',
    x: 44,
    y: 22,
    openPorts: [53, 88, 135, 389, 445, 636],
    attentionScore: 0.92,
    os: 'Windows Server 2022 Core',
    inboundEdges: 4,
    outboundEdges: 3
  },
  {
    id: 'app-07',
    name: 'APP-07',
    ip: '10.0.0.22',
    role: 'Internal API Gateway & Auth',
    segment: 'corporate',
    status: 'compromised',
    x: 32,
    y: 68,
    openPorts: [80, 443, 8080, 5432],
    attentionScore: 0.85,
    os: 'Ubuntu LTS 22.04',
    inboundEdges: 2,
    outboundEdges: 3
  },
  {
    id: 'db-02',
    name: 'DB-02',
    ip: '10.0.0.31',
    role: 'Primary Customer Datastore',
    segment: 'corporate',
    status: 'elevated',
    x: 72,
    y: 38,
    openPorts: [5432, 27017],
    attentionScore: 0.64,
    os: 'Debian 12 Bookworm',
    inboundEdges: 3,
    outboundEdges: 1
  },
  {
    id: 'c2-ext',
    name: 'C2-EXT',
    ip: '185.220.101.4',
    role: 'External Malicious Ingress / C2 Node',
    segment: 'dmz',
    status: 'compromised',
    x: 88,
    y: 72,
    openPorts: [443, 8443, 9001],
    attentionScore: 0.96,
    os: 'Unknown Host (Tor Exit/Bulletproof VPS)',
    inboundEdges: 1,
    outboundEdges: 4
  }
];

export const INITIAL_EDGES: NetworkEdge[] = [
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

export const FORECAST_POINTS: ForecastPoint[] = [
  { timeLabel: '-20s', seconds: -20, actual: 24, baseline: 24, ciUpper: 30, ciLower: 18 },
  { timeLabel: '-15s', seconds: -15, actual: 32, baseline: 32, ciUpper: 39, ciLower: 25 },
  { timeLabel: '-10s', seconds: -10, actual: 44, baseline: 44, ciUpper: 52, ciLower: 36 },
  { timeLabel: '-5s', seconds: -5, actual: 61, baseline: 61, ciUpper: 69, ciLower: 53 },
  { timeLabel: 'NOW', seconds: 0, isNow: true, actual: 87, baseline: 87, counterfactual: 87, ciUpper: 93, ciLower: 81 },
  { timeLabel: '+5s', seconds: 5, baseline: 92, counterfactual: 58, ciUpper: 96, ciLower: 78 },
  { timeLabel: '+10s', seconds: 10, baseline: 95, counterfactual: 34, ciUpper: 98, ciLower: 62 },
  { timeLabel: '+15s', seconds: 15, baseline: 98, counterfactual: 20, ciUpper: 100, ciLower: 48 },
  { timeLabel: '+20s', seconds: 20, baseline: 99, counterfactual: 12, ciUpper: 100, ciLower: 38 }
];

export const INITIAL_SIMULATIONS: SimulationRecord[] = [
  {
    id: 'sim-1',
    actionType: 'block_port',
    actionLabel: 'Block 445',
    targetId: 'ws-042',
    targetLabel: 'WS-042',
    port: 445,
    timeAgo: '4m ago',
    initialRisk: 87,
    simulatedRisk: 24,
    delta: -63,
    timestamp: Date.now() - 240000
  },
  {
    id: 'sim-2',
    actionType: 'isolate_host',
    actionLabel: 'Isolate',
    targetId: 'app-07',
    targetLabel: 'APP-07',
    timeAgo: '12m ago',
    initialRisk: 87,
    simulatedRisk: 12,
    delta: -75,
    timestamp: Date.now() - 720000
  }
];

export const FEATURE_IMPORTANCES: FeatureImportance[] = [
  {
    id: 'f1',
    code: 'dst_port: 445 (SMB)',
    label: 'Lateral movement',
    percentage: 42,
    severity: 'high'
  },
  {
    id: 'f2',
    code: 'syn_ack_ratio: 0.94',
    label: 'Reconnaissance',
    percentage: 28,
    severity: 'high'
  },
  {
    id: 'f3',
    code: 'port_entropy: 3.2',
    label: 'Port scanning',
    percentage: 18,
    severity: 'medium'
  },
  {
    id: 'f4',
    code: 'flow_bytes: 524KB',
    label: 'Exfiltration',
    percentage: 12,
    severity: 'low'
  }
];

export const SOURCE_EXPLAINABILITY_MAP: Record<string, SourceExplainabilityProfile> = {
  // 1. APP-07 -> SRV-DC01 (Internal pivot, SMB PsExec)
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
    mitreTactic: 'TA0008 / T1021 (Remote Services / SMB)',
    mitreTacticCode: 'TA0008',
    predictedStage: 'Lateral movement',
    riskScore: 87,
    riskTrend: '12',
    leadTime: '+18.4s',
    leadTimeDelta: '+3.2s',
    portEntropy: 3.2,
    synRatio: 0.94,
    logByteVolume: 12.6,
    summary: 'Anomalous SMB payload and PsExec execution attempted from compromised API gateway APP-07 targeting Domain Controller SRV-DC01.',
    features: [
      { id: 'f-app07-1', code: 'dst_port: 445 (SMB)', label: 'Lateral movement', percentage: 42, severity: 'high' },
      { id: 'f-app07-2', code: 'syn_ack_ratio: 0.94', label: 'Reconnaissance', percentage: 28, severity: 'high' },
      { id: 'f-app07-3', code: 'port_entropy: 3.2', label: 'Port scanning', percentage: 18, severity: 'medium' },
      { id: 'f-app07-4', code: 'flow_bytes: 524KB', label: 'Credential payload', percentage: 12, severity: 'low' }
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
    mitreTactic: 'TA0011 / T1071 (Web Protocols / C2 Beacon)',
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
    mitreTactic: 'TA0006 / T1558 (Kerberoasting / Overpass-the-Hash)',
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
    mitreTactic: 'TA0010 / T1048 (Data Staging / Exfiltration)',
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
    mitreTactic: 'TA0043 / T1046 (Network Service Discovery)',
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
    mitreTactic: 'TA0008 / T1021 (Generic Vector)',
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
  { step: 1, name: 'Baseline', status: 'completed', tacticId: 'TA0001' },
  { step: 2, name: 'Recon', status: 'completed', tacticId: 'TA0043' },
  { step: 3, name: 'Initial Access', status: 'completed', tacticId: 'TA0002' },
  { step: 4, name: 'Credential', status: 'completed', tacticId: 'TA0006' },
  { step: 5, name: 'Lateral', status: 'active', tacticId: 'TA0008' },
  { step: 6, name: 'C2', status: 'upcoming', tacticId: 'TA0011' },
  { step: 7, name: 'Exfiltration', status: 'upcoming', tacticId: 'TA0010' }
];

export const INITIAL_ALERTS: TelemetryAlert[] = [
  {
    id: 'alt-1',
    timestamp: '14:32:16',
    severity: 'critical',
    source: '10.0.0.22 (APP-07)',
    target: '10.0.0.15 (SRV-DC01)',
    message: 'Anomalous SMB payload detected via port 445 (Possible Pass-the-Hash / PsExec)',
    port: 445
  },
  {
    id: 'alt-2',
    timestamp: '14:31:54',
    severity: 'high',
    source: '185.220.101.4 (C2-EXT)',
    target: '10.0.0.22 (APP-07)',
    message: 'C2 Beacon interval observed matching Cobalt Strike malleable profile',
    port: 443
  },
  {
    id: 'alt-3',
    timestamp: '14:30:20',
    severity: 'medium',
    source: '10.0.0.5 (WS-042)',
    target: '10.0.0.15 (SRV-DC01)',
    message: 'High port entropy burst detected across internal subnets',
    port: 135
  }
];

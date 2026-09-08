export type SegmentType = 'corporate' | 'dmz';

export type HostStatus = 'compromised' | 'targeted' | 'elevated' | 'normal' | 'isolated';

/* ========================================================================== */
/* SECTION 1 & 2 - LAYER A: Python FastAPI Inference Engine Contracts (:8000) */
/* ========================================================================== */

export interface MLHealthResponse {
  status: string;
  model_loaded: boolean;
  device: string;
  version: string;
}

export interface TimelinePoint {
  t: number;
  infiltration_prob: number;
  stage: string;
  stage_conf: number;
}

export interface TopFeature {
  name: string;
  contribution: number;
}

export interface FlaggedEdge {
  src: string;
  dst: string;
  attn: number;
}

export interface PredictResponse {
  timeline: TimelinePoint[];
  current_stage: string;
  mitre_technique: string;
  forecast_K: number;
  top_features: TopFeature[];
  flagged_edges: FlaggedEdge[];
  ood_score: number;
  uncertainty_std: number;
  lead_time_seconds: number;
}

export interface CounterfactualRequest {
  action: 'isolate_host' | 'block_port' | 'rate_limit' | 'segment_subnet' | 'honeypot_divert' | string;
  target: string;
  current_risk: number;
  rate_limit_factor?: number;
  source_subnet?: string;
  target_subnet?: string;
  honeypot_ip?: string;
  port?: number;
}

export interface CounterfactualResponse {
  action: string;
  target: string;
  original_risk: number;
  recalculated_risk: number;
  risk_reduction: number;
  business_disruption_cost: number;
  net_defense_score: number;
  stage_after_action: string;
  latency_ms: number;
  collateral_severed_edges: number;
  severed_connections_summary?: string;
}

export interface RankedIntervention {
  rank: number;
  action: DefenceActionType;
  actionLabel: string;
  target: string;
  targetLabel: string;
  riskReduction: number;
  businessDisruptionCost: number;
  netDefenseScore: number;
  latencyMs: number;
  collateralSeveredEdges: number;
  projectedStage: string;
  recommended: boolean;
  rationale: string;
  details?: string;
}

export interface RankCounterfactualResponse {
  optimal_action: RankedIntervention;
  ranked_interventions: RankedIntervention[];
  total_candidates_evaluated: number;
  inference_latency_ms: number;
  graph_sequence_window: number;
}

export interface OODAutoencoderState {
  oodScore: number;
  reconstructionError: number;
  reconstructionThreshold: number;
  isZeroDayAnomaly: boolean;
  homoscedasticUncertaintySigma: number;
  latentBottleneckDim: number;
  zeroDayAlertMessage?: string;
}

export interface ModelArchitectureTelemetry {
  edgeDropoutRate: number;
  denseAttentionCollapsePrevented: boolean;
  vectorizedFlowSpeedup: string;
  flowAggregationLatencyMs: number;
  inferenceEngineCli: string;
  avgCounterfactualLatencyMs: number;
}

export interface ModelBenchmarkMetrics {
  f1: number;
  precision: number;
  recall: number;
  fpr: number;
  auroc: number;
  brier_score: number;
  lead_time_seconds: number;
}

export interface BenchmarkSummary {
  world_model: ModelBenchmarkMetrics;
  logistic_baseline: ModelBenchmarkMetrics;
}

export interface MetricsApiResponse {
  status: string;
  benchmark_summary: BenchmarkSummary;
}

/* ========================================================================== */
/* SECTION 1 & 2 - LAYER B: Live SOC Gateway & Topology Contracts (:3000)    */
/* ========================================================================== */

export interface NetworkHost {
  id: string;
  name: string;
  ip: string;
  role: string;
  segment: SegmentType;
  status: HostStatus;
  x: number; // percentage in SVG or coordinate
  y: number;
  openPorts: number[];
  attentionScore: number;
  os: string;
  inboundEdges: number;
  outboundEdges: number;
}

export interface NetworkEdge {
  id: string;
  source: string;
  target: string;
  type: 'attack' | 'elevated' | 'normal';
  weight: number;
  port: number;
  protocol: string;
  attention: number;
}

export type DefenceActionType = 'isolate_host' | 'block_port' | 'rate_limit' | 'segment_subnet' | 'honeypot_divert' | 'revoke_creds';

export interface SimulationRecord {
  id: string;
  actionType: DefenceActionType;
  actionLabel: string;
  targetId: string;
  targetLabel: string;
  port?: number;
  timeAgo: string;
  initialRisk: number;
  simulatedRisk: number;
  delta: number;
  timestamp: number;
}

export interface ForecastPoint {
  timeLabel: string;
  seconds: number;
  isNow?: boolean;
  actual?: number;
  baseline: number;
  counterfactual?: number;
  ciUpper: number;
  ciLower: number;
}

export interface FeatureImportance {
  id: string;
  code: string;
  label: string;
  percentage: number;
  severity: 'high' | 'medium' | 'low';
}

export interface SourceExplainabilityProfile {
  edgeId: string;
  sourceId: string;
  sourceName: string;
  sourceIp: string;
  targetId: string;
  targetName: string;
  targetIp: string;
  protocol: string;
  port: number;
  attention: number;
  mitreTactic: string;
  mitreTacticCode: string;
  predictedStage: string;
  riskScore: number;
  riskTrend: string;
  leadTime: string;
  leadTimeDelta: string;
  portEntropy: number;
  synRatio: number;
  logByteVolume: number;
  summary: string;
  features: FeatureImportance[];
}

export interface KillChainStage {
  step: number;
  name: string;
  status: 'completed' | 'active' | 'upcoming';
  tacticId: string;
}

export interface TelemetryAlert {
  id: string;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'info';
  source: string;
  target: string;
  message: string;
  port?: number;
}

export type NavigationTab = 'main_topology' | 'trajectory' | 'what_if' | 'explainability' | 'benchmarks';

export interface ProbabilityIssue {
  id: string;
  factor: string;
  description: string;
  impactScore: number;
  severity: 'critical' | 'high' | 'medium';
  category: 'protocol_flaw' | 'credential_leak' | 'network_path' | 'attention_spike' | 'zero_trust_gap';
}

export interface PredictedTargetNode {
  hostId: string;
  name: string;
  role: string;
  ip: string;
  segment: SegmentType;
  os: string;
  probabilityPercent: number;
  timeToAttackSeconds: number;
  timeToAttackLabel: string;
  predictedAttackVector: string;
  primarySourceId: string;
  primarySourceName: string;
  incomingPort: number;
  protocol: string;
  mitreTactic: string;
  mitreTacticCode: string;
  probabilityIssues: ProbabilityIssue[];
  recommendedMitigations: string[];
}

export interface CaptureMetadata {
  id: string;
  fileName: string;
  fileType: 'pcap' | 'pcapng' | 'csv' | 'json' | 'log' | 'other';
  fileSize: number;
  packetCount: number;
  flowCount: number;
  durationSeconds: number;
  protocolsDetected: string[];
  threatNodesDetected: number;
  uploadedAt: string;
}

export interface PresetCapture {
  id: string;
  title: string;
  fileName: string;
  fileType: string;
  sizeLabel: string;
  description: string;
  targetFocus: string;
  probability: number;
  threatType: string;
}

export interface NetworkApiResponse {
  hosts: NetworkHost[];
  edges: NetworkEdge[];
  attackedNodes: NetworkHost[];
  predictedNextTarget: PredictedTargetNode;
  windowSeq: number;
  isolatedHostIds: string[];
  blockedPorts: { [hostId: string]: number[] };
  lastUpdated: string;
  activeCapture?: CaptureMetadata | null;
}

export type AppTheme = 'slate' | 'light' | 'midnight';

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: 'Lead Threat Analyst' | 'SOC Incident Commander' | 'Tier-3 Forensics Officer' | 'Cyber Defense Operator';
  clearance: string;
  callsign: string;
  badgeId: string;
  station: string;
  loginTime: string;
}

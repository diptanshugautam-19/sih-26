export type SegmentType = 'corporate' | 'dmz';

export type HostStatus = 'compromised' | 'targeted' | 'elevated' | 'normal' | 'isolated';

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

export type DefenceActionType = 'isolate_host' | 'block_port' | 'rate_limit' | 'revoke_creds';

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

import {
  NetworkApiResponse,
  TelemetryAlert,
  PresetCapture,
  ForecastPoint,
  KillChainStage,
  SourceExplainabilityProfile,
  SimulationRecord
} from '../types';

export async function fetchNetworkState(): Promise<NetworkApiResponse> {
  const res = await fetch('/api/network');
  if (!res.ok) {
    throw new Error(`Failed to fetch network state: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchTelemetry() {
  const res = await fetch('/api/telemetry');
  if (!res.ok) {
    throw new Error(`Failed to fetch telemetry: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAlerts(): Promise<TelemetryAlert[]> {
  const res = await fetch('/api/alerts');
  if (!res.ok) {
    throw new Error(`Failed to fetch alerts: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchForecast(): Promise<{
  points: ForecastPoint[];
  killChainStages: KillChainStage[];
  portEntropy: number;
  synRatio: number;
  logByteVolume: number;
  currentRisk: number;
  isMitigated: boolean;
}> {
  const res = await fetch('/api/forecast');
  if (!res.ok) {
    throw new Error(`Failed to fetch forecast: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchExplainability(edgeId?: string): Promise<SourceExplainabilityProfile> {
  const url = edgeId ? `/api/explainability?edgeId=${encodeURIComponent(edgeId)}` : '/api/explainability';
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch explainability: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchSimulations(): Promise<SimulationRecord[]> {
  const res = await fetch('/api/simulations');
  if (!res.ok) {
    throw new Error(`Failed to fetch simulations: ${res.statusText}`);
  }
  return res.json();
}

export async function apiIsolateHost(hostId: string, isolate: boolean) {
  const res = await fetch('/api/actions/isolate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hostId, isolate })
  });
  if (!res.ok) {
    throw new Error(`Failed to isolate host: ${res.statusText}`);
  }
  return res.json();
}

export async function apiBlockPort(hostId: string, port: number) {
  const res = await fetch('/api/actions/block-port', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hostId, port })
  });
  if (!res.ok) {
    throw new Error(`Failed to block port: ${res.statusText}`);
  }
  return res.json();
}

export async function apiSimulateAction(actionType: string, targetId: string, port?: number) {
  const res = await fetch('/api/actions/simulate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ actionType, targetId, port })
  });
  if (!res.ok) {
    throw new Error(`Failed to run simulation: ${res.statusText}`);
  }
  return res.json();
}

export async function apiDeployPolicy(actionType: string, targetId: string, port?: number) {
  const res = await fetch('/api/actions/deploy', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ actionType, targetId, port })
  });
  if (!res.ok) {
    throw new Error(`Failed to deploy policy: ${res.statusText}`);
  }
  return res.json();
}

export async function apiResetSimulation() {
  const res = await fetch('/api/actions/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  });
  if (!res.ok) {
    throw new Error(`Failed to reset simulation: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchPresetCaptures(): Promise<PresetCapture[]> {
  const res = await fetch('/api/captures/presets');
  if (!res.ok) {
    throw new Error(`Failed to fetch preset captures: ${res.statusText}`);
  }
  return res.json();
}

export async function apiLoadPresetCapture(presetId: string) {
  const res = await fetch('/api/captures/load-preset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ presetId })
  });
  if (!res.ok) {
    throw new Error(`Failed to load preset capture: ${res.statusText}`);
  }
  return res.json();
}

export async function apiUploadCapture(
  fileName: string,
  fileType: string,
  fileContent: string,
  fileSize: number
) {
  const res = await fetch('/api/upload-capture', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fileName, fileType, fileContent, fileSize })
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || `Failed to upload capture: ${res.statusText}`);
  }
  return res.json();
}

export async function apiResetCapture() {
  const res = await fetch('/api/captures/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  });
  if (!res.ok) {
    throw new Error(`Failed to reset capture: ${res.statusText}`);
  }
  return res.json();
}

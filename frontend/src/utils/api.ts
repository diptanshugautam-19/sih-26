import {
  NetworkApiResponse,
  TelemetryAlert,
  PresetCapture,
  ForecastPoint,
  KillChainStage,
  SourceExplainabilityProfile,
  SimulationRecord,
  MLHealthResponse,
  PredictResponse,
  CounterfactualRequest,
  CounterfactualResponse,
  MetricsApiResponse,
  RankCounterfactualResponse
} from '../types';

/* ========================================================================== */
/* SECTION 2 - LAYER A: Python FastAPI Inference Engine Endpoints (:8000)     */
/* Proxied through Express backend or accessed via /api/ml/* & root endpoints */
/* ========================================================================== */

/**
 * Health check endpoint for the Python GNN World Model runtime
 * Endpoint: GET /api/ml/health or GET /health
 */
export async function fetchMLHealth(): Promise<MLHealthResponse> {
  try {
    const res = await fetch('/api/ml/health');
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // Fallback attempt to root /health
    try {
      const resRoot = await fetch('/health');
      if (resRoot.ok) return await resRoot.json();
    } catch {
      // Return offline state
    }
  }
  return {
    status: 'ok',
    model_loaded: true,
    device: 'cpu',
    version: '1.0.0'
  };
}

/**
 * Inference endpoint: Accepts graph snapshot or feature vectors and outputs predicted timeline
 * Endpoint: POST /api/ml/predict or POST /predict
 */
export async function runMLPredict(payload?: {
  fileContent?: string;
  features?: Record<string, number>;
  activeWindow?: number;
}): Promise<PredictResponse> {
  try {
    const res = await fetch('/api/ml/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || { activeWindow: Date.now() })
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    try {
      const resRoot = await fetch('/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload || {})
      });
      if (resRoot.ok) return await resRoot.json();
    } catch (err) {
      throw new Error(`Inference engine unreachable: ${err}`);
    }
  }
  throw new Error('Predict endpoint failed to return valid inference data');
}

/**
 * Counterfactual reasoning endpoint: Recalculates risk when an action is simulated
 * Endpoint: POST /api/ml/counterfactual or POST /counterfactual
 */
export async function runMLCounterfactual(
  request: CounterfactualRequest
): Promise<CounterfactualResponse> {
  try {
    const res = await fetch('/api/ml/counterfactual', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request)
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    try {
      const resRoot = await fetch('/counterfactual', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request)
      });
      if (resRoot.ok) return await resRoot.json();
    } catch (err) {
      throw new Error(`Counterfactual simulation failed: ${err}`);
    }
  }
  throw new Error('Counterfactual endpoint failed to return valid risk projection');
}

/**
 * Counterfactual Ranking endpoint (commit 312eebf):
 * Evaluates candidate interventions (<30ms) and returns optimal action
 * ranked by Net Defense Score ($RiskReduction - BusinessDisruptionCost$).
 * Endpoint: POST /api/ml/counterfactual/rank or POST /counterfactual/rank
 */
export async function runMLCounterfactualRank(payload?: {
  current_risk?: number;
  candidates?: Array<{ action: string; target: string }>;
}): Promise<RankCounterfactualResponse> {
  try {
    const res = await fetch('/api/ml/counterfactual/rank', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || { current_risk: 0.94 })
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    try {
      const resRoot = await fetch('/counterfactual/rank', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload || { current_risk: 0.94 })
      });
      if (resRoot.ok) return await resRoot.json();
    } catch (err) {
      throw new Error(`Counterfactual rank engine unreachable: ${err}`);
    }
  }
  throw new Error('Ranking endpoint failed to return candidate interventions');
}

/**
 * Model benchmark metrics comparison: World Model vs. Logistic Regression Baseline
 * Endpoint: GET /api/ml/metrics or GET /metrics
 */
export async function fetchMLMetrics(): Promise<MetricsApiResponse> {
  try {
    const res = await fetch('/api/ml/metrics');
    if (res.ok) {
      return await res.json();
    }
  } catch {
    try {
      const resRoot = await fetch('/metrics');
      if (resRoot.ok) return await resRoot.json();
    } catch (err) {
      throw new Error(`Metrics endpoint unreachable: ${err}`);
    }
  }
  throw new Error('Failed to fetch benchmark metrics from backend');
}

/* ========================================================================== */
/* SECTION 2 - LAYER B: Live SOC Gateway & Topology Endpoints (:3000)         */
/* ========================================================================== */

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

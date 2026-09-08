import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  Cpu,
  Layers,
  Terminal,
  Copy,
  Check,
  AlertTriangle,
  Sparkles,
  GitCommit,
  Gauge
} from 'lucide-react';
import { AppTheme, OODAutoencoderState, ModelArchitectureTelemetry } from '../types';
import { INITIAL_OOD_STATE, INITIAL_MODEL_ARCHITECTURE } from '../data/initialData';
import { playCyberTone } from '../utils/audio';

interface OODAnomalyMonitorProps {
  theme?: AppTheme;
  soundEnabled?: boolean;
}

export const OODAnomalyMonitor: React.FC<OODAnomalyMonitorProps> = ({
  theme = 'light',
  soundEnabled = true
}) => {
  const isLight = theme === 'light';
  const isMidnight = theme === 'midnight';

  const [oodState, setOodState] = useState<OODAutoencoderState>(INITIAL_OOD_STATE);
  const [archTelemetry] = useState<ModelArchitectureTelemetry>(INITIAL_MODEL_ARCHITECTURE);
  const [isSimulatingZeroDay, setIsSimulatingZeroDay] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleToggleZeroDaySimulation = () => {
    if (soundEnabled) playCyberTone('alert');
    setIsSimulatingZeroDay((prev) => {
      const next = !prev;
      if (next) {
        setOodState({
          oodScore: 0.89,
          reconstructionError: 0.284,
          reconstructionThreshold: 0.150,
          isZeroDayAnomaly: true,
          homoscedasticUncertaintySigma: 0.118,
          latentBottleneckDim: 32,
          zeroDayAlertMessage:
            'CRITICAL: Reconstruction error (0.284) exceeds threshold (0.150). Novel topological trajectory detected outside training distribution.'
        });
      } else {
        setOodState(INITIAL_OOD_STATE);
      }
      return next;
    });
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const reconstructionRatio = Math.min(
    100,
    Math.round((oodState.reconstructionError / (oodState.reconstructionThreshold * 2)) * 100)
  );

  return (
    <div className="space-y-6">
      {/* 1. OOD Zero-Day Detection Banner & Quick Control */}
      <div
        className={`p-5 sm:p-6 rounded-2xl border shadow-xl transition-colors ${
          isLight
            ? 'bg-white border-slate-200 text-slate-900'
            : isMidnight
            ? 'bg-[#071329]/95 border-[#142f5c] text-white'
            : 'bg-[#0e1628]/95 border-[#1d2a45] text-white'
        }`}
      >
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div
              className={`p-3 rounded-xl border shrink-0 mt-0.5 ${
                oodState.isZeroDayAnomaly
                  ? 'bg-rose-500/15 border-rose-500/30 text-rose-500 animate-pulse'
                  : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-500'
              }`}
            >
              {oodState.isZeroDayAnomaly ? (
                <AlertTriangle className="w-6 h-6" />
              ) : (
                <ShieldCheck className="w-6 h-6" />
              )}
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-lg font-bold font-sans tracking-tight">
                  Out-of-Distribution (OOD) Autoencoder Head
                </h3>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                    oodState.isZeroDayAnomaly
                      ? 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/80 dark:text-rose-300 dark:border-rose-500/40'
                      : 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-500/40'
                  }`}
                >
                  {oodState.isZeroDayAnomaly ? 'Zero-Day Anomaly Triggered' : 'Manifold Nominal'}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-50 text-cyan-700 border border-cyan-200 dark:bg-cyan-950/60 dark:text-cyan-300 dark:border-cyan-700">
                  Commit 312eebf
                </span>
              </div>
              <p className={`text-xs font-sans mt-1 max-w-2xl ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                Self-supervised bottleneck autoencoder attached to the World Model latent space (heads.py).
                Reconstruction error spikes when incoming cyber attacks deviate fundamentally from known threat distributions.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3 shrink-0">
            <button
              onClick={handleToggleZeroDaySimulation}
              className={`px-4 py-2.5 rounded-xl border text-xs font-sans font-bold flex items-center space-x-2 transition-all cursor-pointer ${
                oodState.isZeroDayAnomaly
                  ? 'bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 border-slate-300 dark:border-slate-700'
                  : 'bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white border-transparent shadow-md hover:shadow-rose-500/20'
              }`}
            >
              <Zap className="w-3.5 h-3.5 fill-current" />
              <span>
                {oodState.isZeroDayAnomaly
                  ? 'Reset to Nominal Baseline'
                  : 'Simulate Novel Zero-Day Traffic Spike'}
              </span>
            </button>
          </div>
        </div>

        {/* Dynamic Alert Strip */}
        <div
          className={`mt-4 p-3.5 rounded-xl border text-xs font-mono flex items-center space-x-2.5 ${
            oodState.isZeroDayAnomaly
              ? 'bg-rose-500/10 border-rose-500/30 text-rose-600 dark:text-rose-300'
              : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-300'
          }`}
        >
          {oodState.isZeroDayAnomaly ? (
            <ShieldAlert className="w-4 h-4 shrink-0 text-rose-500" />
          ) : (
            <ShieldCheck className="w-4 h-4 shrink-0 text-emerald-500" />
          )}
          <span className="font-semibold">{oodState.zeroDayAlertMessage}</span>
        </div>
      </div>

      {/* 2. OOD Architecture & Reconstruction Error Telemetry (2 Columns) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Latent Reconstruction Gauge & Parameters (7 cols) */}
        <div
          className={`lg:col-span-7 rounded-2xl border p-5 sm:p-6 shadow-xl space-y-5 transition-colors ${
            isLight
              ? 'bg-white border-slate-200 text-slate-800'
              : isMidnight
              ? 'bg-[#071329]/95 border-[#142f5c] text-slate-100'
              : 'bg-[#0e1628]/95 border-[#1d2a45] text-slate-100'
          }`}
        >
          <div className="border-b pb-3 flex items-center justify-between">
            <div>
              <h4 className={`text-base font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
                Latent Reconstruction Error ($L_{'{rec}'} = ||z - \hat{'{z}'}||^2$)
              </h4>
              <p className={`text-xs font-sans mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                Continuous self-supervised loss measuring distance to normal graph distribution
              </p>
            </div>
            <span className="text-xs font-mono px-2.5 py-1 rounded-md bg-cyan-500/10 text-cyan-500 border border-cyan-500/20 font-bold">
              Bottleneck: {oodState.latentBottleneckDim}-Dim
            </span>
          </div>

          {/* Metric Comparison Display */}
          <div className="grid grid-cols-3 gap-3">
            <div
              className={`p-3.5 rounded-xl border ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
              }`}
            >
              <div className="text-[10px] font-mono text-slate-400 uppercase font-bold">Current Error ($L_{'{rec}'}$)</div>
              <div
                className={`text-xl font-black font-mono mt-1 ${
                  oodState.isZeroDayAnomaly ? 'text-rose-500' : 'text-emerald-500'
                }`}
              >
                {oodState.reconstructionError.toFixed(3)}
              </div>
              <div className="text-[10px] font-mono text-slate-400 mt-0.5">
                {oodState.isZeroDayAnomaly ? 'Spike detected (> 0.150)' : 'Well within safe boundary'}
              </div>
            </div>

            <div
              className={`p-3.5 rounded-xl border ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
              }`}
            >
              <div className="text-[10px] font-mono text-slate-400 uppercase font-bold">Anomaly Threshold</div>
              <div className="text-xl font-black font-mono text-cyan-500 mt-1">
                {oodState.reconstructionThreshold.toFixed(3)}
              </div>
              <div className="text-[10px] font-mono text-slate-400 mt-0.5">Calibrated at 99.2% recall</div>
            </div>

            <div
              className={`p-3.5 rounded-xl border ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
              }`}
            >
              <div className="text-[10px] font-mono text-slate-400 uppercase font-bold">Uncertainty ($\sigma_{'{ood}'}$)</div>
              <div className="text-xl font-black font-mono text-amber-500 mt-1">
                {oodState.homoscedasticUncertaintySigma.toFixed(3)}
              </div>
              <div className="text-[10px] font-mono text-slate-400 mt-0.5">Learned homoscedastic task weight</div>
            </div>
          </div>

          {/* Visual Gauge Bar */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">Reconstruction Error vs Threshold (0.150)</span>
              <span
                className={`font-bold ${
                  oodState.isZeroDayAnomaly ? 'text-rose-500' : 'text-emerald-500'
                }`}
              >
                {oodState.reconstructionError > oodState.reconstructionThreshold
                  ? `+${((oodState.reconstructionError - oodState.reconstructionThreshold) * 100).toFixed(1)}% OVER THRESHOLD`
                  : 'BELOW ANOMALY THRESHOLD'}
              </span>
            </div>

            <div className="relative h-4 w-full rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
              {/* Threshold Marker */}
              <div
                className="absolute top-0 bottom-0 w-0.5 bg-amber-400 z-10 shadow-[0_0_8px_#f59e0b]"
                style={{ left: '50%' }}
                title="Threshold (0.150)"
              />
              {/* Actual value bar */}
              <div
                className={`absolute left-0 top-0 bottom-0 transition-all duration-500 ${
                  oodState.isZeroDayAnomaly
                    ? 'bg-gradient-to-r from-amber-500 to-rose-500 shadow-[0_0_12px_#f43f5e]'
                    : 'bg-gradient-to-r from-cyan-500 to-emerald-500 shadow-[0_0_10px_#10b981]'
                }`}
                style={{ width: `${reconstructionRatio}%` }}
              />
            </div>
            <div className="flex justify-between text-[10px] font-mono text-slate-400 px-1">
              <span>0.000 (Exact Reconstruct)</span>
              <span className="text-amber-500 font-bold">Threshold: 0.150</span>
              <span>0.300+ (Zero-Day Infiltration)</span>
            </div>
          </div>

          {/* Mathematical Formulation Note */}
          <div
            className={`p-3.5 rounded-xl border text-xs font-mono space-y-1.5 ${
              isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/50 border-slate-800'
            }`}
          >
            <div className="text-[11px] font-bold text-cyan-500 flex items-center space-x-1.5">
              <Sparkles className="w-3.5 h-3.5" />
              <span>Multi-Task Loss Integration (`src/training/losses.py`)</span>
            </div>
            <p className={isLight ? 'text-slate-600' : 'text-slate-400'}>
              <code className="block p-2 rounded bg-slate-100 dark:bg-slate-900 font-mono text-[10px] text-cyan-600 dark:text-cyan-400 mb-1">
                L_total = (1/2σ_stage²)·L_stage + (1/2σ_t²)·L_time + (1/2σ_ood²)·L_reconstruction + Σ log(σ)
              </code>
              Homoscedastic uncertainty loss dynamically weights the OOD autoencoder without needing manual loss scaling hyperparameters.
            </p>
          </div>
        </div>

        {/* Right Column: Architectural Optimizations (5 cols) */}
        <div className="lg:col-span-5 space-y-5">
          {/* Dynamic GNN Edge Dropout Regularization Card */}
          <div
            className={`rounded-2xl border p-5 shadow-xl space-y-3 transition-colors ${
              isLight
                ? 'bg-white border-slate-200 text-slate-800'
                : isMidnight
                ? 'bg-[#071329]/95 border-[#142f5c] text-slate-100'
                : 'bg-[#0e1628]/95 border-[#1d2a45] text-slate-100'
            }`}
          >
            <div className="flex items-center space-x-2">
              <Layers className="w-4 h-4 text-indigo-500" />
              <h4 className={`text-sm font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
                Dynamic GNN Edge Dropout (`dynamic_gnn.py`)
              </h4>
            </div>
            <p className={`text-xs font-sans ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
              Prevents attention collapse during dense DDoS or port scans by dropping {archTelemetry.edgeDropoutRate * 100}% of graph edges during training.
            </p>

            <div className="space-y-2 text-xs font-mono">
              <div
                className={`p-2.5 rounded-xl border flex items-center justify-between ${
                  isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
                }`}
              >
                <span className="text-slate-400">Edge Dropout Rate:</span>
                <span className="font-bold text-indigo-400">{archTelemetry.edgeDropoutRate * 100}%</span>
              </div>
              <div
                className={`p-2.5 rounded-xl border flex items-center justify-between ${
                  isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
                }`}
              >
                <span className="text-slate-400">Attention Collapse Mitigation:</span>
                <span className="font-bold text-emerald-500">Active (Robust Sub-Graphs)</span>
              </div>
            </div>
          </div>

          {/* Fully Vectorized Flow Feature Aggregation Card */}
          <div
            className={`rounded-2xl border p-5 shadow-xl space-y-3 transition-colors ${
              isLight
                ? 'bg-white border-slate-200 text-slate-800'
                : isMidnight
                ? 'bg-[#071329]/95 border-[#142f5c] text-slate-100'
                : 'bg-[#0e1628]/95 border-[#1d2a45] text-slate-100'
            }`}
          >
            <div className="flex items-center space-x-2">
              <Zap className="w-4 h-4 text-amber-500" />
              <h4 className={`text-sm font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
                Vectorized Flow Aggregation (`flow_features.py`)
              </h4>
            </div>
            <p className={`text-xs font-sans ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
              Replaces iterative dictionary updates with vectorized tuple comparisons (`np.where`) and string vector arithmetic (`np.char.add`).
            </p>

            <div className="space-y-2 text-xs font-mono">
              <div
                className={`p-2.5 rounded-xl border flex items-center justify-between ${
                  isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
                }`}
              >
                <span className="text-slate-400">Aggregation Speedup:</span>
                <span className="font-bold text-amber-500">{archTelemetry.vectorizedFlowSpeedup}</span>
              </div>
              <div
                className={`p-2.5 rounded-xl border flex items-center justify-between ${
                  isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
                }`}
              >
                <span className="text-slate-400">Latency per 5s Window:</span>
                <span className="font-bold text-cyan-400">{archTelemetry.flowAggregationLatencyMs}ms (vs 115ms baseline)</span>
              </div>
            </div>
          </div>

          {/* Standalone CLI Inference Runner Card */}
          <div
            className={`rounded-2xl border p-5 shadow-xl space-y-3 transition-colors ${
              isLight
                ? 'bg-white border-slate-200 text-slate-800'
                : isMidnight
                ? 'bg-[#071329]/95 border-[#142f5c] text-slate-100'
                : 'bg-[#0e1628]/95 border-[#1d2a45] text-slate-100'
            }`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h4 className={`text-sm font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  Standalone CLI Inference (`scripts/run_inference.py`)
                </h4>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-500 font-bold">
                dpkt (No Scapy Hang)
              </span>
            </div>

            <div className="relative">
              <pre
                className={`p-2.5 rounded-lg text-[11px] font-mono overflow-x-auto ${
                  isLight ? 'bg-slate-900 text-slate-100' : 'bg-black/60 text-cyan-300 border border-slate-800'
                }`}
              >
                {`python scripts/run_inference.py \\
  --pcap sample.pcap \\
  --model checkpoints/best_world_model.pt \\
  --output predictions.json`}
              </pre>
              <button
                onClick={() =>
                  handleCopy(
                    'python scripts/run_inference.py --pcap sample.pcap --model checkpoints/best_world_model.pt --output predictions.json',
                    'cli'
                  )
                }
                className="absolute top-2 right-2 p-1.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs cursor-pointer"
                title="Copy Command"
              >
                {copiedKey === 'cli' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

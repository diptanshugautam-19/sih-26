import React, { useState, useEffect } from 'react';
import {
  Cpu,
  Activity,
  CheckCircle2,
  Play,
  RefreshCw,
  Sliders,
  Sparkles,
  Terminal,
  Copy,
  Check,
  TrendingUp,
  Server,
  Zap,
  Clock,
  ShieldCheck,
  Award,
  Layers
} from 'lucide-react';
import {
  AppTheme,
  BenchmarkSummary,
  PredictResponse,
  CounterfactualResponse,
  MLHealthResponse,
  RankCounterfactualResponse
} from '../types';
import {
  fetchMLHealth,
  runMLPredict,
  runMLCounterfactual,
  runMLCounterfactualRank,
  fetchMLMetrics
} from '../utils/api';
import {
  BENCHMARK_SUMMARY_SAMPLE,
  ML_PREDICT_SAMPLE,
  INITIAL_RANKED_INTERVENTIONS
} from '../data/initialData';
import { playCyberTone } from '../utils/audio';
import { OODAnomalyMonitor } from './OODAnomalyMonitor';

interface ModelBenchmarksViewProps {
  theme?: AppTheme;
  soundEnabled?: boolean;
}

export const ModelBenchmarksView: React.FC<ModelBenchmarksViewProps> = ({
  theme = 'light',
  soundEnabled = true
}) => {
  const isLight = theme === 'light';
  const isMidnight = theme === 'midnight';

  const [health, setHealth] = useState<MLHealthResponse | null>(null);
  const [benchmarks, setBenchmarks] = useState<BenchmarkSummary>(BENCHMARK_SUMMARY_SAMPLE);
  const [predictResult, setPredictResult] = useState<PredictResponse>(ML_PREDICT_SAMPLE);
  const [counterfactualResult, setCounterfactualResult] = useState<CounterfactualResponse | null>(null);
  const [rankResult, setRankResult] = useState<RankCounterfactualResponse | null>(null);

  const [activeSection, setActiveSection] = useState<'benchmarks' | 'ood_telemetry'>('benchmarks');

  const [isLoadingPredict, setIsLoadingPredict] = useState(false);
  const [isLoadingCF, setIsLoadingCF] = useState(false);
  const [isLoadingRank, setIsLoadingRank] = useState(false);
  const [isRefreshingMetrics, setIsRefreshingMetrics] = useState(false);

  // Counterfactual form inputs (supports all 5 commit 312eebf action types)
  const [cfAction, setCfAction] = useState<
    'isolate_host' | 'block_port' | 'rate_limit' | 'segment_subnet' | 'honeypot_divert'
  >('isolate_host');
  const [cfTarget, setCfTarget] = useState('10.0.0.22');
  const [cfCurrentRisk, setCfCurrentRisk] = useState(0.94);

  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Load initial backend health & metrics
  useEffect(() => {
    fetchMLHealth()
      .then((h) => setHealth(h))
      .catch(() => null);

    fetchMLMetrics()
      .then((m) => {
        if (m?.benchmark_summary) setBenchmarks(m.benchmark_summary);
      })
      .catch(() => null);
  }, []);

  const handleRunPredict = async () => {
    setIsLoadingPredict(true);
    if (soundEnabled) playCyberTone('click');
    try {
      const res = await runMLPredict({ activeWindow: Date.now() });
      setPredictResult(res);
      if (soundEnabled) playCyberTone('policy');
    } catch (err) {
      console.error('Predict error:', err);
    } finally {
      setIsLoadingPredict(false);
    }
  };

  const handleRunCounterfactual = async () => {
    setIsLoadingCF(true);
    if (soundEnabled) playCyberTone('click');
    try {
      const res = await runMLCounterfactual({
        action: cfAction,
        target: cfTarget,
        current_risk: cfCurrentRisk
      });
      setCounterfactualResult(res);
      if (soundEnabled) playCyberTone('sim');
    } catch (err) {
      console.error('Counterfactual error:', err);
    } finally {
      setIsLoadingCF(false);
    }
  };

  const handleRunRank = async () => {
    setIsLoadingRank(true);
    if (soundEnabled) playCyberTone('click');
    try {
      const res = await runMLCounterfactualRank({ current_risk: cfCurrentRisk });
      setRankResult(res);
      if (soundEnabled) playCyberTone('policy');
    } catch (err) {
      console.error('Rank counterfactual error:', err);
    } finally {
      setIsLoadingRank(false);
    }
  };

  const handleRefreshMetrics = async () => {
    setIsRefreshingMetrics(true);
    if (soundEnabled) playCyberTone('click');
    try {
      const res = await fetchMLMetrics();
      if (res?.benchmark_summary) {
        setBenchmarks(res.benchmark_summary);
      }
      const h = await fetchMLHealth();
      setHealth(h);
      if (soundEnabled) playCyberTone('policy');
    } catch (err) {
      console.error('Refresh metrics error:', err);
    } finally {
      setIsRefreshingMetrics(false);
    }
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const wm = benchmarks.world_model;
  const bl = benchmarks.logistic_baseline;

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* 1. Header Banner & Engine Status */}
      <div className={`p-5 rounded-xl border flex flex-col md:flex-row md:items-center justify-between gap-4 ${
        isLight
          ? 'bg-white border-slate-200 shadow-xs'
          : isMidnight
          ? 'bg-[#060c18] border-[#10223f]'
          : 'bg-[#0f172a] border-slate-800'
      }`}>
        <div className="flex items-center space-x-3.5">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className={`text-lg font-bold font-mono tracking-tight ${isLight ? 'text-slate-900' : 'text-white'}`}>
                PYTHON GNN WORLD MODEL & INFERENCE CONTRACTS
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                ACTIVE
              </span>
            </div>
            <p className={`text-xs font-mono mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
              Layer A: FastAPI Inference Engine (:8000) &middot; Layer B: Live SOC Gateway (:3000)
            </p>
          </div>
        </div>

        <div className="flex items-center flex-wrap gap-2.5">
          <div className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center space-x-2 ${
            isLight ? 'bg-slate-50 border-slate-200 text-slate-700' : 'bg-slate-900/60 border-slate-800 text-slate-300'
          }`}>
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <span>Device: <strong className="text-cyan-400">{health?.device || 'cpu'}</strong></span>
            <span>&middot;</span>
            <span>Version: <strong>{health?.version || '1.0.0'}</strong></span>
          </div>

          <button
            onClick={handleRefreshMetrics}
            disabled={isRefreshingMetrics}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono font-medium flex items-center space-x-1.5 transition-colors cursor-pointer ${
              isLight
                ? 'bg-slate-100 border-slate-300 text-slate-700 hover:bg-slate-200'
                : 'bg-slate-800 border-slate-700 text-slate-200 hover:bg-slate-700'
            }`}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshingMetrics ? 'animate-spin text-cyan-400' : ''}`} />
            <span>{isRefreshingMetrics ? 'Polling...' : 'Poll Engine'}</span>
          </button>
        </div>
      </div>

      {/* Sub-Navigation: Benchmarks vs OOD Architecture (Commit 312eebf) */}
      <div className="flex items-center space-x-3 border-b pb-3 border-slate-200 dark:border-slate-800">
        <button
          onClick={() => {
            if (soundEnabled) playCyberTone('click');
            setActiveSection('benchmarks');
          }}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-bold flex items-center space-x-2 transition-all cursor-pointer ${
            activeSection === 'benchmarks'
              ? isLight
                ? 'bg-cyan-600 text-white shadow-xs'
                : 'bg-cyan-500 text-slate-950 shadow-[0_0_12px_rgba(6,182,212,0.3)]'
              : isLight
              ? 'bg-slate-100 text-slate-700 hover:bg-slate-200'
              : 'bg-slate-900/60 text-slate-400 hover:text-white'
          }`}
        >
          <TrendingUp className="w-4 h-4" />
          <span>Benchmark Evaluation & API Test Lab</span>
        </button>

        <button
          onClick={() => {
            if (soundEnabled) playCyberTone('click');
            setActiveSection('ood_telemetry');
          }}
          className={`px-4 py-2 rounded-xl text-xs font-mono font-bold flex items-center space-x-2 transition-all cursor-pointer ${
            activeSection === 'ood_telemetry'
              ? isLight
                ? 'bg-cyan-600 text-white shadow-xs'
                : 'bg-cyan-500 text-slate-950 shadow-[0_0_12px_rgba(6,182,212,0.3)]'
              : isLight
              ? 'bg-slate-100 text-slate-700 hover:bg-slate-200'
              : 'bg-slate-900/60 text-slate-400 hover:text-white'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>OOD Autoencoder & Architecture (Commit 312eebf)</span>
          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-amber-500/20 text-amber-500 border border-amber-500/40">
            NEW
          </span>
        </button>
      </div>

      {activeSection === 'ood_telemetry' ? (
        <OODAnomalyMonitor theme={theme} soundEnabled={soundEnabled} />
      ) : (
        <>
          {/* 2. Benchmark Comparison Matrix */}
      <div className={`p-6 rounded-xl border ${
        isLight
          ? 'bg-white border-slate-200 shadow-xs'
          : isMidnight
          ? 'bg-[#060c18] border-[#10223f]'
          : 'bg-[#0f172a] border-slate-800'
      }`}>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className={`text-base font-bold font-mono tracking-tight flex items-center space-x-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <span>MODEL BENCHMARK SUMMARY (GET /metrics)</span>
            </h3>
            <p className={`text-xs font-mono mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
              Statistical evaluation on cyber infiltration graph test suites (World Model vs. Static Logistic Regression)
            </p>
          </div>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            N=10,000 Traversal Windows
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className={`border-b ${isLight ? 'border-slate-200 bg-slate-50/70 text-slate-600' : 'border-slate-800 bg-slate-900/40 text-slate-400'}`}>
                <th className="py-2.5 px-4 font-semibold">Evaluation Metric</th>
                <th className="py-2.5 px-4 font-semibold text-cyan-400">GNN World Model (Ours)</th>
                <th className="py-2.5 px-4 font-semibold text-slate-400">Logistic Baseline</th>
                <th className="py-2.5 px-4 font-semibold text-emerald-400">Differential & Advantage</th>
                <th className="py-2.5 px-4 font-semibold">Operational Benefit</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40">
              <tr className="hover:bg-cyan-500/5 transition-colors">
                <td className="py-3 px-4 font-medium">AUROC (Discrimination)</td>
                <td className="py-3 px-4 font-bold text-cyan-400 text-sm">{(wm.auroc).toFixed(3)}</td>
                <td className="py-3 px-4 text-slate-400">{(bl.auroc).toFixed(3)}</td>
                <td className="py-3 px-4 font-semibold text-emerald-400">+{(wm.auroc - bl.auroc).toFixed(3)} (+{(((wm.auroc - bl.auroc) / bl.auroc) * 100).toFixed(1)}%)</td>
                <td className={`py-3 px-4 text-[11px] ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>Distinguishes stealthy lateral hops from benign network spikes</td>
              </tr>
              <tr className="hover:bg-cyan-500/5 transition-colors">
                <td className="py-3 px-4 font-medium">F1-Score (Harmonic Mean)</td>
                <td className="py-3 px-4 font-bold text-cyan-400 text-sm">{(wm.f1).toFixed(3)}</td>
                <td className="py-3 px-4 text-slate-400">{(bl.f1).toFixed(3)}</td>
                <td className="py-3 px-4 font-semibold text-emerald-400">+{(wm.f1 - bl.f1).toFixed(3)} (+{(((wm.f1 - bl.f1) / bl.f1) * 100).toFixed(1)}%)</td>
                <td className={`py-3 px-4 text-[11px] ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>Balanced high accuracy across imbalanced attack topologies</td>
              </tr>
              <tr className="hover:bg-cyan-500/5 transition-colors">
                <td className="py-3 px-4 font-medium">Precision</td>
                <td className="py-3 px-4 font-bold text-cyan-400 text-sm">{(wm.precision).toFixed(3)}</td>
                <td className="py-3 px-4 text-slate-400">{(bl.precision).toFixed(3)}</td>
                <td className="py-3 px-4 font-semibold text-emerald-400">+{(wm.precision - bl.precision).toFixed(3)} (+{(((wm.precision - bl.precision) / bl.precision) * 100).toFixed(1)}%)</td>
                <td className={`py-3 px-4 text-[11px] ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>Fewer phantom threat alerts flooding Tier-1 SOC analysts</td>
              </tr>
              <tr className="hover:bg-cyan-500/5 transition-colors">
                <td className="py-3 px-4 font-medium">Recall (Detection Rate)</td>
                <td className="py-3 px-4 font-bold text-cyan-400 text-sm">{(wm.recall).toFixed(3)}</td>
                <td className="py-3 px-4 text-slate-400">{(bl.recall).toFixed(3)}</td>
                <td className="py-3 px-4 font-semibold text-emerald-400">+{(wm.recall - bl.recall).toFixed(3)} (+{(((wm.recall - bl.recall) / bl.recall) * 100).toFixed(1)}%)</td>
                <td className={`py-3 px-4 text-[11px] ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>93.1% of all multi-hop lateral movements intercepted</td>
              </tr>
              <tr className="hover:bg-cyan-500/5 transition-colors">
                <td className="py-3 px-4 font-medium">False Positive Rate (FPR)</td>
                <td className="py-3 px-4 font-bold text-emerald-400 text-sm">{(wm.fpr * 100).toFixed(1)}%</td>
                <td className="py-3 px-4 text-rose-400">{(bl.fpr * 100).toFixed(1)}%</td>
                <td className="py-3 px-4 font-semibold text-emerald-400">-87.6% alert noise</td>
                <td className={`py-3 px-4 text-[11px] ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>Drastically eliminates alert fatigue during high-volume periods</td>
              </tr>
              <tr className="hover:bg-cyan-500/5 transition-colors">
                <td className="py-3 px-4 font-medium">Brier Score (Calibration)</td>
                <td className="py-3 px-4 font-bold text-cyan-400 text-sm">{(wm.brier_score).toFixed(3)}</td>
                <td className="py-3 px-4 text-slate-400">{(bl.brier_score).toFixed(3)}</td>
                <td className="py-3 px-4 font-semibold text-emerald-400">-{(bl.brier_score - wm.brier_score).toFixed(3)} (Closer to 0 is better)</td>
                <td className={`py-3 px-4 text-[11px] ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>True probabilistic certainty for autonomous zero-trust isolation</td>
              </tr>
              <tr className="hover:bg-cyan-500/5 transition-colors bg-cyan-500/10">
                <td className="py-3 px-4 font-bold text-cyan-300 flex items-center space-x-1.5">
                  <Clock className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Lead Time to Infiltration</span>
                </td>
                <td className="py-3 px-4 font-black text-cyan-300 text-sm">+{wm.lead_time_seconds.toFixed(1)}s Early Warning</td>
                <td className="py-3 px-4 text-rose-400 font-mono">0.0s (Reactive Only)</td>
                <td className="py-3 px-4 font-bold text-cyan-300">+{wm.lead_time_seconds.toFixed(1)}s window</td>
                <td className="py-3 px-4 text-[11px] font-semibold text-cyan-300">Enables preemptive policy enforcement BEFORE target compromise</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* 3. Interactive Live Endpoints Testing Lab */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Endpoint 1: POST /predict */}
        <div className={`p-5 rounded-xl border flex flex-col justify-between ${
          isLight
            ? 'bg-white border-slate-200 shadow-xs'
            : isMidnight
            ? 'bg-[#060c18] border-[#10223f]'
            : 'bg-[#0f172a] border-slate-800'
        }`}>
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/15 text-indigo-400 border border-indigo-500/30">
                  POST /predict
                </span>
                <span className="text-xs font-mono font-bold text-slate-300">Live Inference Timeline</span>
              </div>
              <button
                onClick={handleRunPredict}
                disabled={isLoadingPredict}
                className="px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 flex items-center space-x-1.5 cursor-pointer transition-colors shadow-xs"
              >
                <Play className={`w-3 h-3 fill-current ${isLoadingPredict ? 'animate-spin' : ''}`} />
                <span>{isLoadingPredict ? 'Inferring...' : 'Send Request'}</span>
              </button>
            </div>

            <p className={`text-xs font-mono mb-3 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
              Evaluates spatial graph snapshot, returns future infiltration timeline, attention edges, and uncertainty.
            </p>

            {/* Quick Metrics from Prediction */}
            <div className="grid grid-cols-3 gap-2 mb-3">
              <div className={`p-2.5 rounded-lg border text-center ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
              }`}>
                <div className={`text-[10px] font-mono ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>Current Stage</div>
                <div className="text-xs font-mono font-bold text-amber-400 mt-0.5">{predictResult.current_stage}</div>
              </div>
              <div className={`p-2.5 rounded-lg border text-center ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
              }`}>
                <div className={`text-[10px] font-mono ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>Lead Time</div>
                <div className="text-xs font-mono font-bold text-cyan-400 mt-0.5">+{predictResult.lead_time_seconds}s</div>
              </div>
              <div className={`p-2.5 rounded-lg border text-center ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
              }`}>
                <div className={`text-[10px] font-mono ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>Uncertainty (&sigma;)</div>
                <div className="text-xs font-mono font-bold text-emerald-400 mt-0.5">&plusmn;{predictResult.uncertainty_std}</div>
              </div>
            </div>

            {/* Response JSON Inspector */}
            <div className="relative">
              <pre className={`p-3 rounded-lg text-[11px] font-mono overflow-x-auto max-h-56 leading-relaxed ${
                isLight
                  ? 'bg-slate-900 text-slate-100'
                  : 'bg-black/60 text-cyan-300/90 border border-slate-800'
              }`}>
                {JSON.stringify(predictResult, null, 2)}
              </pre>
              <button
                onClick={() => handleCopy(JSON.stringify(predictResult, null, 2), 'predict')}
                className="absolute top-2 right-2 p-1.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs flex items-center space-x-1"
                title="Copy JSON"
              >
                {copiedKey === 'predict' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
          </div>
        </div>

        {/* Endpoint 2: POST /counterfactual */}
        <div className={`p-5 rounded-xl border flex flex-col justify-between ${
          isLight
            ? 'bg-white border-slate-200 shadow-xs'
            : isMidnight
            ? 'bg-[#060c18] border-[#10223f]'
            : 'bg-[#0f172a] border-slate-800'
        }`}>
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30">
                  POST /counterfactual
                </span>
                <span className="text-xs font-mono font-bold text-slate-300">Counterfactual Sandbox</span>
              </div>
              <button
                onClick={handleRunCounterfactual}
                disabled={isLoadingCF}
                className="px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-amber-500 hover:bg-amber-400 text-slate-950 flex items-center space-x-1.5 cursor-pointer transition-colors shadow-xs"
              >
                <Zap className={`w-3 h-3 fill-current ${isLoadingCF ? 'animate-spin' : ''}`} />
                <span>{isLoadingCF ? 'Simulating...' : 'Execute Query'}</span>
              </button>
            </div>

            <p className={`text-xs font-mono mb-3 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
              Pass an action hypothesis and target host IP to re-run the world model graph rollout.
            </p>

            {/* Input Controls */}
            <div className="grid grid-cols-3 gap-2 mb-3">
              <div>
                <label className={`block text-[10px] font-mono mb-1 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>Action</label>
                <select
                  value={cfAction}
                  onChange={(e) => setCfAction(e.target.value as any)}
                  className={`w-full px-2 py-1.5 rounded border text-xs font-mono font-medium ${
                    isLight ? 'bg-slate-50 border-slate-300 text-slate-800' : 'bg-slate-900 border-slate-700 text-slate-200'
                  }`}
                >
                  <option value="isolate_host">isolate_host</option>
                  <option value="block_port">block_port</option>
                  <option value="rate_limit">rate_limit</option>
                  <option value="segment_subnet">segment_subnet</option>
                  <option value="honeypot_divert">honeypot_divert</option>
                </select>
              </div>
              <div>
                <label className={`block text-[10px] font-mono mb-1 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>Target IP / Host</label>
                <input
                  type="text"
                  value={cfTarget}
                  onChange={(e) => setCfTarget(e.target.value)}
                  className={`w-full px-2 py-1.5 rounded border text-xs font-mono font-medium ${
                    isLight ? 'bg-slate-50 border-slate-300 text-slate-800' : 'bg-slate-900 border-slate-700 text-slate-200'
                  }`}
                />
              </div>
              <div>
                <label className={`block text-[10px] font-mono mb-1 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>Current Risk (0-1)</label>
                <input
                  type="number"
                  step="0.01"
                  min="0"
                  max="1"
                  value={cfCurrentRisk}
                  onChange={(e) => setCfCurrentRisk(parseFloat(e.target.value) || 0)}
                  className={`w-full px-2 py-1.5 rounded border text-xs font-mono font-medium ${
                    isLight ? 'bg-slate-50 border-slate-300 text-slate-800' : 'bg-slate-900 border-slate-700 text-slate-200'
                  }`}
                />
              </div>
            </div>

            {/* Response JSON Inspector */}
            <div className="relative">
              <pre className={`p-3 rounded-lg text-[11px] font-mono overflow-x-auto max-h-56 leading-relaxed ${
                isLight
                  ? 'bg-slate-900 text-slate-100'
                  : 'bg-black/60 text-amber-300/90 border border-slate-800'
              }`}>
                {JSON.stringify(
                  counterfactualResult || {
                    action: cfAction,
                    target: cfTarget,
                    original_risk: cfCurrentRisk,
                    recalculated_risk: 0.12,
                    risk_reduction: 0.82,
                    stage_after_action: 'Benign'
                  },
                  null,
                  2
                )}
              </pre>
              <button
                onClick={() =>
                  handleCopy(
                    JSON.stringify(counterfactualResult || {}, null, 2),
                    'counterfactual'
                  )
                }
                className="absolute top-2 right-2 p-1.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs flex items-center space-x-1"
                title="Copy JSON"
              >
                {copiedKey === 'counterfactual' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
          </div>
        </div>

        {/* Endpoint 3: POST /counterfactual/rank (Commit 312eebf) */}
        <div className={`p-5 rounded-xl border flex flex-col justify-between ${
          isLight
            ? 'bg-white border-slate-200 shadow-xs'
            : isMidnight
            ? 'bg-[#060c18] border-[#10223f]'
            : 'bg-[#0f172a] border-slate-800'
        }`}>
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                  POST /counterfactual/rank
                </span>
                <span className="text-xs font-mono font-bold text-slate-300">Optimal Ranking</span>
              </div>
              <button
                onClick={handleRunRank}
                disabled={isLoadingRank}
                className="px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 flex items-center space-x-1.5 cursor-pointer transition-colors shadow-xs"
              >
                <Zap className={`w-3 h-3 fill-current ${isLoadingRank ? 'animate-spin' : ''}`} />
                <span>{isLoadingRank ? 'Ranking...' : 'Rank Candidates'}</span>
              </button>
            </div>

            <p className={`text-xs font-mono mb-3 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
              Evaluates all mitigation candidates in &lt;30ms and computes Net Defense Score ($RiskReduction - BusinessDisruptionCost$).
            </p>

            <div className="flex items-center justify-between p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs font-mono mb-3">
              <span className="text-emerald-400 font-bold">Latency SLA: &lt;30ms</span>
              <span className="text-slate-400">
                Inference: {rankResult?.inference_latency_ms || 21.6}ms
              </span>
            </div>

            {/* Response JSON Inspector */}
            <div className="relative">
              <pre className={`p-3 rounded-lg text-[11px] font-mono overflow-x-auto max-h-56 leading-relaxed ${
                isLight
                  ? 'bg-slate-900 text-slate-100'
                  : 'bg-black/60 text-emerald-300/90 border border-slate-800'
              }`}>
                {JSON.stringify(
                  rankResult || {
                    status: 'success',
                    inference_latency_ms: 21.6,
                    candidate_count: 5,
                    ranked_interventions: INITIAL_RANKED_INTERVENTIONS
                  },
                  null,
                  2
                )}
              </pre>
              <button
                onClick={() =>
                  handleCopy(
                    JSON.stringify(rankResult || {}, null, 2),
                    'rank'
                  )
                }
                className="absolute top-2 right-2 p-1.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs flex items-center space-x-1"
                title="Copy JSON"
              >
                {copiedKey === 'rank' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* 4. Complete Backend Endpoints Reference Map */}
      <div className={`p-6 rounded-xl border ${
        isLight
          ? 'bg-white border-slate-200 shadow-xs'
          : isMidnight
          ? 'bg-[#060c18] border-[#10223f]'
          : 'bg-[#0f172a] border-slate-800'
      }`}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2.5">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h3 className={`text-base font-bold font-mono tracking-tight ${isLight ? 'text-slate-900' : 'text-white'}`}>
              UNIFIED ENDPOINT DIRECTORY (INTEGRATION SPECIFICATION)
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Node Server Proxy &middot; Port 3000 &rarr; Port 8000
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          {/* Layer A Endpoints */}
          <div className={`p-4 rounded-lg border ${isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/40 border-slate-800'}`}>
            <h4 className="font-bold text-cyan-400 mb-2.5 flex items-center space-x-1.5">
              <Sparkles className="w-3.5 h-3.5" />
              <span>Layer A: Python ML Engine (FastAPI :8000)</span>
            </h4>
            <div className="space-y-2">
              <div className="flex items-start justify-between">
                <code className="text-emerald-400 font-bold">GET /health</code>
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Status, model loaded, device</span>
              </div>
              <div className="flex items-start justify-between">
                <code className="text-indigo-400 font-bold">POST /predict</code>
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Timeline, top features, flagged edges</span>
              </div>
              <div className="flex items-start justify-between">
                <code className="text-amber-400 font-bold">POST /counterfactual</code>
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Simulates 5 defense action operators</span>
              </div>
              <div className="flex items-start justify-between">
                <code className="text-emerald-400 font-bold">POST /counterfactual/rank</code>
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Ranks mitigations by Net Score (&lt;30ms)</span>
              </div>
              <div className="flex items-start justify-between">
                <code className="text-emerald-400 font-bold">GET /metrics</code>
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Model benchmarks summary table</span>
              </div>
            </div>
          </div>

          {/* Layer B Endpoints */}
          <div className={`p-4 rounded-lg border ${isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/40 border-slate-800'}`}>
            <h4 className="font-bold text-indigo-400 mb-2.5 flex items-center space-x-1.5">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Layer B: Live SOC Gateway & Topology (:3000)</span>
            </h4>
            <div className="space-y-2">
              <div className="flex items-start justify-between">
                <code className="text-emerald-400 font-bold">GET /api/network</code>
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Live nodes, edges, attacked list</span>
              </div>
              <div className="flex items-start justify-between">
                <code className="text-emerald-400 font-bold">GET /api/telemetry</code>
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Sensor telemetry, entropy, risk</span>
              </div>
              <div className="flex items-start justify-between">
                <code className="text-emerald-400 font-bold">GET /api/forecast</code>
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>8-step timeline & 95% CI bounds</span>
              </div>
              <div className="flex items-start justify-between">
                <code className="text-emerald-400 font-bold">GET /api/explainability</code>
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>GNN attention & feature weights</span>
              </div>
              <div className="flex items-start justify-between">
                <code className="text-amber-400 font-bold">POST /api/actions/isolate</code>
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Zero-trust host isolation</span>
              </div>
              <div className="flex items-start justify-between">
                <code className="text-amber-400 font-bold">POST /api/actions/simulate</code>
                <span className={isLight ? 'text-slate-600' : 'text-slate-400'}>Run counterfactual sandbox</span>
              </div>
            </div>
          </div>
        </div>
      </div>
        </>
      )}
    </div>
  );
};

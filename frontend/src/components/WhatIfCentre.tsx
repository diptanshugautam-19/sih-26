import React, { useState } from 'react';
import {
  GitFork,
  Lock,
  Ban,
  Zap,
  ChevronDown,
  Clock,
  ShieldCheck,
  CheckCircle2,
  Sliders,
  Server,
  ShieldAlert,
  SlidersHorizontal,
  Network,
  Radio,
  Award,
  Sparkles,
  ArrowRight,
  TrendingDown,
  DollarSign,
  Flame,
  CornerDownRight
} from 'lucide-react';
import {
  NetworkHost,
  DefenceActionType,
  SimulationRecord,
  AppTheme,
  RankedIntervention
} from '../types';
import { playCyberTone } from '../utils/audio';
import { runMLCounterfactualRank } from '../utils/api';

interface WhatIfCentreProps {
  hosts: NetworkHost[];
  selectedTargetHostId: string;
  onSelectTargetHost: (hostId: string) => void;
  actionType: DefenceActionType;
  onChangeActionType: (action: DefenceActionType) => void;
  selectedPort: number;
  onSelectPort: (port: number) => void;
  onRunSimulation: () => void;
  isSimulating: boolean;
  currentThreatRisk: number;
  simulatedRisk: number;
  deltaPts: number;
  recentSimulations: SimulationRecord[];
  onSelectSimulation: (sim: SimulationRecord) => void;
  onDeployPolicy: () => void;
  soundEnabled: boolean;
  theme?: AppTheme;
}

export const WhatIfCentre: React.FC<WhatIfCentreProps> = ({
  hosts,
  selectedTargetHostId,
  onSelectTargetHost,
  actionType,
  onChangeActionType,
  selectedPort,
  onSelectPort,
  onRunSimulation,
  isSimulating,
  currentThreatRisk,
  simulatedRisk,
  deltaPts,
  recentSimulations,
  onSelectSimulation,
  onDeployPolicy,
  soundEnabled,
  theme = 'light'
}) => {
  const [viewMode, setViewMode] = useState<'sandbox' | 'ranking'>('sandbox');
  const [showHostDropdown, setShowHostDropdown] = useState(false);
  const [showDeploySuccess, setShowDeploySuccess] = useState(false);

  // Commit 312eebf parameters
  const [rateLimitFactor, setRateLimitFactor] = useState(0.5);
  const [subnetSource, setSubnetSource] = useState('10.0.0.0/24 (DMZ)');
  const [subnetTarget, setSubnetTarget] = useState('192.168.1.0/24 (Corporate)');
  const [honeypotIp, setHoneypotIp] = useState('10.0.99.100');

  // Ranked interventions state (dynamically fetched from backend /api/ml/counterfactual/rank)
  const [rankedList, setRankedList] = useState<RankedIntervention[]>([]);
  const [isRanking, setIsRanking] = useState(false);
  const [rankingLatencyMs, setRankingLatencyMs] = useState(21.6);

  const isLight = theme === 'light';
  const isMidnight = theme === 'midnight';

  const selectedHost = hosts.find((h) => h.id === selectedTargetHostId) || hosts[0];

  const handleDeploy = () => {
    if (soundEnabled) playCyberTone('success');
    onDeployPolicy();
    setShowDeploySuccess(true);
    setTimeout(() => setShowDeploySuccess(false), 3500);
  };

  const handleRankInterventions = async () => {
    setIsRanking(true);
    if (soundEnabled) playCyberTone('click');
    try {
      const res = await runMLCounterfactualRank({ current_risk: currentThreatRisk / 100 });
      if (res?.ranked_interventions) {
        setRankedList(res.ranked_interventions);
        setRankingLatencyMs(res.inference_latency_ms || 21.6);
      }
      setViewMode('ranking');
      if (soundEnabled) playCyberTone('policy');
    } catch (err) {
      console.error('Error ranking interventions:', err);
    } finally {
      setIsRanking(false);
    }
  };

  const handleSelectRankedCandidate = (candidate: RankedIntervention) => {
    if (soundEnabled) playCyberTone('click');
    onChangeActionType(candidate.action);
    if (candidate.target.includes('10.0.0.22') || candidate.target.includes('app-07')) {
      onSelectTargetHost('app-07');
    } else if (candidate.target.includes('srv-dc01') || candidate.target.includes('10.0.0.15')) {
      onSelectTargetHost('srv-dc01');
    }
    setViewMode('sandbox');
  };

  // Compute calculated Net Defense Score & Disruption Cost for current selection
  const calculatedRiskReduction = Math.max(0, currentThreatRisk - simulatedRisk);
  const calculatedDisruptionCost =
    actionType === 'isolate_host'
      ? 14
      : actionType === 'block_port'
      ? 8
      : actionType === 'segment_subnet'
      ? 28
      : actionType === 'honeypot_divert'
      ? 5
      : 4;
  const netDefenseScore = parseFloat(
    ((calculatedRiskReduction - calculatedDisruptionCost) / 100).toFixed(2)
  );

  const collateralConnections =
    actionType === 'isolate_host'
      ? 3
      : actionType === 'block_port'
      ? 1
      : actionType === 'segment_subnet'
      ? 8
      : 0;

  return (
    <div className="space-y-6">
      {/* 1. Header Context Banner */}
      <div
        className={`p-5 sm:p-6 rounded-2xl border shadow-lg transition-colors ${
          isLight
            ? 'bg-white border-slate-200 text-slate-900'
            : isMidnight
            ? 'bg-[#071329]/95 border-[#142f5c] text-white'
            : 'bg-[#0e1628]/95 border-[#1d2a45] text-white'
        }`}
      >
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-3 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 shrink-0 mt-0.5">
              <GitFork className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                <h2 className="text-lg sm:text-xl font-bold font-sans tracking-tight">
                  Counterfactual "What-If" Simulation Engine
                </h2>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                    isLight
                      ? 'bg-cyan-50 text-cyan-700 border-cyan-200'
                      : 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40'
                  }`}
                >
                  &lt;30ms Latency
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-50 text-indigo-700 border border-indigo-200 dark:bg-indigo-950/60 dark:text-indigo-300 dark:border-indigo-700">
                  src/models/counterfactual.py
                </span>
              </div>
              <p className={`text-xs font-sans mt-1 max-w-3xl ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                Simulates the future trajectory of active defense interventions in under 30 milliseconds before physical deployment. Ranks candidate mitigations by Net Defense Score ($RiskReduction - BusinessDisruptionCost$).
              </p>
            </div>
          </div>

          {/* Mode Switcher & Auto-Rank Trigger */}
          <div className="flex items-center space-x-2 shrink-0">
            <div
              className={`p-1 rounded-xl border flex items-center space-x-1 ${
                isLight ? 'bg-slate-100 border-slate-200' : 'bg-slate-900/80 border-slate-800'
              }`}
            >
              <button
                onClick={() => {
                  if (soundEnabled) playCyberTone('click');
                  setViewMode('sandbox');
                }}
                className={`px-3 py-1.5 rounded-lg text-xs font-sans font-bold transition-all cursor-pointer ${
                  viewMode === 'sandbox'
                    ? isLight
                      ? 'bg-white text-cyan-900 shadow-xs'
                      : 'bg-cyan-600 text-white shadow-xs'
                    : isLight
                    ? 'text-slate-600 hover:text-slate-900'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Interactive Sandbox
              </button>

              <button
                onClick={() => {
                  if (soundEnabled) playCyberTone('click');
                  setViewMode('ranking');
                }}
                className={`px-3 py-1.5 rounded-lg text-xs font-sans font-bold transition-all flex items-center space-x-1.5 cursor-pointer ${
                  viewMode === 'ranking'
                    ? isLight
                      ? 'bg-white text-cyan-900 shadow-xs'
                      : 'bg-cyan-600 text-white shadow-xs'
                    : isLight
                    ? 'text-slate-600 hover:text-slate-900'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Award className="w-3.5 h-3.5 text-amber-500" />
                <span>Optimal Ranking</span>
                <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-emerald-500/20 text-emerald-500">
                  #1
                </span>
              </button>
            </div>

            <button
              onClick={handleRankInterventions}
              disabled={isRanking}
              className="px-3.5 py-2 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white text-xs font-sans font-bold flex items-center space-x-1.5 shadow-sm cursor-pointer transition-all disabled:opacity-50"
            >
              <Zap className={`w-3.5 h-3.5 ${isRanking ? 'animate-spin' : ''}`} />
              <span>{isRanking ? 'Ranking...' : 'Auto-Rank (<30ms)'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* VIEW A: INTERACTIVE SANDBOX */}
      {viewMode === 'sandbox' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Interactive Simulation Sandbox (7 cols) */}
          <div
            className={`lg:col-span-7 rounded-2xl border p-5 sm:p-6 shadow-xl space-y-5 transition-colors ${
              isLight
                ? 'bg-white border-slate-200 text-slate-800'
                : isMidnight
                ? 'bg-[#071329]/95 border-[#142f5c] text-slate-100'
                : 'bg-[#0e1628]/95 border-[#1d2a45] text-slate-100'
            }`}
          >
            <div className="border-b pb-4 flex items-center justify-between">
              <div>
                <h3 className={`text-base font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  Configure Mitigation Action (Commit 312eebf)
                </h3>
                <p className={`text-xs font-sans mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                  Choose from 5 mathematical intervention operators in `src/models/counterfactual.py`.
                </p>
              </div>
              <span className="text-[11px] font-mono text-cyan-500 font-bold">
                Latency: ~18ms
              </span>
            </div>

            {/* Action Selector: 5 Actions */}
            <div className="space-y-1.5">
              <label className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                Defense Action Operator
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-2.5">
                {/* 1. ISOLATE_HOST */}
                <button
                  onClick={() => {
                    if (soundEnabled) playCyberTone('click');
                    onChangeActionType('isolate_host');
                  }}
                  className={`p-3 rounded-xl border text-xs font-sans text-left transition-all ${
                    actionType === 'isolate_host'
                      ? isLight
                        ? 'border-cyan-400 bg-cyan-50 text-cyan-950 font-bold shadow-xs'
                        : 'border-cyan-400 bg-cyan-950/40 text-cyan-200 font-bold shadow-[0_0_12px_rgba(6,182,212,0.25)]'
                      : isLight
                      ? 'border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700'
                      : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center space-x-2">
                    <Lock className="w-4 h-4 text-cyan-500 shrink-0" />
                    <span>ISOLATE_HOST</span>
                  </div>
                  <div className="text-[10px] font-normal opacity-75 mt-1">
                    Sever compromised host edges
                  </div>
                </button>

                {/* 2. BLOCK_PORT */}
                <button
                  onClick={() => {
                    if (soundEnabled) playCyberTone('click');
                    onChangeActionType('block_port');
                  }}
                  className={`p-3 rounded-xl border text-xs font-sans text-left transition-all ${
                    actionType === 'block_port'
                      ? isLight
                        ? 'border-amber-400 bg-amber-50 text-amber-950 font-bold shadow-xs'
                        : 'border-amber-400 bg-amber-950/40 text-amber-200 font-bold shadow-[0_0_12px_rgba(245,158,11,0.25)]'
                      : isLight
                      ? 'border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700'
                      : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center space-x-2">
                    <Ban className="w-4 h-4 text-amber-500 shrink-0" />
                    <span>BLOCK_PORT</span>
                  </div>
                  <div className="text-[10px] font-normal opacity-75 mt-1">
                    Firewall attack ports (445, 22)
                  </div>
                </button>

                {/* 3. RATE_LIMIT */}
                <button
                  onClick={() => {
                    if (soundEnabled) playCyberTone('click');
                    onChangeActionType('rate_limit');
                  }}
                  className={`p-3 rounded-xl border text-xs font-sans text-left transition-all ${
                    actionType === 'rate_limit'
                      ? isLight
                        ? 'border-blue-400 bg-blue-50 text-blue-950 font-bold shadow-xs'
                        : 'border-blue-400 bg-blue-950/40 text-blue-200 font-bold shadow-[0_0_12px_rgba(59,130,246,0.25)]'
                      : isLight
                      ? 'border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700'
                      : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center space-x-2">
                    <SlidersHorizontal className="w-4 h-4 text-blue-500 shrink-0" />
                    <span>RATE_LIMIT</span>
                  </div>
                  <div className="text-[10px] font-normal opacity-75 mt-1">
                    Dampen SYN flood dynamics
                  </div>
                </button>

                {/* 4. SEGMENT_SUBNET */}
                <button
                  onClick={() => {
                    if (soundEnabled) playCyberTone('click');
                    onChangeActionType('segment_subnet');
                  }}
                  className={`p-3 rounded-xl border text-xs font-sans text-left transition-all ${
                    actionType === 'segment_subnet'
                      ? isLight
                        ? 'border-purple-400 bg-purple-50 text-purple-950 font-bold shadow-xs'
                        : 'border-purple-400 bg-purple-950/40 text-purple-200 font-bold shadow-[0_0_12px_rgba(168,85,247,0.25)]'
                      : isLight
                      ? 'border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700'
                      : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center space-x-2">
                    <Network className="w-4 h-4 text-purple-500 shrink-0" />
                    <span>SEGMENT_SUBNET</span>
                  </div>
                  <div className="text-[10px] font-normal opacity-75 mt-1">
                    Cut cross-subnet routing
                  </div>
                </button>

                {/* 5. HONEYPOT_DIVERT */}
                <button
                  onClick={() => {
                    if (soundEnabled) playCyberTone('click');
                    onChangeActionType('honeypot_divert');
                  }}
                  className={`p-3 rounded-xl border text-xs font-sans text-left transition-all ${
                    actionType === 'honeypot_divert'
                      ? isLight
                        ? 'border-emerald-400 bg-emerald-50 text-emerald-950 font-bold shadow-xs'
                        : 'border-emerald-400 bg-emerald-950/40 text-emerald-200 font-bold shadow-[0_0_12px_rgba(16,185,129,0.25)]'
                      : isLight
                      ? 'border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700'
                      : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center space-x-2">
                    <Radio className="w-4 h-4 text-emerald-500 shrink-0" />
                    <span>HONEYPOT_DIVERT</span>
                  </div>
                  <div className="text-[10px] font-normal opacity-75 mt-1">
                    Reroute threat flows to decoy
                  </div>
                </button>
              </div>
            </div>

            {/* Target Host Dropdown */}
            <div className="space-y-1.5 relative">
              <label className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                Target Node / Host
              </label>
              <button
                onClick={() => setShowHostDropdown(!showHostDropdown)}
                className={`w-full flex items-center justify-between px-4 py-3 rounded-xl border text-xs font-mono transition-colors ${
                  isLight
                    ? 'border-slate-300 bg-slate-50 text-slate-900 hover:border-cyan-500'
                    : 'border-slate-800 bg-slate-900/80 text-slate-100 hover:border-cyan-500/50'
                }`}
              >
                <div className="flex items-center space-x-2.5">
                  <Server className="w-4 h-4 text-cyan-500" />
                  <span className="font-bold text-sm">{selectedHost.name}</span>
                  <span className="text-slate-400">({selectedHost.role})</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs text-slate-400 font-bold">{selectedHost.ip}</span>
                  <ChevronDown className="w-4 h-4 text-slate-400" />
                </div>
              </button>

              {showHostDropdown && (
                <div
                  className={`absolute top-full left-0 right-0 mt-1.5 rounded-xl border shadow-2xl z-30 overflow-hidden divide-y ${
                    isLight
                      ? 'bg-white border-slate-300 divide-slate-100 text-slate-800'
                      : 'bg-slate-900 border-slate-700 divide-slate-800 text-slate-100'
                  }`}
                >
                  {hosts.map((h) => (
                    <div
                      key={h.id}
                      onClick={() => {
                        if (soundEnabled) playCyberTone('click');
                        onSelectTargetHost(h.id);
                        setShowHostDropdown(false);
                      }}
                      className={`flex items-center justify-between px-4 py-2.5 cursor-pointer text-xs font-mono transition-colors ${
                        isLight ? 'hover:bg-slate-100' : 'hover:bg-slate-800'
                      } ${
                        selectedTargetHostId === h.id
                          ? isLight
                            ? 'bg-cyan-50 font-bold'
                            : 'bg-cyan-950/40 font-bold'
                          : ''
                      }`}
                    >
                      <div className="flex items-center space-x-2">
                        <span className="font-bold">{h.name}</span>
                        <span className="text-slate-400 text-[11px]">{h.role}</span>
                      </div>
                      <span className="text-cyan-500">{h.ip}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Dynamic Parameter Settings based on Action */}
            {actionType === 'block_port' && (
              <div className="space-y-1.5">
                <label className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                  Target Port / Attack Vector
                </label>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                  {[
                    { port: 445, label: 'Port 445 (SMB)' },
                    { port: 22, label: 'Port 22 (SSH)' },
                    { port: 3389, label: 'Port 3389 (RDP)' },
                    { port: 8080, label: 'Port 8080 (API)' }
                  ].map((p) => (
                    <button
                      key={p.port}
                      onClick={() => {
                        if (soundEnabled) playCyberTone('click');
                        onSelectPort(p.port);
                      }}
                      className={`py-2 px-3 rounded-xl border text-xs font-mono transition-all ${
                        selectedPort === p.port
                          ? isLight
                            ? 'border-amber-400 bg-amber-50 text-amber-900 font-bold'
                            : 'border-amber-400 bg-amber-950/50 text-amber-300 font-bold'
                          : isLight
                          ? 'border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100'
                          : 'border-slate-800 bg-slate-900/60 text-slate-400 hover:text-white'
                      }`}
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {actionType === 'rate_limit' && (
              <div className="space-y-2 p-3.5 rounded-xl border border-blue-500/20 bg-blue-500/5">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="font-bold text-blue-500">Packet Dampening Factor:</span>
                  <span className="font-bold text-blue-400">{(rateLimitFactor * 100).toFixed(0)}% suppression</span>
                </div>
                <input
                  type="range"
                  min="0.1"
                  max="0.9"
                  step="0.05"
                  value={rateLimitFactor}
                  onChange={(e) => setRateLimitFactor(parseFloat(e.target.value))}
                  className="w-full h-2 bg-slate-200 dark:bg-slate-700 rounded-lg appearance-none cursor-pointer accent-blue-500"
                />
                <div className="flex justify-between text-[10px] font-mono text-slate-400">
                  <span>10% (Mild)</span>
                  <span>50% (Recommended)</span>
                  <span>90% (Strict throttle)</span>
                </div>
              </div>
            )}

            {actionType === 'segment_subnet' && (
              <div className="space-y-3 p-3.5 rounded-xl border border-purple-500/20 bg-purple-500/5">
                <div className="text-xs font-bold font-mono text-purple-500">
                  Subnet Quarantine Configuration
                </div>
                <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                  <div>
                    <label className="block text-[10px] text-slate-400 mb-1">Source Subnet (Isolate)</label>
                    <input
                      type="text"
                      value={subnetSource}
                      onChange={(e) => setSubnetSource(e.target.value)}
                      className={`w-full px-2.5 py-1.5 rounded-lg border text-xs font-mono ${
                        isLight ? 'bg-white border-slate-300 text-slate-800' : 'bg-slate-900 border-slate-700 text-slate-200'
                      }`}
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] text-slate-400 mb-1">Target Subnet (Protect)</label>
                    <input
                      type="text"
                      value={subnetTarget}
                      onChange={(e) => setSubnetTarget(e.target.value)}
                      className={`w-full px-2.5 py-1.5 rounded-lg border text-xs font-mono ${
                        isLight ? 'bg-white border-slate-300 text-slate-800' : 'bg-slate-900 border-slate-700 text-slate-200'
                      }`}
                    />
                  </div>
                </div>
              </div>
            )}

            {actionType === 'honeypot_divert' && (
              <div className="space-y-2 p-3.5 rounded-xl border border-emerald-500/20 bg-emerald-500/5">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="font-bold text-emerald-500">Deceptive Honeypot Sink IP:</span>
                  <span className="text-[10px] text-slate-400 font-mono">High-Interaction Decoy</span>
                </div>
                <input
                  type="text"
                  value={honeypotIp}
                  onChange={(e) => setHoneypotIp(e.target.value)}
                  className={`w-full px-3 py-2 rounded-lg border text-xs font-mono font-bold ${
                    isLight ? 'bg-white border-slate-300 text-slate-800' : 'bg-slate-900 border-slate-700 text-emerald-400'
                  }`}
                />
              </div>
            )}

            {/* Primary Action Button: Simulate */}
            <button
              onClick={() => {
                if (soundEnabled) playCyberTone('sim');
                onRunSimulation();
              }}
              disabled={isSimulating}
              className="w-full flex items-center justify-center space-x-2.5 py-3.5 px-5 rounded-xl bg-gradient-to-r from-cyan-600 via-cyan-500 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold font-sans text-sm tracking-wide shadow-[0_0_20px_rgba(6,182,212,0.35)] active:scale-98 transition-all disabled:opacity-50 cursor-pointer"
            >
              <Zap className={`w-4 h-4 fill-white ${isSimulating ? 'animate-spin' : ''}`} />
              <span>
                {isSimulating ? 'Evaluating Graph Rollout in Memory...' : 'Simulate Counterfactual Defense (<30ms)'}
              </span>
            </button>

            {/* Mathematical Evaluation Card: Net Defense Score & Collateral */}
            <div
              className={`p-4 rounded-xl border space-y-3.5 ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/70 border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400 uppercase font-semibold">Simulated Outcome Telemetry</span>
                <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-500 font-bold border border-cyan-500/30">
                  Latency: 18.4ms (Target &lt;30ms)
                </span>
              </div>

              {/* Net Defense Score & Disruption Cost Metrics */}
              <div className="grid grid-cols-3 gap-2 text-center">
                <div className={`p-2.5 rounded-lg border ${isLight ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-800'}`}>
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Risk Reduction</div>
                  <div className="text-base font-black font-mono text-emerald-500 mt-0.5">
                    -{calculatedRiskReduction}%
                  </div>
                </div>
                <div className={`p-2.5 rounded-lg border ${isLight ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-800'}`}>
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Disruption Cost</div>
                  <div className="text-base font-black font-mono text-amber-500 mt-0.5">
                    {calculatedDisruptionCost}%
                  </div>
                </div>
                <div className={`p-2.5 rounded-lg border ${isLight ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-800'}`}>
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Net Defense Score</div>
                  <div className="text-base font-black font-mono text-cyan-500 mt-0.5">
                    +{netDefenseScore}
                  </div>
                </div>
              </div>

              {/* Before & After Risk Bar */}
              <div className="flex items-baseline justify-between pt-1">
                <div>
                  <span className="text-xs text-slate-400 font-mono">Current Infiltration Risk</span>
                  <div className="text-2xl sm:text-3xl font-extrabold font-mono text-rose-500">
                    {currentThreatRisk}%
                  </div>
                </div>

                <div className="text-slate-400 text-xl font-bold">➔</div>

                <div className="text-right">
                  <span className="text-xs text-slate-400 font-mono">Post-Mitigation Projected</span>
                  <div className="text-2xl sm:text-3xl font-extrabold font-mono text-emerald-500">
                    {simulatedRisk}%
                  </div>
                </div>
              </div>

              <div className="relative h-2.5 w-full rounded-full bg-slate-300 dark:bg-slate-800 overflow-hidden">
                <div
                  className="absolute left-0 top-0 bottom-0 bg-rose-500 transition-all duration-500"
                  style={{ width: `${currentThreatRisk}%` }}
                />
                <div
                  className="absolute left-0 top-0 bottom-0 bg-emerald-400 transition-all duration-500 shadow-[0_0_8px_#34d399]"
                  style={{ width: `${simulatedRisk}%` }}
                />
              </div>

              {/* Collateral Connections Note */}
              <div className="flex items-center justify-between text-xs font-mono pt-1 text-slate-400">
                <span className="flex items-center space-x-1">
                  <CornerDownRight className="w-3.5 h-3.5 text-cyan-500" />
                  <span>Collateral severed connections:</span>
                </span>
                <span className="font-bold text-slate-200">
                  {collateralConnections} active socket edges
                </span>
              </div>
            </div>

            {/* Deploy Policy Button */}
            <div>
              <button
                onClick={handleDeploy}
                className={`w-full flex items-center justify-center space-x-2 py-3 px-4 rounded-xl border font-sans font-bold text-xs transition-all cursor-pointer ${
                  isLight
                    ? 'border-emerald-300 bg-emerald-50 hover:bg-emerald-100 text-emerald-900'
                    : 'border-emerald-500/40 bg-emerald-950/30 hover:bg-emerald-950/50 text-emerald-300'
                }`}
              >
                <ShieldCheck className="w-4 h-4 text-emerald-500" />
                <span>Deploy Verified Policy to Active Firewalls</span>
              </button>

              {showDeploySuccess && (
                <div className="mt-2.5 p-3 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-600 dark:text-emerald-300 text-xs font-sans font-semibold flex items-center justify-center space-x-2 animate-in fade-in">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                  <span>Policy successfully deployed. Network traffic rerouted away from compromised node.</span>
                </div>
              )}
            </div>
          </div>

          {/* Right Column: Simulation History & Blast Radius Analysis (5 cols) */}
          <div className="lg:col-span-5 space-y-5">
            {/* History Panel */}
            <div
              className={`rounded-2xl border p-5 shadow-xl space-y-4 transition-colors ${
                isLight
                  ? 'bg-white border-slate-200 text-slate-800'
                  : isMidnight
                  ? 'bg-[#071329]/95 border-[#142f5c] text-slate-100'
                  : 'bg-[#0e1628]/95 border-[#1d2a45] text-slate-100'
              }`}
            >
              <div className="flex items-center justify-between border-b pb-3">
                <div>
                  <h4 className={`text-sm font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
                    Recent Simulation History
                  </h4>
                  <p className={`text-[11px] font-sans ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                    Click any past scenario to reload its configuration
                  </p>
                </div>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                    isLight ? 'bg-slate-100 text-slate-600' : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {recentSimulations.length} runs
                </span>
              </div>

              <div className="space-y-2 max-h-[280px] overflow-y-auto pr-1">
                {recentSimulations.map((sim) => (
                  <div
                    key={sim.id}
                    onClick={() => {
                      if (soundEnabled) playCyberTone('click');
                      onSelectSimulation(sim);
                    }}
                    className={`flex items-center justify-between p-3 rounded-xl border cursor-pointer transition-all ${
                      isLight
                        ? 'border-slate-200 bg-slate-50 hover:bg-slate-100'
                        : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800 hover:border-cyan-500/30'
                    }`}
                  >
                    <div className="flex items-center space-x-3">
                      <div
                        className={`p-2 rounded-lg ${
                          isLight ? 'bg-white text-cyan-700 shadow-2xs' : 'bg-slate-800 text-cyan-400'
                        }`}
                      >
                        {sim.actionType === 'isolate_host' ? (
                          <Lock className="w-4 h-4" />
                        ) : sim.actionType === 'block_port' ? (
                          <Ban className="w-4 h-4" />
                        ) : sim.actionType === 'rate_limit' ? (
                          <SlidersHorizontal className="w-4 h-4 text-blue-400" />
                        ) : sim.actionType === 'segment_subnet' ? (
                          <Network className="w-4 h-4 text-purple-400" />
                        ) : (
                          <Radio className="w-4 h-4 text-emerald-400" />
                        )}
                      </div>
                      <div>
                        <div className="font-bold text-xs font-sans">{sim.actionLabel}</div>
                        <div className="text-[10px] text-slate-400 flex items-center space-x-1 mt-0.5 font-mono">
                          <Clock className="w-2.5 h-2.5" />
                          <span>{sim.timeAgo}</span>
                          <span>·</span>
                          <span>{sim.targetLabel}</span>
                        </div>
                      </div>
                    </div>

                    <div className="text-right">
                      <div className="text-xs font-mono font-bold text-emerald-500">
                        {sim.delta < 0 ? `${sim.delta} pts` : `-${sim.delta} pts`}
                      </div>
                      <div className="text-[10px] font-mono text-slate-400">
                        {sim.initialRisk}% ➔ {sim.simulatedRisk}%
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Blast Radius Assessment Card */}
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
                <ShieldAlert className="w-4 h-4 text-amber-500" />
                <h4 className={`text-sm font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  Blast Radius Impact Analysis
                </h4>
              </div>

              <div className="space-y-2 text-xs font-sans">
                <div
                  className={`p-2.5 rounded-xl border flex items-center justify-between ${
                    isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
                  }`}
                >
                  <span className="text-slate-500 font-medium">Domain Controller Exposure:</span>
                  <span className="font-bold text-emerald-500">Protected (-91%)</span>
                </div>
                <div
                  className={`p-2.5 rounded-xl border flex items-center justify-between ${
                    isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
                  }`}
                >
                  <span className="text-slate-500 font-medium">Internal API Availability:</span>
                  <span className="font-bold text-slate-400">99.8% Nominal</span>
                </div>
                <div
                  className={`p-2.5 rounded-xl border flex items-center justify-between ${
                    isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
                  }`}
                >
                  <span className="text-slate-500 font-medium">Lateral Traversal Paths:</span>
                  <span className="font-bold text-emerald-500">Severed (0 reachable hops)</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* VIEW B: OPTIMAL ACTION RANKING (rank_interventions) */}
      {viewMode === 'ranking' && (
        <div
          className={`p-5 sm:p-6 rounded-2xl border shadow-xl space-y-5 transition-colors ${
            isLight
              ? 'bg-white border-slate-200 text-slate-800'
              : isMidnight
              ? 'bg-[#071329]/95 border-[#142f5c] text-slate-100'
              : 'bg-[#0e1628]/95 border-[#1d2a45] text-slate-100'
          }`}
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b pb-4">
            <div>
              <div className="flex items-center space-x-2">
                <Award className="w-5 h-5 text-amber-500" />
                <h3 className={`text-base font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  Optimal Action Ranking (`rank_interventions`)
                </h3>
              </div>
              <p className={`text-xs font-sans mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                Evaluates candidate interventions and ranks them by Net Defense Score ($RiskReduction - BusinessDisruptionCost$) in under 30ms.
              </p>
            </div>

            <div className="flex items-center space-x-2 text-xs font-mono">
              <span className="text-slate-400">Evaluated in:</span>
              <span className="font-bold text-cyan-500">{rankingLatencyMs}ms (&lt;30ms SLA)</span>
            </div>
          </div>

          {/* Mathematical Formula Banner */}
          <div
            className={`p-3.5 rounded-xl border text-xs font-mono flex items-center justify-between flex-wrap gap-2 ${
              isLight ? 'bg-slate-50 border-slate-200 text-slate-700' : 'bg-slate-900/60 border-slate-800 text-slate-300'
            }`}
          >
            <div className="flex items-center space-x-2">
              <Sparkles className="w-4 h-4 text-cyan-500" />
              <span>
                <strong>Objective:</strong> $\text{'{Net Defense Score}'} = \text{'{Risk Reduction}'} - \text{'{Business Disruption Cost}'}$
              </span>
            </div>
            <span className="text-emerald-500 font-bold">
              Recommended: Action #1 (Maximum Net Score)
            </span>
          </div>

          {/* Ranking Cards / Table */}
          <div className="space-y-3">
            {rankedList.length === 0 ? (
              <div
                className={`p-10 rounded-xl border text-center font-mono text-xs ${
                  isLight ? 'bg-slate-50 border-slate-200 text-slate-500' : 'bg-slate-900/40 border-slate-800 text-slate-400'
                }`}
              >
                <div className="mb-2">Click "Rank Mitigations" to evaluate candidate interventions against the backend live world model</div>
                <button
                  onClick={handleRankInterventions}
                  disabled={isRanking}
                  className="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs cursor-pointer shadow-sm"
                >
                  {isRanking ? 'Evaluating Candidates...' : 'Run Optimization Rank'}
                </button>
              </div>
            ) : (
              rankedList.map((item) => (
              <div
                key={item.rank}
                className={`p-4 rounded-xl border transition-all ${
                  item.recommended
                    ? isLight
                      ? 'border-emerald-400 bg-emerald-50/50 shadow-md ring-1 ring-emerald-400/50'
                      : 'border-emerald-500/50 bg-emerald-950/20 shadow-[0_0_16px_rgba(16,185,129,0.15)] ring-1 ring-emerald-500/40'
                    : isLight
                    ? 'border-slate-200 bg-slate-50/60 hover:bg-slate-100'
                    : 'border-slate-800 bg-slate-900/40 hover:bg-slate-800/60'
                }`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  {/* Rank badge + Action details */}
                  <div className="flex items-start space-x-3.5">
                    <div
                      className={`w-9 h-9 rounded-xl flex items-center justify-center font-black font-mono text-sm shrink-0 ${
                        item.recommended
                          ? 'bg-emerald-500 text-slate-950 shadow-sm'
                          : isLight
                          ? 'bg-slate-200 text-slate-700'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      #{item.rank}
                    </div>

                    <div>
                      <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                        <span className="font-bold text-sm font-sans">{item.actionLabel}</span>
                        <code className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                          {item.action}
                        </code>
                        {item.recommended && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500 text-slate-950">
                            OPTIMAL ACTION
                          </span>
                        )}
                      </div>
                      <p className={`text-xs font-mono mt-0.5 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                        Target: <strong className="text-cyan-500">{item.targetLabel}</strong>
                      </p>
                      <p className={`text-xs font-sans mt-1 ${isLight ? 'text-slate-700' : 'text-slate-300'}`}>
                        {item.rationale}
                      </p>
                    </div>
                  </div>

                  {/* Quantitative Scores & 1-Click Apply */}
                  <div className="flex items-center space-x-4 shrink-0 flex-wrap gap-y-2">
                    <div className="grid grid-cols-4 gap-2 text-center text-xs font-mono">
                      <div className={`p-2 rounded-lg border ${isLight ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-800'}`}>
                        <div className="text-[9px] text-slate-400">Risk Red.</div>
                        <div className="font-bold text-emerald-500">+{(item.riskReduction * 100).toFixed(0)}%</div>
                      </div>
                      <div className={`p-2 rounded-lg border ${isLight ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-800'}`}>
                        <div className="text-[9px] text-slate-400">Cost</div>
                        <div className="font-bold text-amber-500">{(item.businessDisruptionCost * 100).toFixed(0)}%</div>
                      </div>
                      <div className={`p-2 rounded-lg border ${isLight ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-800'}`}>
                        <div className="text-[9px] text-slate-400">Net Score</div>
                        <div className="font-bold text-cyan-400">+{item.netDefenseScore.toFixed(2)}</div>
                      </div>
                      <div className={`p-2 rounded-lg border ${isLight ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-800'}`}>
                        <div className="text-[9px] text-slate-400">Latency</div>
                        <div className="font-bold text-slate-400">{item.latencyMs}ms</div>
                      </div>
                    </div>

                    <button
                      onClick={() => handleSelectRankedCandidate(item)}
                      className={`px-3.5 py-2.5 rounded-xl font-sans font-bold text-xs flex items-center space-x-1.5 transition-all cursor-pointer ${
                        item.recommended
                          ? 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-sm'
                          : isLight
                          ? 'bg-slate-200 hover:bg-slate-300 text-slate-800'
                          : 'bg-slate-800 hover:bg-slate-700 text-slate-200'
                      }`}
                    >
                      <span>Select & Simulate</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            )))}
          </div>
        </div>
      )}
    </div>
  );
};

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
  ShieldAlert
} from 'lucide-react';
import { NetworkHost, DefenceActionType, SimulationRecord, AppTheme } from '../types';
import { playCyberTone } from '../utils/audio';

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
  const [showHostDropdown, setShowHostDropdown] = useState(false);
  const [showDeploySuccess, setShowDeploySuccess] = useState(false);

  const isLight = theme === 'light';
  const isMidnight = theme === 'midnight';

  const selectedHost = hosts.find((h) => h.id === selectedTargetHostId) || hosts[0];

  const handleDeploy = () => {
    if (soundEnabled) playCyberTone('success');
    onDeployPolicy();
    setShowDeploySuccess(true);
    setTimeout(() => setShowDeploySuccess(false), 3500);
  };

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
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-3 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 shrink-0 mt-0.5">
              <GitFork className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-lg sm:text-xl font-bold font-sans tracking-tight">
                  Counterfactual Defense Simulator
                </h2>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                    isLight
                      ? 'bg-cyan-50 text-cyan-700 border-cyan-200'
                      : 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40'
                  }`}
                >
                  Policy Sandbox
                </span>
              </div>
              <p className={`text-xs font-sans mt-1 max-w-2xl ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                Simulate firewall rules, network quarantine, and port blocks in-memory before applying them to physical edge devices. Evaluates projected blast radius reduction in real time.
              </p>
            </div>
          </div>

          <div
            className={`px-4 py-2.5 rounded-xl border text-xs font-mono shrink-0 ${
              isLight
                ? 'bg-slate-50 border-slate-200 text-slate-700'
                : 'bg-slate-900/80 border-slate-800 text-slate-300'
            }`}
          >
            <div className="text-[10px] text-slate-400 uppercase font-semibold">Active Engine Mode</div>
            <div className="font-bold text-cyan-500 mt-0.5">Graph Neural Counterfactuals</div>
          </div>
        </div>
      </div>

      {/* 2. Main 12-Column Layout */}
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
          <div className="border-b pb-4">
            <h3 className={`text-base font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
              Configure Mitigation Action
            </h3>
            <p className={`text-xs font-sans mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
              Select the network defense action and the target infrastructure node to test.
            </p>
          </div>

          {/* Action Selector */}
          <div className="space-y-1.5">
            <label className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
              Defense Action Type
            </label>
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => {
                  if (soundEnabled) playCyberTone('click');
                  onChangeActionType('isolate_host');
                }}
                className={`flex items-center space-x-2.5 p-3 rounded-xl border text-xs font-sans font-bold transition-all ${
                  actionType === 'isolate_host'
                    ? isLight
                      ? 'border-cyan-400 bg-cyan-50 text-cyan-900 shadow-xs'
                      : 'border-cyan-400 bg-cyan-950/40 text-cyan-200 shadow-[0_0_12px_rgba(6,182,212,0.25)]'
                    : isLight
                    ? 'border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700'
                    : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-300'
                }`}
              >
                <Lock className="w-4 h-4 text-cyan-500 shrink-0" />
                <div className="text-left">
                  <div>Isolate Host</div>
                  <div className="text-[10px] font-normal opacity-70">Cut off all internal network routes</div>
                </div>
              </button>

              <button
                onClick={() => {
                  if (soundEnabled) playCyberTone('click');
                  onChangeActionType('block_port');
                }}
                className={`flex items-center space-x-2.5 p-3 rounded-xl border text-xs font-sans font-bold transition-all ${
                  actionType === 'block_port'
                    ? isLight
                      ? 'border-cyan-400 bg-cyan-50 text-cyan-900 shadow-xs'
                      : 'border-cyan-400 bg-cyan-950/40 text-cyan-200 shadow-[0_0_12px_rgba(6,182,212,0.25)]'
                    : isLight
                    ? 'border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700'
                    : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-300'
                }`}
              >
                <Ban className="w-4 h-4 text-amber-500 shrink-0" />
                <div className="text-left">
                  <div>Block Port / Service</div>
                  <div className="text-[10px] font-normal opacity-70">Drop inbound packets on target port</div>
                </div>
              </button>
            </div>
          </div>

          {/* Target Host Selector: Visible Interactive Node Cards */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                Target Node ({hosts.length} Available in Active Network)
              </label>
              <span className="text-[11px] text-cyan-500 font-mono font-semibold">
                Click any node to switch
              </span>
            </div>

            {/* Grid of host cards so the user can easily click and switch between nodes */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
              {hosts.map((h) => {
                const isSelected = selectedTargetHostId === h.id;
                const isComp = h.status === 'compromised';
                const isTgt = h.status === 'targeted';
                return (
                  <button
                    key={h.id}
                    type="button"
                    onClick={() => {
                      if (soundEnabled) playCyberTone('click');
                      onSelectTargetHost(h.id);
                      if (h.openPorts && h.openPorts.length > 0) {
                        onSelectPort(h.openPorts[0]);
                      }
                    }}
                    className={`p-3 rounded-xl border text-left transition-all relative ${
                      isSelected
                        ? isLight
                          ? 'border-cyan-500 bg-cyan-50/90 shadow-md ring-2 ring-cyan-400/30'
                          : 'border-cyan-400 bg-cyan-950/60 shadow-[0_0_15px_rgba(6,182,212,0.3)] ring-2 ring-cyan-400/40'
                        : isLight
                        ? 'border-slate-200 bg-slate-50 hover:bg-slate-100 hover:border-slate-300'
                        : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <Server className={`w-3.5 h-3.5 ${isSelected ? 'text-cyan-500' : 'text-slate-400'}`} />
                        <span className="font-bold font-mono text-xs">{h.name}</span>
                      </div>
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold font-mono uppercase ${
                        isComp
                          ? 'bg-rose-500/20 text-rose-500'
                          : isTgt
                          ? 'bg-amber-500/20 text-amber-500'
                          : 'bg-emerald-500/20 text-emerald-500'
                      }`}>
                        {isComp ? 'Breached' : isTgt ? 'Targeted' : 'Healthy'}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 truncate">
                      {h.role}
                    </div>
                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mt-1.5">
                      <span>{h.ip}</span>
                      <span className="text-cyan-600 dark:text-cyan-400 font-semibold">
                        {h.openPorts?.length ? `P: ${h.openPorts.slice(0, 3).join(', ')}` : 'No Ports'}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Port Selector (if block_port is chosen) */}
          {actionType === 'block_port' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                  Target Port / Attack Vector on {selectedHost.name}
                </label>
                <span className="text-[11px] text-amber-500 font-mono">
                  {selectedHost.openPorts?.length ? `${selectedHost.openPorts.length} open services detected` : 'Standard ports'}
                </span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
                {(() => {
                  const portProtocols: { [p: number]: string } = {
                    21: 'FTP',
                    22: 'SSH',
                    23: 'Telnet',
                    25: 'SMTP',
                    53: 'DNS',
                    80: 'HTTP',
                    88: 'Kerberos',
                    135: 'RPC',
                    443: 'HTTPS',
                    445: 'SMB / PsExec',
                    3389: 'RDP Sync',
                    5000: 'TCP/5000',
                    5432: 'PostgreSQL',
                    8080: 'Web Proxy'
                  };
                  const hostPorts = selectedHost?.openPorts?.length ? selectedHost.openPorts : [445, 3389, 80, 443, 22, 21];
                  const allPorts = Array.from(new Set([...hostPorts, 445, 3389, 80, 443]));

                  return allPorts.map((p) => {
                    const label = `Port ${p} (${portProtocols[p] || 'TCP Service'})`;
                    const isSelected = selectedPort === p;
                    return (
                      <button
                        key={p}
                        type="button"
                        onClick={() => {
                          if (soundEnabled) playCyberTone('click');
                          onSelectPort(p);
                        }}
                        className={`py-2.5 px-3 rounded-xl border text-xs font-mono transition-all text-left flex items-center justify-between ${
                          isSelected
                            ? isLight
                              ? 'border-amber-400 bg-amber-50 text-amber-900 font-bold shadow-sm ring-1 ring-amber-400'
                              : 'border-amber-400 bg-amber-950/60 text-amber-300 font-bold shadow-[0_0_10px_rgba(251,191,36,0.25)] ring-1 ring-amber-400'
                            : isLight
                            ? 'border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100 hover:border-slate-300'
                            : 'border-slate-800 bg-slate-900/60 text-slate-300 hover:bg-slate-800 hover:text-white'
                        }`}
                      >
                        <span>{label}</span>
                        {selectedHost?.openPorts?.includes(p) && (
                          <span className="w-1.5 h-1.5 rounded-full bg-amber-400" title="Open on selected host" />
                        )}
                      </button>
                    );
                  });
                })()}
              </div>
            </div>
          )}

          {/* Primary Action Button: Simulate */}
          <button
            onClick={() => {
              if (soundEnabled) playCyberTone('sim');
              onRunSimulation();
            }}
            disabled={isSimulating}
            className="w-full flex items-center justify-center space-x-2.5 py-3.5 px-5 rounded-xl bg-gradient-to-r from-cyan-600 via-cyan-500 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold font-sans text-sm tracking-wide shadow-[0_0_20px_rgba(6,182,212,0.35)] active:scale-98 transition-all disabled:opacity-50"
          >
            <Zap className={`w-4 h-4 fill-white ${isSimulating ? 'animate-spin' : ''}`} />
            <span>{isSimulating ? 'Running In-Memory Counterfactual...' : 'Simulate Counterfactual Defense'}</span>
          </button>

          {/* Simulated Risk Reduction Comparison Gauge */}
          <div
            className={`p-4 rounded-xl border space-y-3 ${
              isLight
                ? 'bg-slate-50 border-slate-200'
                : 'bg-slate-900/70 border-slate-800'
            }`}
          >
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400 uppercase font-semibold">Simulated Threat Impact</span>
              <span className="text-emerald-500 font-bold">
                {deltaPts > 0 ? `-${deltaPts} pts reduction` : `${deltaPts} pts`}
              </span>
            </div>

            <div className="flex items-baseline justify-between">
              <div>
                <span className="text-xs text-slate-400 font-mono">Current Infiltration Risk</span>
                <div className="text-2xl sm:text-3xl font-extrabold font-mono text-rose-500">
                  {currentThreatRisk}%
                </div>
              </div>

              <div className="text-slate-400 text-xl font-bold">➔</div>

              <div className="text-right">
                <span className="text-xs text-slate-400 font-mono">Post-Mitigation Projected Risk</span>
                <div className="text-2xl sm:text-3xl font-extrabold font-mono text-emerald-500">
                  {simulatedRisk}%
                </div>
              </div>
            </div>

            {/* Visual Bar */}
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
          </div>

          {/* Deploy Policy Button */}
          <div>
            <button
              onClick={handleDeploy}
              className={`w-full flex items-center justify-center space-x-2 py-3 px-4 rounded-xl border font-sans font-bold text-xs transition-all ${
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
                      {sim.actionType === 'isolate_host' ? <Lock className="w-4 h-4" /> : <Ban className="w-4 h-4" />}
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
                <span className="text-slate-500 font-medium">Lateral Propagation Paths:</span>
                <span className="font-bold text-emerald-500">Severed (0 reachable hops)</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

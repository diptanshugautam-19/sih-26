import React, { useState } from 'react';
import {
  GitFork,
  Lock,
  Ban,
  Zap,
  ChevronDown,
  Clock,
  ArrowDownRight,
  ShieldCheck,
  CheckCircle2,
  Sliders,
  Send
} from 'lucide-react';
import { NetworkHost, DefenceActionType, SimulationRecord } from '../types';
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
  currentThreatRisk: number | null;
  simulatedRisk: number | null;
  deltaPts: number | null;
  recentSimulations: SimulationRecord[];
  onSelectSimulation: (sim: SimulationRecord) => void;
  onDeployPolicy: () => void;
  soundEnabled: boolean;
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
  soundEnabled
}) => {
  const [showHostDropdown, setShowHostDropdown] = useState(false);
  const [showDeploySuccess, setShowDeploySuccess] = useState(false);

  const selectedHost = hosts.find((h) => h.id === selectedTargetHostId) || hosts[0] || null;

  const handleDeploy = () => {
    if (soundEnabled) playCyberTone('success');
    onDeployPolicy();
    setShowDeploySuccess(true);
    setTimeout(() => setShowDeploySuccess(false), 3500);
  };

  return (
    <div className="flex flex-col rounded-xl border border-[#142d54] bg-[#061126]/90 overflow-hidden backdrop-blur-md">
      {/* Header */}
      <div className="flex items-center justify-between px-4 sm:px-5 py-3.5 border-b border-[#12284c] bg-[#08152e]/70">
        <div>
          <div className="text-[11px] font-mono tracking-wider text-slate-400">
            03 <span className="text-slate-600">/</span> COUNTERFACTUAL
          </div>
          <h3 className="text-base sm:text-lg font-bold text-white tracking-tight">
            What-if centre
          </h3>
        </div>

        <div className="px-2.5 py-1 rounded bg-cyan-950/60 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-bold tracking-wider shadow-[0_0_10px_rgba(6,182,212,0.2)]">
          SUB-50MS SIM
        </div>
      </div>

      {/* Hero simulation prompt banner */}
      <div className="p-4 bg-[#07152f]/50 border-b border-[#102447] flex items-start space-x-3.5">
        <div className="p-2 rounded-lg border border-cyan-500/30 bg-cyan-950/30 text-cyan-400 shrink-0">
          <GitFork className="w-5 h-5" />
        </div>
        <div className="space-y-0.5">
          <h4 className="text-xs sm:text-sm font-bold text-slate-100 font-sans">
            Test a defence before deploying it
          </h4>
          <p className="text-[11px] font-mono text-slate-400 leading-snug">
            Modify the cached graph sequence in memory.
          </p>
        </div>
      </div>

      {/* Main control form */}
      <div className="p-4 sm:p-5 space-y-4">
        {/* DEFENCE ACTION Selector */}
        <div className="space-y-1.5">
          <label className="text-[10px] font-mono tracking-wider text-slate-400 uppercase font-semibold">
            Defence Action
          </label>
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={() => {
                if (soundEnabled) playCyberTone('click');
                onChangeActionType('isolate_host');
              }}
              className={`flex items-center justify-center space-x-2 py-2 px-3 rounded-lg border text-xs font-mono font-medium transition-all ${
                actionType === 'isolate_host'
                  ? 'border-cyan-400 bg-cyan-950/40 text-cyan-300 shadow-[0_0_12px_rgba(6,182,212,0.25)]'
                  : 'border-[#142d54] bg-[#071329] text-slate-400 hover:text-slate-200 hover:border-[#1e447d]'
              }`}
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Isolate host</span>
            </button>

            <button
              onClick={() => {
                if (soundEnabled) playCyberTone('click');
                onChangeActionType('block_port');
              }}
              className={`flex items-center justify-center space-x-2 py-2 px-3 rounded-lg border text-xs font-mono font-medium transition-all ${
                actionType === 'block_port'
                  ? 'border-cyan-400 bg-cyan-950/40 text-cyan-300 shadow-[0_0_12px_rgba(6,182,212,0.25)]'
                  : 'border-[#142d54] bg-[#071329] text-slate-400 hover:text-slate-200 hover:border-[#1e447d]'
              }`}
            >
              <Ban className="w-3.5 h-3.5" />
              <span>Block port</span>
            </button>
          </div>
        </div>

        {/* TARGET HOST Selector */}
        <div className="space-y-1.5 relative">
          <label className="text-[10px] font-mono tracking-wider text-slate-400 uppercase font-semibold">
            Target Host
          </label>
          <button
            onClick={() => hosts.length > 0 && setShowHostDropdown(!showHostDropdown)}
            disabled={hosts.length === 0}
            className="w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg border border-[#142d54] bg-[#071329] text-xs font-mono text-slate-200 hover:border-cyan-500/40 transition-colors disabled:opacity-50"
          >
            <span className="font-bold text-white">
              {selectedHost ? selectedHost.name : 'No Target Host (Awaiting Telemetry)'}
            </span>
            <div className="flex items-center space-x-2 text-slate-400">
              <span>{selectedHost ? selectedHost.ip : '--'}</span>
              <ChevronDown className="w-3.5 h-3.5" />
            </div>
          </button>

          {/* Host Dropdown Options */}
          {showHostDropdown && hosts.length > 0 && (
            <div className="absolute top-full left-0 right-0 mt-1 rounded-lg border border-[#173a72] bg-[#071329] shadow-2xl z-30 overflow-hidden divide-y divide-[#10264b]">
              {hosts.map((h) => (
                <div
                  key={h.id}
                  onClick={() => {
                    if (soundEnabled) playCyberTone('click');
                    onSelectTargetHost(h.id);
                    setShowHostDropdown(false);
                  }}
                  className="flex items-center justify-between px-3.5 py-2 hover:bg-[#0c234a] cursor-pointer text-xs font-mono transition-colors"
                >
                  <span className="text-slate-100 font-bold">{h.name}</span>
                  <span className="text-cyan-400 text-[11px]">{h.ip}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* TARGET PORT Selector (shown when block_port is active) */}
        {actionType === 'block_port' && (
          <div className="space-y-1.5">
            <label className="text-[10px] font-mono tracking-wider text-slate-400 uppercase font-semibold">
              Target Port (Service)
            </label>
            <div className="grid grid-cols-3 gap-2">
              {[
                { port: 445, label: '445 (SMB)' },
                { port: 3389, label: '3389 (RDP)' },
                { port: 8080, label: '8080 (API)' }
              ].map((p) => (
                <button
                  key={p.port}
                  onClick={() => {
                    if (soundEnabled) playCyberTone('click');
                    onSelectPort(p.port);
                  }}
                  className={`py-1.5 px-2 rounded border text-xs font-mono transition-all ${
                    selectedPort === p.port
                      ? 'border-cyan-400 bg-cyan-950/40 text-cyan-300'
                      : 'border-[#142d54] bg-[#071329] text-slate-400 hover:text-white'
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Big Action Button: Simulate Defence */}
        <button
          onClick={() => {
            if (soundEnabled) playCyberTone('sim');
            onRunSimulation();
          }}
          disabled={isSimulating || hosts.length === 0}
          className="w-full flex items-center justify-center space-x-2 py-3 px-4 rounded-lg bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold font-mono text-sm tracking-wide shadow-[0_0_20px_rgba(6,182,212,0.4)] hover:shadow-[0_0_25px_rgba(6,182,212,0.6)] active:scale-98 transition-all disabled:opacity-40"
        >
          <Zap className={`w-4 h-4 fill-slate-950 ${isSimulating ? 'animate-bounce' : ''}`} />
          <span>{hosts.length === 0 ? 'Awaiting Host Telemetry...' : isSimulating ? 'Simulating in memory...' : 'Simulate defence'}</span>
        </button>

        {/* SIMULATED RISK REDUCTION METRICS */}
        <div className="pt-2 border-t border-[#12284c] space-y-2.5">
          <div className="flex items-center justify-between text-[10px] font-mono tracking-wider uppercase">
            <span className="text-slate-400 font-semibold">Simulated Risk Reduction</span>
            <span className="text-slate-500">World Model Delta</span>
          </div>

          <div className="flex items-baseline justify-between">
            <div className="flex items-center space-x-2 font-mono">
              <span className="text-2xl sm:text-3xl font-extrabold text-rose-500">
                {currentThreatRisk != null ? `${currentThreatRisk}%` : '--'}
              </span>
              <span className="text-slate-400 text-lg">↘</span>
              <span className="text-2xl sm:text-3xl font-extrabold text-emerald-400 drop-shadow-[0_0_10px_rgba(16,185,129,0.3)]">
                {simulatedRisk != null ? `${simulatedRisk}%` : '--'}
              </span>
            </div>

            <div className="text-sm sm:text-base font-mono font-bold text-emerald-400 bg-emerald-950/30 px-2 py-0.5 rounded border border-emerald-500/30">
              {deltaPts != null ? (deltaPts > 0 ? `-${deltaPts} pts` : `${deltaPts} pts`) : '--'}
            </div>
          </div>

          {/* Dual Segment Progress Bar */}
          <div className="relative h-2 w-full rounded-full bg-[#0c1c38] overflow-hidden">
            <div
              className="absolute left-0 top-0 bottom-0 bg-rose-500 transition-all duration-500"
              style={{ width: `${currentThreatRisk || 0}%` }}
            />
            <div
              className="absolute left-0 top-0 bottom-0 bg-emerald-400 shadow-[0_0_8px_#34d399] transition-all duration-500"
              style={{ width: `${simulatedRisk || 0}%` }}
            />
          </div>

          <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
            <span>Current threat</span>
            <span>After {actionType === 'isolate_host' ? 'isolation' : 'port block'}</span>
          </div>
        </div>

        {/* RECENT SIMULATIONS LIST */}
        <div className="pt-3 border-t border-[#12284c] space-y-2">
          <div className="flex items-center justify-between text-[10px] font-mono tracking-wider text-slate-400 uppercase">
            <span>Recent Simulations</span>
            <span className="text-slate-500">{recentSimulations.length} Runs</span>
          </div>

          <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
            {recentSimulations.length === 0 ? (
              <div className="text-center py-4 text-slate-500 text-[11px] font-mono border border-dashed border-[#142d54] rounded-lg">
                No simulation history yet. Select an action above to test intervention impact.
              </div>
            ) : (
              recentSimulations.map((sim) => (
                <div
                  key={sim.id}
                  onClick={() => {
                    if (soundEnabled) playCyberTone('click');
                    onSelectSimulation(sim);
                  }}
                  className="flex items-center justify-between p-2.5 rounded-lg border border-[#122b54] bg-[#071329] hover:bg-[#0c234a] hover:border-cyan-500/30 cursor-pointer transition-colors text-xs font-mono"
                >
                  <div className="flex items-center space-x-2.5">
                    <div className="p-1.5 rounded bg-[#0b2247] text-cyan-400">
                      {sim.actionType === 'isolate_host' ? (
                        <Lock className="w-3.5 h-3.5" />
                      ) : (
                        <Ban className="w-3.5 h-3.5" />
                      )}
                    </div>
                    <div>
                      <div className="font-bold text-slate-200">
                        {sim.actionLabel} · {sim.targetLabel}
                      </div>
                      <div className="text-[10px] text-slate-500 flex items-center space-x-1">
                        <Clock className="w-2.5 h-2.5" />
                        <span>{sim.timeAgo} · simulated</span>
                      </div>
                    </div>
                  </div>

                  <div className="text-right">
                    <div className="text-[11px] font-bold text-slate-300">
                      <span className="text-rose-400">{sim.initialRisk}%</span>
                      <span className="text-slate-500 mx-1">↘</span>
                      <span className="text-emerald-400">{sim.simulatedRisk}%</span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Deploy to Network Firewalls / Orchestration button */}
        <div className="pt-2">
          <button
            onClick={handleDeploy}
            className="w-full flex items-center justify-center space-x-2 py-2 px-3 rounded-lg border border-emerald-500/40 bg-emerald-950/20 hover:bg-emerald-950/40 text-emerald-400 text-xs font-mono font-semibold transition-all"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Apply defence to active firewall rules</span>
          </button>

          {showDeploySuccess && (
            <div className="mt-2 p-2 rounded bg-emerald-950/60 border border-emerald-500/50 text-emerald-300 text-[11px] font-mono text-center animate-in fade-in flex items-center justify-center space-x-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span>Counterfactual rule pushed to edge orchestrator!</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

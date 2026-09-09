import React, { useState } from 'react';
import {
  Server,
  Skull,
  ShieldAlert,
  AlertTriangle,
  ArrowRight,
  ShieldCheck,
  ShieldOff,
  Lock,
  Zap,
  HelpCircle,
  HardDrive,
  RefreshCw,
  ExternalLink,
  Layers,
  Radio,
  Clock,
  Sparkles,
  CheckCircle2,
  SlidersHorizontal,
  ChevronRight,
  Activity,
  Upload,
  GitFork
} from 'lucide-react';
import {
  NetworkHost,
  NetworkEdge,
  PredictedTargetNode,
  CaptureMetadata,
  AppTheme
} from '../types';
import { TopologyGraph } from './TopologyGraph';
import { CaptureUtilityBar } from './CaptureUtilityBar';
import { playCyberTone } from '../utils/audio';

interface MainThreatTopologyViewProps {
  hosts: NetworkHost[];
  edges: NetworkEdge[];
  attackedNodes: NetworkHost[];
  predictedNextTarget: PredictedTargetNode | null;
  selectedHostId: string;
  onSelectHost: (id: string) => void;
  selectedEdgeId: string;
  onSelectEdge: (edge: NetworkEdge) => void;
  isolatedHostIds: string[];
  blockedPorts: { [hostId: string]: number[] };
  onToggleIsolate: (hostId: string) => void;
  onQuickMitigate: (targetId: string, port?: number) => void;
  onRefreshData: () => void;
  isRefreshing: boolean;
  soundEnabled: boolean;
  onNavigateToWhatIf: (targetHostId?: string) => void;
  activeCapture?: CaptureMetadata | null;
  onOpenUploadModal?: () => void;
  theme?: AppTheme;
}

type ViewMode = 'map' | 'target' | 'attacked' | 'guide' | 'split';

export const MainThreatTopologyView: React.FC<MainThreatTopologyViewProps> = ({
  hosts,
  edges,
  attackedNodes,
  predictedNextTarget,
  selectedHostId,
  onSelectHost,
  selectedEdgeId,
  onSelectEdge,
  isolatedHostIds,
  blockedPorts,
  onToggleIsolate,
  onQuickMitigate,
  onRefreshData,
  isRefreshing,
  soundEnabled,
  onNavigateToWhatIf,
  activeCapture = null,
  onOpenUploadModal,
  theme = 'light'
}) => {
  const [activeTab, setActiveTab] = useState<ViewMode>('map');

  const isLight = theme === 'light';
  const isMidnight = theme === 'midnight';

  const selectedHost = hosts.find((h) => h.id === selectedHostId) || hosts[0];

  // Dynamically resolve attacker node and target node from active network state
  const compromisedNodes = hosts.filter((h) => h.status === 'compromised');
  const targetedNodes = hosts.filter((h) => h.status === 'targeted');

  const attackerNode =
    attackedNodes[0] ||
    compromisedNodes[0] ||
    hosts.find((h) => h.segment === 'dmz') ||
    hosts[0];

  const targetNode =
    (predictedNextTarget ? hosts.find((h) => h.id === predictedNextTarget.hostId) : null) ||
    targetedNodes[0] ||
    hosts.find((h) => h.segment === 'corporate') ||
    hosts[1] ||
    hosts[0];

  const attackerName = attackerNode?.name || predictedNextTarget?.primarySourceName || 'External Ingress';
  const attackerRole = attackerNode?.role || 'Compromised Ingress Host';
  const attackerId = attackerNode?.id || 'node-src';
  const isAttackerIsolated = isolatedHostIds.includes(attackerId);

  const targetName = predictedNextTarget?.name || targetNode?.name || 'Primary Server';
  const targetRole = predictedNextTarget?.role || targetNode?.role || 'Domain Controller / Database';
  const targetIp = predictedNextTarget?.ip || targetNode?.ip || '';
  const targetId = predictedNextTarget?.hostId || targetNode?.id || '';
  const targetProb = Math.round(predictedNextTarget?.probabilityPercent ?? (targetNode?.attentionScore ? targetNode.attentionScore * 100 : 90));
  const targetPort = predictedNextTarget?.incomingPort || targetNode?.openPorts?.[0] || 445;
  const isTargetPortBlocked = (blockedPorts[targetId] || []).includes(targetPort);
  const timeToAttack = predictedNextTarget?.timeToAttackLabel || '+18.0s';
  const targetProtocol = predictedNextTarget?.protocol || 'Network Service';

  return (
    <div className="space-y-6">
      {/* 1. TOP UTILITY BAR: Capture info + sync (Consistent across all pages) */}
      <CaptureUtilityBar
        activeCapture={activeCapture}
        onOpenUploadModal={onOpenUploadModal}
        onRefreshData={onRefreshData}
        isRefreshing={isRefreshing}
        soundEnabled={soundEnabled}
        theme={theme}
      />

      {/* 2. CURRENT SITUATION IN PLAIN ENGLISH (Spacious Hero Story Card) */}
      <div className={`rounded-2xl border p-6 sm:p-7 shadow-xl relative overflow-hidden transition-all ${
        isLight
          ? 'border-rose-200 bg-gradient-to-r from-rose-50/80 via-white to-indigo-50/60 text-slate-900'
          : isMidnight
          ? 'border-rose-900/60 bg-gradient-to-r from-[#170c18] via-[#0d142b] to-[#071329] text-white shadow-2xl'
          : 'border-indigo-900/50 bg-gradient-to-r from-[#2a1738] via-[#1a2347] to-[#121c38] text-white shadow-2xl'
      }`}>
        {/* Background ambient glow */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-rose-500/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />

        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          {/* Left: Plain English Story */}
          <div className="space-y-4 max-w-3xl">
            <div className="flex items-center space-x-3">
              <span className={`flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-bold font-mono tracking-wide border ${
                isLight
                  ? 'bg-rose-100 border-rose-300 text-rose-800'
                  : 'bg-rose-950/80 border-rose-500/50 text-rose-300'
              }`}>
                <Radio className="w-3.5 h-3.5 text-rose-500 animate-pulse" />
                <span>CYBER INCIDENT IN PROGRESS</span>
              </span>
              <span className={`text-xs font-mono ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                Predicted attack in <strong className={isLight ? 'text-amber-700 font-bold' : 'text-amber-300 font-bold'}>{timeToAttack}</strong>
              </span>
            </div>

            <h2 className={`text-xl sm:text-2xl font-bold font-sans tracking-tight leading-snug ${
              isLight ? 'text-slate-900' : 'text-white'
            }`}>
              An attacker has infiltrated <span className="text-rose-500 underline decoration-rose-500/50">{attackerName}</span> and is attempting to breach <span className={isLight ? 'text-amber-700 underline decoration-amber-500/50' : 'text-amber-300 underline decoration-amber-500/50'}>{targetName} {targetIp ? `(${targetIp})` : ''}</span>.
            </h2>

            {/* 3 Plain English Steps */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1 text-xs">
              <div className={`p-3 rounded-xl border space-y-1 ${
                isLight ? 'bg-rose-50/70 border-rose-200' : 'bg-rose-950/30 border-rose-900/40'
              }`}>
                <div className={`flex items-center space-x-1.5 font-bold ${isLight ? 'text-rose-800' : 'text-rose-300'}`}>
                  <span className="w-2 h-2 rounded-full bg-rose-500" />
                  <span>1. Where They Entered</span>
                </div>
                <p className={isLight ? 'text-slate-700 leading-relaxed font-sans' : 'text-slate-300 leading-relaxed font-sans'}>
                  <strong>{attackerName} ({attackerRole})</strong> was compromised from the network perimeter.
                </p>
              </div>

              <div className={`p-3 rounded-xl border space-y-1 ${
                isLight ? 'bg-amber-50/70 border-amber-200' : 'bg-amber-950/30 border-amber-900/40'
              }`}>
                <div className={`flex items-center space-x-1.5 font-bold ${isLight ? 'text-amber-800' : 'text-amber-300'}`}>
                  <span className="w-2 h-2 rounded-full bg-amber-500 animate-ping" />
                  <span>2. Who Is in Danger</span>
                </div>
                <p className={isLight ? 'text-slate-700 leading-relaxed font-sans' : 'text-slate-300 leading-relaxed font-sans'}>
                  <strong>{targetName} ({targetRole})</strong> has a <strong className="text-rose-500 font-mono">{targetProb}%</strong> chance of being taken over.
                </p>
              </div>

              <div className={`p-3 rounded-xl border space-y-1 ${
                isLight ? 'bg-emerald-50/70 border-emerald-200' : 'bg-emerald-950/30 border-emerald-900/40'
              }`}>
                <div className={`flex items-center space-x-1.5 font-bold ${isLight ? 'text-emerald-800' : 'text-emerald-300'}`}>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                  <span>3. Recommended Action</span>
                </div>
                <p className={isLight ? 'text-slate-700 leading-relaxed font-sans' : 'text-slate-300 leading-relaxed font-sans'}>
                  Click <strong>Quarantine</strong> below to cut off the attacker's trajectory.
                </p>
              </div>
            </div>
          </div>

          {/* Right: Big, Friendly Action Buttons */}
          <div className="flex flex-col sm:flex-row lg:flex-col gap-3 min-w-[280px]">
            <button
              onClick={() => {
                if (soundEnabled) playCyberTone('policy');
                onToggleIsolate(attackerId);
              }}
              className={`flex items-start space-x-3 p-3.5 rounded-xl border transition-all text-left ${
                isAttackerIsolated
                  ? isLight
                    ? 'border-emerald-300 bg-emerald-50 text-emerald-900 hover:bg-emerald-100'
                    : 'border-emerald-500/50 bg-emerald-950/40 text-emerald-100 hover:bg-emerald-900/50'
                  : 'border-rose-500/60 bg-rose-600 hover:bg-rose-700 text-white shadow-lg'
              }`}
            >
              <div className="p-2 rounded-lg bg-black/20 mt-0.5">
                {isAttackerIsolated ? (
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                ) : (
                  <ShieldOff className="w-5 h-5 text-white" />
                )}
              </div>
              <div>
                <div className="font-bold text-sm font-sans">
                  {isAttackerIsolated ? `${attackerName} is Quarantined ✓` : `Quarantine ${attackerName}`}
                </div>
                <p className={`text-[11px] mt-0.5 leading-tight ${isAttackerIsolated ? (isLight ? 'text-emerald-700' : 'text-emerald-300') : 'text-rose-100'}`}>
                  {isAttackerIsolated
                    ? 'Infected machine unplugged. Attack cannot spread.'
                    : `Unplugs ${attackerName} so virus cannot jump.`}
                </p>
              </div>
            </button>

            {targetId && (
              <button
                onClick={() => {
                  if (soundEnabled) playCyberTone('policy');
                  onQuickMitigate(targetId, targetPort);
                }}
                className={`flex items-start space-x-3 p-3.5 rounded-xl border transition-all text-left ${
                  isTargetPortBlocked
                    ? isLight
                      ? 'border-emerald-300 bg-emerald-50 text-emerald-900'
                      : 'border-emerald-500/50 bg-emerald-950/40 text-emerald-100'
                    : isLight
                    ? 'border-amber-400 bg-amber-500 hover:bg-amber-600 text-white shadow-md'
                    : 'border-amber-500/60 bg-amber-600 hover:bg-amber-700 text-white shadow-md'
                }`}
              >
                <div className="p-2 rounded-lg bg-black/20 mt-0.5">
                  <Lock className="w-5 h-5 text-white" />
                </div>
                <div>
                  <div className="font-bold text-sm font-sans">
                    {isTargetPortBlocked ? `Port ${targetPort} is Locked ✓` : `Lock Port ${targetPort} on ${targetName}`}
                  </div>
                  <p className={`text-[11px] mt-0.5 leading-tight ${isTargetPortBlocked ? (isLight ? 'text-emerald-700' : 'text-emerald-300') : 'text-amber-100'}`}>
                    {isTargetPortBlocked
                      ? 'Access port locked. Infiltration path severed.'
                      : `Blocks incoming ${targetProtocol} traffic on port ${targetPort}.`}
                  </p>
                </div>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* 3. SPACIOUS VIEW NAVIGATION TABS */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b pb-4 ${
        isLight ? 'border-slate-200' : isMidnight ? 'border-[#142d54]' : 'border-slate-700/60'
      }`}>
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => {
              if (soundEnabled) playCyberTone('click');
              setActiveTab('map');
            }}
            className={`flex items-center space-x-2 px-4 py-2.5 rounded-xl font-sans text-xs font-bold transition-all ${
              activeTab === 'map'
                ? isLight
                  ? 'bg-cyan-100 border border-cyan-400 text-cyan-900 shadow-xs'
                  : 'bg-cyan-500/20 border border-cyan-400 text-cyan-200 shadow-[0_0_12px_rgba(6,182,212,0.25)]'
                : isLight
                ? 'border border-slate-200 bg-white text-slate-700 hover:text-slate-900 hover:bg-slate-100'
                : 'border border-slate-700 bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700'
            }`}
          >
            <Server className="w-4 h-4 text-cyan-500" />
            <span>🗺️ Interactive Network Map</span>
          </button>

          <button
            onClick={() => {
              if (soundEnabled) playCyberTone('click');
              setActiveTab('target');
            }}
            className={`flex items-center space-x-2 px-4 py-2.5 rounded-xl font-sans text-xs font-bold transition-all ${
              activeTab === 'target'
                ? isLight
                  ? 'bg-amber-100 border border-amber-400 text-amber-900 shadow-xs'
                  : 'bg-amber-500/20 border border-amber-400 text-amber-200 shadow-[0_0_12px_rgba(245,158,11,0.25)]'
                : isLight
                ? 'border border-slate-200 bg-white text-slate-700 hover:text-slate-900 hover:bg-slate-100'
                : 'border border-slate-700 bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700'
            }`}
          >
            <AlertTriangle className="w-4 h-4 text-amber-500" />
            <span>🎯 Next Target in Danger ({targetName} · {targetProb}%)</span>
          </button>

          <button
            onClick={() => {
              if (soundEnabled) playCyberTone('click');
              setActiveTab('attacked');
            }}
            className={`flex items-center space-x-2 px-4 py-2.5 rounded-xl font-sans text-xs font-bold transition-all ${
              activeTab === 'attacked'
                ? isLight
                  ? 'bg-rose-100 border border-rose-400 text-rose-900 shadow-xs'
                  : 'bg-rose-500/20 border border-rose-400 text-rose-200 shadow-[0_0_12px_rgba(244,63,94,0.25)]'
                : isLight
                ? 'border border-slate-200 bg-white text-slate-700 hover:text-slate-900 hover:bg-slate-100'
                : 'border border-slate-700 bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700'
            }`}
          >
            <Skull className="w-4 h-4 text-rose-500" />
            <span>🛑 Infected Computers ({attackedNodes.length})</span>
          </button>

          <button
            onClick={() => {
              if (soundEnabled) playCyberTone('click');
              setActiveTab('guide');
            }}
            className={`flex items-center space-x-2 px-4 py-2.5 rounded-xl font-sans text-xs font-bold transition-all ${
              activeTab === 'guide'
                ? isLight
                  ? 'bg-blue-100 border border-blue-400 text-blue-900 shadow-xs'
                  : 'bg-blue-500/20 border border-blue-400 text-blue-200 shadow-[0_0_12px_rgba(59,130,246,0.25)]'
                : isLight
                ? 'border border-slate-200 bg-white text-slate-700 hover:text-slate-900 hover:bg-slate-100'
                : 'border border-slate-700 bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700'
            }`}
          >
            <HelpCircle className="w-4 h-4 text-blue-500" />
            <span>💡 Plain English Guide</span>
          </button>
        </div>

        {/* Optional Side-by-Side toggle */}
        <button
          onClick={() => {
            if (soundEnabled) playCyberTone('click');
            setActiveTab((prev) => (prev === 'split' ? 'map' : 'split'));
          }}
          className={`flex items-center space-x-1.5 px-3 py-2 rounded-xl text-xs font-sans transition-colors ${
            activeTab === 'split'
              ? isLight
                ? 'bg-purple-100 border border-purple-400 text-purple-900'
                : 'bg-purple-950/60 border border-purple-400 text-purple-200'
              : isLight
              ? 'border border-slate-200 bg-white text-slate-600 hover:text-slate-900'
              : 'border border-slate-700 bg-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-purple-500" />
          <span>{activeTab === 'split' ? 'Standard Spacious View' : 'Side-by-Side View'}</span>
        </button>
      </div>

      {/* 4. TAB 1: SPACIOUS INTERACTIVE NETWORK MAP */}
      {(activeTab === 'map' || activeTab === 'split') && (
        <div className={`space-y-4 ${activeTab === 'split' ? 'lg:grid lg:grid-cols-12 lg:gap-6 lg:space-y-0' : ''}`}>
          <div className={activeTab === 'split' ? 'lg:col-span-7' : 'w-full'}>
            <div className={`rounded-2xl border p-5 sm:p-6 backdrop-blur-md shadow-xl space-y-4 transition-colors ${
              isLight
                ? 'bg-white border-slate-200 text-slate-800'
                : isMidnight
                ? 'bg-[#061126]/90 border-[#142d54] text-slate-100'
                : 'bg-slate-800/90 border-slate-700/80 text-slate-100'
            }`}>
              <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b pb-4 ${
                isLight ? 'border-slate-200' : isMidnight ? 'border-[#12284c]' : 'border-slate-700/60'
              }`}>
                <div>
                  <h3 className={`text-lg font-bold font-sans flex items-center space-x-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
                    <span>Company Computer Network Map</span>
                  </h3>
                  <p className={`text-xs font-sans mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                    Click any computer to inspect its details and disconnect it if compromised.
                  </p>
                </div>

                {/* Friendly Plain English Map Legend */}
                <div className="flex flex-wrap items-center gap-3 text-xs font-sans">
                  <span className={`flex items-center space-x-1.5 ${isLight ? 'text-rose-700' : 'text-rose-300'}`}>
                    <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse" />
                    <span>🔴 Infected</span>
                  </span>
                  <span className={`flex items-center space-x-1.5 ${isLight ? 'text-amber-700' : 'text-amber-300'}`}>
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
                    <span>⚠️ In Danger (94%)</span>
                  </span>
                  <span className={`flex items-center space-x-1.5 ${isLight ? 'text-emerald-700' : 'text-emerald-300'}`}>
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
                    <span>🟢 Safe</span>
                  </span>
                  <span className="flex items-center space-x-1.5 text-slate-400">
                    <span className="w-2.5 h-2.5 rounded-full bg-slate-500" />
                    <span>🛡️ Unplugged</span>
                  </span>
                </div>
              </div>

              {/* Spacious SVG Topology Canvas */}
              <TopologyGraph
                hosts={hosts}
                edges={edges}
                selectedHostId={selectedHostId}
                onSelectHost={onSelectHost}
                selectedEdgeId={selectedEdgeId}
                onSelectEdge={onSelectEdge}
                isolatedHostIds={isolatedHostIds}
                blockedPorts={blockedPorts}
                onIsolateToggle={onToggleIsolate}
                soundEnabled={soundEnabled}
                theme={theme}
              />

              {/* Interactive Node Switcher Strip */}
              <div className={`mt-3 pt-3 border-t flex flex-wrap items-center gap-2 ${
                isLight ? 'border-slate-200' : 'border-slate-700/60'
              }`}>
                <span className="text-[11px] font-mono text-slate-400 uppercase font-bold mr-1">
                  Inspect Any Node ({hosts.length}):
                </span>
                {hosts.map((h) => {
                  const isSel = h.id === selectedHost.id;
                  const isComp = h.status === 'compromised';
                  const isTgt = h.status === 'targeted';
                  const isIso = isolatedHostIds.includes(h.id);
                  return (
                    <button
                      key={h.id}
                      onClick={() => {
                        if (soundEnabled) playCyberTone('click');
                        onSelectHost(h.id);
                      }}
                      className={`px-3 py-1.5 rounded-xl text-xs font-mono font-bold transition-all flex items-center space-x-1.5 ${
                        isSel
                          ? isLight
                            ? 'bg-cyan-600 text-white shadow-md ring-2 ring-cyan-400'
                            : 'bg-cyan-500 text-slate-950 font-black shadow-[0_0_15px_rgba(6,182,212,0.4)] ring-2 ring-cyan-300'
                          : isLight
                          ? 'bg-slate-100 text-slate-700 hover:bg-slate-200 border border-slate-200'
                          : 'bg-slate-900 text-slate-300 hover:bg-slate-800 border border-slate-700'
                      }`}
                    >
                      <span className={`w-2 h-2 rounded-full ${
                        isIso ? 'bg-slate-400' : isComp ? 'bg-rose-500 animate-pulse' : isTgt ? 'bg-amber-400' : 'bg-emerald-400'
                      }`} />
                      <span>{h.name}</span>
                      <span className="text-[10px] opacity-70">({h.ip})</span>
                    </button>
                  );
                })}
              </div>

              {/* Comprehensive Selected Host Properties & Control Panel */}
              {selectedHost && (() => {
                const isIso = isolatedHostIds.includes(selectedHost.id);
                const isComp = selectedHost.status === 'compromised';
                const isTgt = selectedHost.status === 'targeted';
                const nodeRisk = Math.round((selectedHost.attentionScore || (isTgt ? 0.90 : isComp ? 0.92 : 0.35)) * 100);
                const inboundFlows = edges.filter((e) => e.target === selectedHost.id);
                const outboundFlows = edges.filter((e) => e.source === selectedHost.id);

                return (
                  <div className={`mt-3 p-5 rounded-2xl border transition-all space-y-4 shadow-lg ${
                    isIso
                      ? isLight
                        ? 'bg-slate-100 border-slate-300 text-slate-800'
                        : 'bg-slate-900/90 border-slate-700 text-slate-200'
                      : isComp
                      ? isLight
                        ? 'bg-rose-50/90 border-rose-300 text-rose-950'
                        : 'bg-rose-950/30 border-rose-900/60 text-rose-100'
                      : isTgt
                      ? isLight
                        ? 'bg-amber-50/90 border-amber-300 text-amber-950'
                        : 'bg-amber-950/30 border-amber-900/60 text-amber-100'
                      : isLight
                      ? 'bg-slate-50 border-slate-200 text-slate-800'
                      : isMidnight
                      ? 'bg-[#071329] border-[#17386c] text-slate-100'
                      : 'bg-slate-900/60 border-slate-700/60 text-slate-100'
                  }`}>
                    {/* Header: Name, IP, Role, Security Badge */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b pb-3 border-slate-200/60 dark:border-slate-700/60">
                      <div className="flex items-center space-x-3">
                        <div className={`p-2.5 rounded-xl border ${
                          isComp
                            ? 'bg-rose-500/20 border-rose-500/40 text-rose-500'
                            : isTgt
                            ? 'bg-amber-500/20 border-amber-500/40 text-amber-500'
                            : 'bg-cyan-500/20 border-cyan-500/40 text-cyan-500'
                        }`}>
                          <Server className="w-5 h-5" />
                        </div>
                        <div>
                          <div className="flex items-center space-x-2">
                            <h4 className="text-base font-bold font-mono tracking-tight">
                              {selectedHost.name}
                            </h4>
                            <span className="text-xs font-mono text-cyan-600 dark:text-cyan-400 font-bold">
                              {selectedHost.ip}
                            </span>
                            <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300">
                              {selectedHost.segment.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                            {selectedHost.role} · OS: <strong className="text-slate-700 dark:text-slate-200">{selectedHost.os}</strong>
                          </p>
                        </div>
                      </div>

                      {/* Security Status Tag */}
                      <span className={`px-3 py-1.5 rounded-xl text-xs font-mono font-bold border shrink-0 ${
                        isIso
                          ? 'bg-slate-700 text-slate-200 border-slate-600'
                          : isComp
                          ? 'bg-rose-500/20 text-rose-600 dark:text-rose-300 border-rose-500/50 animate-pulse'
                          : isTgt
                          ? 'bg-amber-500/20 text-amber-600 dark:text-amber-300 border-amber-500/50'
                          : 'bg-emerald-500/20 text-emerald-600 dark:text-emerald-300 border-emerald-500/50'
                      }`}>
                        {isIso
                          ? '🛡️ QUARANTINED (ISOLATED)'
                          : isComp
                          ? '🔴 INFECTED (ACTIVE ATTACKER)'
                          : isTgt
                          ? `⚠️ IN IMMEDIATE DANGER (${nodeRisk}%)`
                          : '🟢 HEALTHY BASELINE'}
                      </span>
                    </div>

                    {/* Properties Grid: Ports, Attention, Inbound/Outbound */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-sans">
                      {/* 1. GNN Attention Score */}
                      <div className={`p-3 rounded-xl border ${
                        isLight ? 'bg-white/80 border-slate-200' : 'bg-slate-800/60 border-slate-700/60'
                      }`}>
                        <div className="text-[10px] font-mono uppercase text-slate-400 font-bold mb-1">
                          GNN Attention / Risk
                        </div>
                        <div className="flex items-center justify-between">
                          <span className={`text-base font-bold font-mono ${
                            nodeRisk > 70 ? 'text-rose-500' : nodeRisk > 40 ? 'text-amber-500' : 'text-emerald-500'
                          }`}>
                            {nodeRisk}%
                          </span>
                          <span className="text-[10px] text-slate-400 font-mono">Neural Pressure</span>
                        </div>
                        <div className="w-full bg-slate-200 dark:bg-slate-700 h-1.5 rounded-full mt-2 overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all duration-300 ${
                              nodeRisk > 70 ? 'bg-rose-500' : nodeRisk > 40 ? 'bg-amber-400' : 'bg-emerald-400'
                            }`}
                            style={{ width: `${nodeRisk}%` }}
                          />
                        </div>
                      </div>

                      {/* 2. Open Ports */}
                      <div className={`p-3 rounded-xl border ${
                        isLight ? 'bg-white/80 border-slate-200' : 'bg-slate-800/60 border-slate-700/60'
                      }`}>
                        <div className="text-[10px] font-mono uppercase text-slate-400 font-bold mb-1">
                          Open Services / Ports ({selectedHost.openPorts.length})
                        </div>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {selectedHost.openPorts.map((p) => (
                            <span
                              key={p}
                              className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-50 dark:bg-cyan-950/60 text-cyan-700 dark:text-cyan-300 border border-cyan-200 dark:border-cyan-800"
                            >
                              Port {p}
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* 3. Inbound Traffic Flows */}
                      <div className={`p-3 rounded-xl border ${
                        isLight ? 'bg-white/80 border-slate-200' : 'bg-slate-800/60 border-slate-700/60'
                      }`}>
                        <div className="text-[10px] font-mono uppercase text-slate-400 font-bold mb-1">
                          Inbound Flows ({inboundFlows.length})
                        </div>
                        {inboundFlows.length > 0 ? (
                          <div className="space-y-1 mt-1 max-h-16 overflow-y-auto">
                            {inboundFlows.map((e) => {
                              const src = hosts.find((h) => h.id === e.source);
                              return (
                                <div key={e.id} className="text-[11px] font-mono text-slate-600 dark:text-slate-300 flex items-center justify-between">
                                  <span>{src?.name || e.source}</span>
                                  <span className="text-cyan-600 dark:text-cyan-400">{e.protocol}</span>
                                </div>
                              );
                            })}
                          </div>
                        ) : (
                          <span className="text-[11px] text-slate-400 italic">No incoming links</span>
                        )}
                      </div>

                      {/* 4. Outbound Traffic Flows */}
                      <div className={`p-3 rounded-xl border ${
                        isLight ? 'bg-white/80 border-slate-200' : 'bg-slate-800/60 border-slate-700/60'
                      }`}>
                        <div className="text-[10px] font-mono uppercase text-slate-400 font-bold mb-1">
                          Outbound Flows ({outboundFlows.length})
                        </div>
                        {outboundFlows.length > 0 ? (
                          <div className="space-y-1 mt-1 max-h-16 overflow-y-auto">
                            {outboundFlows.map((e) => {
                              const dst = hosts.find((h) => h.id === e.target);
                              return (
                                <div key={e.id} className="text-[11px] font-mono text-slate-600 dark:text-slate-300 flex items-center justify-between">
                                  <span>➔ {dst?.name || e.target}</span>
                                  <span className="text-cyan-600 dark:text-cyan-400">{e.protocol}</span>
                                </div>
                              );
                            })}
                          </div>
                        ) : (
                          <span className="text-[11px] text-slate-400 italic">No outgoing links</span>
                        )}
                      </div>
                    </div>

                    {/* Action Controls for This Specific Node */}
                    <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                      <div className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                        Active Node Selected: <strong className="text-cyan-500">{selectedHost.name}</strong> ({selectedHost.ip})
                      </div>

                      <div className="flex items-center space-x-2.5">
                        <button
                          onClick={() => {
                            if (soundEnabled) playCyberTone('click');
                            onNavigateToWhatIf(selectedHost.id);
                          }}
                          className={`px-3.5 py-2 rounded-xl text-xs font-bold font-sans transition-all flex items-center space-x-1.5 ${
                            isLight
                              ? 'border border-cyan-300 bg-cyan-50 text-cyan-800 hover:bg-cyan-100'
                              : 'border border-cyan-500/40 bg-cyan-950/40 text-cyan-300 hover:bg-cyan-900/60'
                          }`}
                        >
                          <GitFork className="w-3.5 h-3.5 text-cyan-500" />
                          <span>Simulate Defense on {selectedHost.name}</span>
                        </button>

                        <button
                          onClick={() => {
                            if (soundEnabled) playCyberTone('click');
                            onToggleIsolate(selectedHost.id);
                          }}
                          className={`px-4 py-2 rounded-xl text-xs font-bold font-sans transition-all flex items-center space-x-2 ${
                            isIso
                              ? isLight
                                ? 'border border-emerald-400 bg-emerald-50 text-emerald-700 hover:bg-emerald-100'
                                : 'border border-emerald-500/40 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/50'
                              : 'border border-rose-500 bg-rose-600 hover:bg-rose-700 text-white shadow-md'
                          }`}
                        >
                          {isIso ? (
                            <>
                              <ShieldCheck className="w-4 h-4 text-emerald-500" />
                              <span>Plug Back In</span>
                            </>
                          ) : (
                            <>
                              <ShieldOff className="w-4 h-4 text-white" />
                              <span>Quarantine {selectedHost.name}</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>

          {/* If Split View is active, show the Target card on the right */}
          {activeTab === 'split' && predictedNextTarget && (
            <div className="lg:col-span-5">
              <TargetDetailSection
                predictedNextTarget={predictedNextTarget}
                isTargetPortBlocked={isTargetPortBlocked}
                onQuickMitigate={onQuickMitigate}
                onNavigateToWhatIf={onNavigateToWhatIf}
                soundEnabled={soundEnabled}
                theme={theme}
              />
            </div>
          )}
        </div>
      )}

      {/* 5. TAB 2: STANDALONE PROBABLE TARGET IN DANGER */}
      {activeTab === 'target' && predictedNextTarget && (
        <div className="max-w-4xl mx-auto">
          <TargetDetailSection
            predictedNextTarget={predictedNextTarget}
            isTargetPortBlocked={isTargetPortBlocked}
            onQuickMitigate={onQuickMitigate}
            onNavigateToWhatIf={onNavigateToWhatIf}
            soundEnabled={soundEnabled}
            isSpacious
            theme={theme}
          />
        </div>
      )}

      {/* 6. TAB 3: STANDALONE INFECTED COMPUTERS LIST */}
      {activeTab === 'attacked' && (
        <div className={`max-w-4xl mx-auto rounded-2xl border p-6 sm:p-7 backdrop-blur-md shadow-xl space-y-6 transition-colors ${
          isLight
            ? 'bg-white border-slate-200 text-slate-800'
            : isMidnight
            ? 'bg-[#071329]/95 border-[#173b75] text-slate-100'
            : 'bg-slate-800/90 border-slate-700/80 text-slate-100'
        }`}>
          <div className={`border-b pb-4 ${isLight ? 'border-slate-200' : 'border-slate-700'}`}>
            <div className="flex items-center space-x-2.5">
              <Skull className="w-6 h-6 text-rose-500 animate-pulse" />
              <div>
                <h3 className={`text-xl font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  Infected Computers Currently Under Attack ({attackedNodes.length})
                </h3>
                <p className={`text-xs font-sans mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                  These devices have already been breached by the hacker and are actively being used to attack other computers.
                </p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {attackedNodes.map((node) => {
              const isIsolated = isolatedHostIds.includes(node.id);
              return (
                <div
                  key={node.id}
                  className={`p-5 rounded-xl border transition-all space-y-4 ${
                    isIsolated
                      ? isLight
                        ? 'border-slate-300 bg-slate-50'
                        : 'border-slate-700 bg-slate-900/50'
                      : isLight
                      ? 'border-rose-300 bg-rose-50/70 shadow-sm'
                      : 'border-rose-900/50 bg-rose-950/20'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className={`text-lg font-bold font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
                          {node.name}
                        </span>
                        <span className="text-xs font-mono text-slate-400">
                          ({node.ip})
                        </span>
                      </div>
                      <div className={`text-xs font-sans mt-0.5 ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
                        {node.role}
                      </div>
                    </div>

                    <span className={`px-2.5 py-1 rounded text-[11px] font-bold font-mono border ${
                      isIsolated
                        ? 'bg-slate-700 text-slate-200 border-slate-600'
                        : 'bg-rose-500 text-white border-rose-600'
                    }`}>
                      {isIsolated ? '🛡️ QUARANTINED' : '🔴 INFECTED'}
                    </span>
                  </div>

                  <div className={`p-3 rounded-lg border text-xs font-sans ${
                    isLight ? 'bg-white border-slate-200 text-slate-700' : 'bg-slate-900/60 border-slate-700/60 text-slate-300'
                  }`}>
                    <div className="font-bold text-slate-400 uppercase text-[10px] mb-1">
                      What happened to this machine:
                    </div>
                    {node.role?.includes('External') || node.segment === 'dmz'
                      ? `External actor / ingress endpoint (${node.ip}) compromised via perimeter vulnerability or open ports (${node.openPorts.slice(0, 3).join(', ')}).`
                      : `Internal enterprise host (${node.name} - ${node.ip}) compromised. Inbound anomalous traversal detected with anomaly attention score ${Math.round(node.attentionScore * 100)}%.`}
                  </div>

                  <button
                    onClick={() => {
                      if (soundEnabled) playCyberTone('click');
                      onToggleIsolate(node.id);
                    }}
                    className={`w-full py-2.5 px-4 rounded-xl text-xs font-bold font-sans transition-all flex items-center justify-center space-x-2 ${
                      isIsolated
                        ? isLight
                          ? 'border border-emerald-300 bg-emerald-50 text-emerald-700 hover:bg-emerald-100'
                          : 'border border-emerald-500/40 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/50'
                        : 'border border-rose-500 bg-rose-600 hover:bg-rose-700 text-white shadow-md'
                    }`}
                  >
                    {isIsolated ? (
                      <>
                        <ShieldCheck className="w-4 h-4 text-emerald-500" />
                        <span>Plug Back Into Network</span>
                      </>
                    ) : (
                      <>
                        <ShieldOff className="w-4 h-4 text-white" />
                        <span>Unplug From Network (Isolate Immediately)</span>
                      </>
                    )}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 7. TAB 4: PLAIN-ENGLISH BEGINNER'S GUIDE */}
      {activeTab === 'guide' && (
        <div className={`max-w-4xl mx-auto rounded-2xl border p-7 backdrop-blur-md shadow-xl space-y-6 transition-colors ${
          isLight
            ? 'bg-white border-slate-200 text-slate-800'
            : isMidnight
            ? 'bg-[#071329]/95 border-[#173b75] text-slate-100'
            : 'bg-slate-800/90 border-slate-700/80 text-slate-100'
        }`}>
          <div className={`border-b pb-4 ${isLight ? 'border-slate-200' : 'border-slate-700'}`}>
            <h3 className={`text-xl font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
              💡 How Network Attacks Work (Plain English Guide)
            </h3>
            <p className={`text-sm font-sans mt-1 ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
              You do not need to be a cybersecurity expert to understand what is happening on this screen. Here is what is taking place:
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            <div className={`p-5 rounded-xl border space-y-2.5 ${
              isLight ? 'bg-rose-50/70 border-rose-200' : 'bg-rose-950/20 border-rose-900/50'
            }`}>
              <div className="w-10 h-10 rounded-lg bg-rose-500/20 text-rose-500 flex items-center justify-center font-bold text-lg">
                1
              </div>
              <h4 className={`font-bold text-base font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>The Break-In</h4>
              <p className={`text-xs leading-relaxed font-sans ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
                A hacker gains initial foothold on <strong>{attackerName}</strong> ({attackerRole}). That computer is marked with a 🔴 <strong>Infected</strong> badge.
              </p>
            </div>

            <div className={`p-5 rounded-xl border space-y-2.5 ${
              isLight ? 'bg-amber-50/70 border-amber-200' : 'bg-amber-950/20 border-amber-900/50'
            }`}>
              <div className="w-10 h-10 rounded-lg bg-amber-500/20 text-amber-500 flex items-center justify-center font-bold text-lg">
                2
              </div>
              <h4 className={`font-bold text-base font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>The Jump (Lateral Movement)</h4>
              <p className={`text-xs leading-relaxed font-sans ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
                Hackers do not stop at one computer. They probe internal paths to jump to high-value infrastructure (<strong>{targetName}</strong> - {targetRole}).
              </p>
            </div>

            <div className={`p-5 rounded-xl border space-y-2.5 ${
              isLight ? 'bg-emerald-50/70 border-emerald-200' : 'bg-emerald-950/20 border-emerald-900/50'
            }`}>
              <div className="w-10 h-10 rounded-lg bg-emerald-500/20 text-emerald-500 flex items-center justify-center font-bold text-lg">
                3
              </div>
              <h4 className={`font-bold text-base font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>Stopping It in Time</h4>
              <p className={`text-xs leading-relaxed font-sans ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
                Clicking <strong>Quarantine</strong> instantly cuts the digital connection, isolating {attackerName} before {targetName} is breached.
              </p>
            </div>
          </div>

          <div className={`p-4 rounded-xl border ${
            isLight ? 'bg-slate-100 border-slate-200 text-slate-700' : 'bg-slate-900/80 border-slate-700/80 text-slate-200'
          }`}>
            <p className="text-xs leading-relaxed font-sans">
              <strong>Tip:</strong> The AI on this dashboard predicts the attacker's trajectory before the breach happens, giving you a proactive <strong>18-second head start</strong> to disconnect the hacker before damage occurs.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

// Extracted Sub-Component for Target Details so it can be rendered standalone or in split mode
interface TargetDetailProps {
  predictedNextTarget: PredictedTargetNode;
  isTargetPortBlocked?: boolean;
  onQuickMitigate: (hostId: string, port?: number) => void;
  onNavigateToWhatIf: () => void;
  soundEnabled: boolean;
  isSpacious?: boolean;
  theme?: AppTheme;
}

const TargetDetailSection: React.FC<TargetDetailProps> = ({
  predictedNextTarget,
  isTargetPortBlocked = false,
  onQuickMitigate,
  onNavigateToWhatIf,
  soundEnabled,
  isSpacious = false,
  theme = 'light'
}) => {
  const isLight = theme === 'light';
  const isMidnight = theme === 'midnight';

  return (
    <div className={`rounded-2xl border overflow-hidden shadow-xl transition-colors ${
      isLight
        ? 'border-amber-200 bg-white text-slate-800'
        : isMidnight
        ? 'border-amber-500/50 bg-gradient-to-b from-[#141829] to-[#0a1122] text-slate-100'
        : 'border-slate-700 bg-slate-800/90 text-slate-100'
    } ${isSpacious ? 'p-6 sm:p-8' : 'p-5'}`}>
      {/* Header */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-5 border-b ${
        isLight ? 'border-slate-200' : 'border-slate-700'
      }`}>
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-5 h-5 text-amber-500 animate-pulse" />
            <h3 className={`text-base sm:text-lg font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
              Target Computer in Immediate Danger
            </h3>
          </div>
          <p className={`text-xs font-sans ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
            The AI predicts this machine will be attacked next based on real-time network traffic patterns.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold flex items-center space-x-1.5 border ${
            isLight ? 'bg-amber-100 text-amber-800 border-amber-300' : 'bg-amber-950/80 border-amber-500/40 text-amber-300'
          }`}>
            <Zap className="w-3.5 h-3.5 text-amber-500" />
            <span>{predictedNextTarget.timeToAttackLabel} LEAD TIME</span>
          </span>
        </div>
      </div>

      <div className="py-6 space-y-6">
        {/* Computer Details + Big Danger Meter */}
        <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-6 p-5 rounded-xl border ${
          isLight ? 'bg-amber-50/50 border-amber-200' : 'bg-slate-900/60 border-slate-700/60'
        }`}>
          <div>
            <div className="flex items-center space-x-2">
              <span className={`text-xl sm:text-2xl font-bold font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
                {predictedNextTarget.name}
              </span>
              <span className="text-xs font-mono text-slate-400">
                ({predictedNextTarget.ip})
              </span>
            </div>
            <div className={`text-sm font-sans font-medium mt-1 ${isLight ? 'text-amber-800' : 'text-amber-300'}`}>
              {predictedNextTarget.role} (Manages all company accounts & permissions)
            </div>
            <div className="text-xs font-mono text-slate-400 mt-1">
              Operating System: {predictedNextTarget.os} · Network Area: {predictedNextTarget.segment.toUpperCase()}
            </div>
          </div>

          {/* Probability Display */}
          <div className="sm:text-right min-w-[140px]">
            <div className={`text-xs font-sans ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
              Chance of Breach
            </div>
            <div className="text-3xl sm:text-4xl font-extrabold font-mono text-rose-500">
              {predictedNextTarget.probabilityPercent.toFixed(1)}%
            </div>
            <span className="text-[11px] font-mono text-rose-500 font-bold uppercase">
              HIGH RISK (CRITICAL)
            </span>
          </div>
        </div>

        {/* Why the AI believes this machine is next */}
        <div className="space-y-3">
          <h4 className={`text-sm font-bold font-sans flex items-center space-x-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
            <Sparkles className="w-4 h-4 text-cyan-500" />
            <span>Why the AI Predicts This Machine is Next:</span>
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div className={`p-4 rounded-xl border space-y-1 ${
              isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/40 border-slate-700/60'
            }`}>
              <div className={`font-bold flex items-center space-x-1.5 ${isLight ? 'text-slate-800' : 'text-slate-200'}`}>
                <Activity className="w-3.5 h-3.5 text-cyan-500" />
                <span>Suspicious Traffic Detected</span>
              </div>
              <p className={isLight ? 'text-slate-600 leading-relaxed font-sans' : 'text-slate-300 leading-relaxed font-sans'}>
                Network spikes on <strong>Port {predictedNextTarget.incomingPort} ({predictedNextTarget.protocol || 'Protocol'})</strong> from infected machine {predictedNextTarget.primarySourceName || 'Infected Node'}.
              </p>
            </div>

            <div className={`p-4 rounded-xl border space-y-1 ${
              isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/40 border-slate-700/60'
            }`}>
              <div className={`font-bold flex items-center space-x-1.5 ${isLight ? 'text-slate-800' : 'text-slate-200'}`}>
                <Clock className="w-3.5 h-3.5 text-amber-500" />
                <span>Proactive Reaction Window</span>
              </div>
              <p className={isLight ? 'text-slate-600 leading-relaxed font-sans' : 'text-slate-300 leading-relaxed font-sans'}>
                You have approximately <strong>{predictedNextTarget.timeToAttackLabel || '15 seconds'}</strong> to take protective action before authentication tokens are compromised.
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className={`pt-4 border-t flex flex-col sm:flex-row items-center justify-between gap-4 ${
          isLight ? 'border-slate-200' : 'border-slate-700'
        }`}>
          <div className="space-y-0.5">
            <div className={`text-xs font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
              Recommended Mitigation:
            </div>
            <div className={`text-[11px] font-sans ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
              Lock incoming Port {predictedNextTarget.incomingPort} to reject unauthorized login attempts.
            </div>
          </div>

          <div className="flex items-center space-x-3 w-full sm:w-auto">
            <button
              onClick={() => {
                if (soundEnabled) playCyberTone('policy');
                onQuickMitigate(predictedNextTarget.hostId, predictedNextTarget.incomingPort);
              }}
              className={`flex-1 sm:flex-initial px-5 py-2.5 rounded-xl font-sans text-xs font-bold transition-all flex items-center justify-center space-x-2 ${
                isTargetPortBlocked
                  ? isLight
                    ? 'border border-emerald-300 bg-emerald-50 text-emerald-700'
                    : 'border border-emerald-500/40 bg-emerald-950/40 text-emerald-300'
                  : 'bg-amber-600 hover:bg-amber-700 text-white shadow-md'
              }`}
            >
              <Lock className="w-4 h-4" />
              <span>{isTargetPortBlocked ? `Port ${predictedNextTarget.incomingPort} Locked ✓` : `Lock Port ${predictedNextTarget.incomingPort}`}</span>
            </button>

            <button
              onClick={() => {
                if (soundEnabled) playCyberTone('click');
                onNavigateToWhatIf();
              }}
              className={`flex-1 sm:flex-initial px-4 py-2.5 rounded-xl font-sans text-xs font-medium border transition-colors flex items-center justify-center space-x-1.5 ${
                isLight
                  ? 'border-slate-300 bg-white hover:bg-slate-100 text-slate-700'
                  : 'border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white'
              }`}
            >
              <span>Test in Simulator</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

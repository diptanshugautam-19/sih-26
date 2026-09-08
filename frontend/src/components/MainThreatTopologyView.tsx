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
  Upload
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
  onNavigateToWhatIf: () => void;
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
  const isApp07Isolated = isolatedHostIds.includes('app-07');
  const isTargetPortBlocked = predictedNextTarget && (blockedPorts[predictedNextTarget.hostId] || []).includes(predictedNextTarget.incomingPort);

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
                Predicted attack in <strong className={isLight ? 'text-amber-700 font-bold' : 'text-amber-300 font-bold'}>18 seconds</strong>
              </span>
            </div>

            <h2 className={`text-xl sm:text-2xl font-bold font-sans tracking-tight leading-snug ${
              isLight ? 'text-slate-900' : 'text-white'
            }`}>
              An attacker has infiltrated <span className="text-rose-500 underline decoration-rose-500/50">APP-07</span> and is attempting to breach the <span className={isLight ? 'text-amber-700 underline decoration-amber-500/50' : 'text-amber-300 underline decoration-amber-500/50'}>Central Main Server</span>.
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
                  <strong>APP-07 (Web Server)</strong> was hacked from outside internet.
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
                  <strong>SRV-DC01 (Main Server)</strong> has a <strong className="text-rose-500 font-mono">94%</strong> chance of being taken over.
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
                  Click <strong>Quarantine</strong> below to cut off the attacker's path.
                </p>
              </div>
            </div>
          </div>

          {/* Right: Big, Friendly Action Buttons */}
          <div className="flex flex-col sm:flex-row lg:flex-col gap-3 min-w-[280px]">
            <button
              onClick={() => {
                if (soundEnabled) playCyberTone('policy');
                onToggleIsolate('app-07');
              }}
              className={`flex items-start space-x-3 p-3.5 rounded-xl border transition-all text-left ${
                isApp07Isolated
                  ? isLight
                    ? 'border-emerald-300 bg-emerald-50 text-emerald-900 hover:bg-emerald-100'
                    : 'border-emerald-500/50 bg-emerald-950/40 text-emerald-100 hover:bg-emerald-900/50'
                  : 'border-rose-500/60 bg-rose-600 hover:bg-rose-700 text-white shadow-lg'
              }`}
            >
              <div className="p-2 rounded-lg bg-black/20 mt-0.5">
                {isApp07Isolated ? (
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                ) : (
                  <ShieldOff className="w-5 h-5 text-white" />
                )}
              </div>
              <div>
                <div className="font-bold text-sm font-sans">
                  {isApp07Isolated ? 'APP-07 is Quarantined ✓' : 'Quarantine APP-07'}
                </div>
                <p className={`text-[11px] mt-0.5 leading-tight ${isApp07Isolated ? (isLight ? 'text-emerald-700' : 'text-emerald-300') : 'text-rose-100'}`}>
                  {isApp07Isolated
                    ? 'Infected machine unplugged. Attack cannot spread.'
                    : 'Unplugs the hacked server so virus cannot jump.'}
                </p>
              </div>
            </button>

            {predictedNextTarget && (
              <button
                onClick={() => {
                  if (soundEnabled) playCyberTone('policy');
                  onQuickMitigate(predictedNextTarget.hostId, predictedNextTarget.incomingPort);
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
                    {isTargetPortBlocked ? 'Port 445 is Locked ✓' : 'Lock Port 445 on Main Server'}
                  </div>
                  <p className={`text-[11px] mt-0.5 leading-tight ${isTargetPortBlocked ? (isLight ? 'text-emerald-700' : 'text-emerald-300') : 'text-amber-100'}`}>
                    {isTargetPortBlocked
                      ? 'Door closed. Remote file execution blocked.'
                      : 'Closes the file-sharing door the hacker is using.'}
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
            <span>🎯 Next Target in Danger (SRV-DC01 · 94%)</span>
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

              {/* Selected Host Explanatory Card Underneath Map */}
              {selectedHost && (
                <div className={`mt-4 p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors ${
                  isLight
                    ? 'bg-slate-50 border-slate-200'
                    : isMidnight
                    ? 'bg-[#071329] border-[#17386c]'
                    : 'bg-slate-900/60 border-slate-700/60'
                }`}>
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-mono uppercase text-cyan-500 font-bold">
                        Selected Computer:
                      </span>
                      <span className={`font-bold text-sm font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
                        {selectedHost.name} ({selectedHost.ip})
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        isolatedHostIds.includes(selectedHost.id)
                          ? 'bg-slate-700 text-slate-300'
                          : selectedHost.status === 'compromised'
                          ? 'bg-rose-500/20 text-rose-500 border border-rose-500/40'
                          : selectedHost.id === 'srv-dc01'
                          ? 'bg-amber-500/20 text-amber-500 border border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-500 border border-emerald-500/40'
                      }`}>
                        {isolatedHostIds.includes(selectedHost.id)
                          ? 'QUARANTINED (UNPLUGGED)'
                          : selectedHost.status === 'compromised'
                          ? 'INFECTED'
                          : selectedHost.id === 'srv-dc01'
                          ? 'IN DANGER (94%)'
                          : 'SAFE'}
                      </span>
                    </div>
                    <p className={`text-xs font-sans ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
                      {selectedHost.role} · Operating System: {selectedHost.os} · Open Ports: {selectedHost.openPorts.join(', ')}
                    </p>
                  </div>

                  <button
                    onClick={() => {
                      if (soundEnabled) playCyberTone('click');
                      onToggleIsolate(selectedHost.id);
                    }}
                    className={`px-4 py-2 rounded-xl text-xs font-bold font-sans transition-all flex items-center space-x-2 ${
                      isolatedHostIds.includes(selectedHost.id)
                        ? isLight
                          ? 'border border-emerald-400 bg-emerald-50 text-emerald-700 hover:bg-emerald-100'
                          : 'border border-emerald-500/40 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/50'
                        : 'border border-rose-500 bg-rose-600 hover:bg-rose-700 text-white shadow-md'
                    }`}
                  >
                    {isolatedHostIds.includes(selectedHost.id) ? (
                      <>
                        <ShieldCheck className="w-4 h-4 text-emerald-500" />
                        <span>Plug Back In</span>
                      </>
                    ) : (
                      <>
                        <ShieldOff className="w-4 h-4 text-white" />
                        <span>Unplug / Quarantine Machine</span>
                      </>
                    )}
                  </button>
                </div>
              )}
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
                    {node.id === 'app-07'
                      ? 'Attacker found an unpatched vulnerability on the public web server and gained remote root execution.'
                      : 'Finance employee opened a malicious email attachment that connected back to the attacker.'}
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
                A hacker breaks into an initial computer (like your public website server <strong>APP-07</strong>). That computer is now marked with a 🔴 <strong>Infected</strong> badge.
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
                Hackers do not stop at one computer. They probe internal cables to jump to the most valuable machine (the <strong>Central Main Server</strong>).
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
                Clicking <strong>Quarantine</strong> instantly cuts the digital wire, trapping the hacker in the infected machine before they reach your main server.
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
                Network spikes on <strong>Port {predictedNextTarget.incomingPort} (SMB / Windows File Sharing)</strong> from infected machine APP-07.
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
                You have approximately <strong>18 seconds</strong> to take protective action before authentication tokens are compromised.
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

import React, { useState } from 'react';
import { SlidersHorizontal, Search, ShieldAlert, Server, Laptop, Database, Globe, Lock, ShieldCheck, X } from 'lucide-react';
import { NetworkHost, NetworkEdge } from '../types';
import { playCyberTone } from '../utils/audio';

interface TopologyGraphProps {
  hosts: NetworkHost[];
  edges: NetworkEdge[];
  selectedHostId: string;
  onSelectHost: (hostId: string) => void;
  selectedEdgeId?: string;
  onSelectEdge?: (edge: NetworkEdge) => void;
  isolatedHostIds: string[];
  blockedPorts: { [hostId: string]: number[] };
  onIsolateToggle: (hostId: string) => void;
  soundEnabled: boolean;
}

export const TopologyGraph: React.FC<TopologyGraphProps> = ({
  hosts,
  edges,
  selectedHostId,
  onSelectHost,
  selectedEdgeId,
  onSelectEdge,
  isolatedHostIds,
  blockedPorts,
  onIsolateToggle,
  soundEnabled
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'high_attention' | 'corporate' | 'dmz'>('all');
  const [showInspector, setShowInspector] = useState(false);

  const filteredHosts = hosts.filter((h) => {
    const matchesSearch =
      h.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      h.ip.toLowerCase().includes(searchQuery.toLowerCase()) ||
      h.role.toLowerCase().includes(searchQuery.toLowerCase());

    if (!matchesSearch) return false;

    if (filterType === 'corporate') return h.segment === 'corporate';
    if (filterType === 'dmz') return h.segment === 'dmz';
    if (filterType === 'high_attention') return h.attentionScore >= 0.8;
    return true;
  });

  const selectedHost = hosts.find((h) => h.id === selectedHostId) || hosts[0];

  const getNodeIcon = (host: NetworkHost) => {
    if (host.id === 'c2-ext') return <Globe className="w-4 h-4 text-rose-400" />;
    if (host.id.includes('db')) return <Database className="w-4 h-4 text-cyan-400" />;
    if (host.id.includes('srv')) return <Server className="w-4 h-4 text-cyan-400" />;
    return <Laptop className="w-4 h-4 text-cyan-400" />;
  };

  // Node coordinate mapping in SVG viewbox (800x420)
  const nodeCoords: { [id: string]: { x: number; y: number } } = {
    'ws-042': { x: 120, y: 150 },
    'srv-dc01': { x: 300, y: 110 },
    'app-07': { x: 380, y: 280 },
    'db-02': { x: 540, y: 170 },
    'c2-ext': { x: 700, y: 300 }
  };

  return (
    <div className="relative flex flex-col rounded-xl border border-[#142d54] bg-[#061126]/90 overflow-hidden backdrop-blur-md">
      {/* Top section header */}
      <div className="flex items-center justify-between px-4 sm:px-5 py-3.5 border-b border-[#12284c] bg-[#08152e]/70">
        <div>
          <div className="text-[11px] font-mono tracking-wider text-slate-400">
            01 <span className="text-slate-600">/</span> TOPOLOGY
          </div>
          <h3 className="text-base sm:text-lg font-bold text-white tracking-tight">
            Network state graph
          </h3>
        </div>

        <div className="flex items-center space-x-2">
          <div className="px-2.5 py-1 rounded bg-rose-950/60 border border-rose-600/40 text-rose-400 text-xs font-mono font-bold tracking-wider shadow-[0_0_10px_rgba(244,63,94,0.2)]">
            ATTENTION 0.92
          </div>
          <button
            onClick={() => {
              if (soundEnabled) playCyberTone('click');
              setFilterType((prev) => (prev === 'all' ? 'high_attention' : 'all'));
            }}
            title="Filter high attention nodes"
            className={`p-1.5 rounded border transition-colors ${
              filterType === 'high_attention'
                ? 'border-cyan-500 bg-cyan-950/40 text-cyan-300'
                : 'border-[#17386c] bg-[#071329] text-slate-400 hover:text-white'
            }`}
          >
            <SlidersHorizontal className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Search and stats bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5 px-4 sm:px-5 py-2.5 bg-[#050e20] border-b border-[#102344] text-xs font-mono">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Find host or IP"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#08162e] border border-[#142e5c] rounded px-8 py-1.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 text-xs font-mono"
          />
        </div>

        <div className="flex items-center space-x-4 text-[11px] text-slate-400">
          <span className="flex items-center space-x-1.5">
            <span className="w-2 h-2 rounded-xs bg-rose-500" />
            <span>5 active hosts</span>
          </span>
          <span className="flex items-center space-x-1.5">
            <span className="w-2 h-2 rounded-xs bg-cyan-500" />
            <span>12 edges</span>
          </span>
        </div>
      </div>

      {/* Segment labels */}
      <div className="flex justify-between px-5 pt-2 text-[10px] font-mono tracking-widest text-slate-500 select-none">
        <div>| CORPORATE SEGMENT</div>
        <div>| DMZ / EDGE</div>
      </div>

      {/* Interactive Topology Graph Canvas / SVG */}
      <div className="relative w-full h-[320px] sm:h-[350px] cyber-grid overflow-hidden">
        {/* Subtle background segment dividing line */}
        <div className="absolute top-0 bottom-0 left-[68%] border-l border-dashed border-[#142b4e] pointer-events-none opacity-60" />

        <svg className="w-full h-full" viewBox="0 0 800 420" preserveAspectRatio="xMidYMid meet">
          <defs>
            {/* Glow filters */}
            <filter id="cyanGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
            <filter id="redGlow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
            <linearGradient id="attackGrad" x1="100%" y1="100%" x2="0%" y2="0%">
              <stop offset="0%" stopColor="#f43f5e" />
              <stop offset="100%" stopColor="#fb7185" />
            </linearGradient>
          </defs>

          {/* Render Edges */}
          {edges.map((edge) => {
            const src = nodeCoords[edge.source];
            const tgt = nodeCoords[edge.target];
            if (!src || !tgt) return null;

            const isSourceIsolated = isolatedHostIds.includes(edge.source);
            const isTargetIsolated = isolatedHostIds.includes(edge.target);
            const isBlocked = isSourceIsolated || isTargetIsolated;

            const isAttack = edge.type === 'attack';
            const isElevated = edge.type === 'elevated';
            const isSelected = selectedEdgeId === edge.id;

            const strokeColor = isBlocked
              ? '#334155'
              : isSelected
              ? '#00f0ff'
              : isAttack
              ? '#f43f5e'
              : isElevated
              ? '#f59e0b'
              : '#06b6d4';

            const strokeDash = isBlocked
              ? '4, 4'
              : isAttack
              ? '8, 6'
              : isElevated
              ? '6, 6'
              : '4, 8';

            const midX = (src.x + tgt.x) / 2;
            const midY = (src.y + tgt.y) / 2;

            return (
              <g
                key={edge.id}
                onClick={() => {
                  if (soundEnabled) playCyberTone('click');
                  if (onSelectEdge) onSelectEdge(edge);
                }}
                className="transition-all duration-300 cursor-pointer group"
              >
                {/* Active or hovered selection glow */}
                {isSelected && (
                  <line
                    x1={src.x}
                    y1={src.y}
                    x2={tgt.x}
                    y2={tgt.y}
                    stroke="#00f0ff"
                    strokeWidth={8}
                    opacity={0.4}
                    className="animate-pulse"
                  />
                )}

                {/* Edge line background glow */}
                {!isBlocked && isAttack && !isSelected && (
                  <line
                    x1={src.x}
                    y1={src.y}
                    x2={tgt.x}
                    y2={tgt.y}
                    stroke="#f43f5e"
                    strokeWidth={4}
                    opacity={0.3}
                  />
                )}

                {/* Invisible wider hit area for easy clicking */}
                <line
                  x1={src.x}
                  y1={src.y}
                  x2={tgt.x}
                  y2={tgt.y}
                  stroke="transparent"
                  strokeWidth={16}
                />

                {/* Main edge line */}
                <line
                  x1={src.x}
                  y1={src.y}
                  x2={tgt.x}
                  y2={tgt.y}
                  stroke={strokeColor}
                  strokeWidth={isSelected ? 3.5 : isAttack ? 3 : 2}
                  strokeDasharray={strokeDash}
                  opacity={isBlocked ? 0.3 : 0.95}
                  className={!isBlocked && isAttack ? 'animate-pulse' : ''}
                />

                {/* Direction arrow / indicator near target */}
                <circle
                  cx={src.x * 0.35 + tgt.x * 0.65}
                  cy={src.y * 0.35 + tgt.y * 0.65}
                  r={isSelected ? 3.5 : 2.5}
                  fill={strokeColor}
                  className="animate-ping opacity-60"
                  style={{ animationDuration: '3s' }}
                />

                {/* Edge label pill */}
                {isSelected && (
                  <rect
                    x={midX - 35}
                    y={midY - 18}
                    width={70}
                    height={15}
                    rx={3}
                    fill="#05142b"
                    stroke="#00f0ff"
                    strokeWidth={1}
                    className="shadow-md"
                  />
                )}

                {/* Edge label */}
                <text
                  x={midX}
                  y={midY - 8}
                  fill={isSelected ? '#38bdf8' : strokeColor}
                  fontSize={isSelected ? "10" : "9"}
                  fontWeight={isSelected ? "bold" : "normal"}
                  fontFamily="monospace"
                  textAnchor="middle"
                  className="select-none pointer-events-none"
                >
                  {isBlocked ? '[BLOCKED]' : isSelected ? `★ ${edge.protocol} :${edge.port}` : `${edge.protocol} :${edge.port}`}
                </text>
              </g>
            );
          })}

          {/* Render Nodes */}
          {hosts.map((host) => {
            const coords = nodeCoords[host.id];
            if (!coords) return null;

            const isSelected = selectedHostId === host.id;
            const isIsolated = isolatedHostIds.includes(host.id);
            const isMatching = filteredHosts.some((h) => h.id === host.id);
            const isC2 = host.id === 'c2-ext';

            const opacity = isMatching ? 1 : 0.25;

            return (
              <g
                key={host.id}
                transform={`translate(${coords.x}, ${coords.y})`}
                opacity={opacity}
                onClick={() => {
                  if (soundEnabled) playCyberTone('click');
                  onSelectHost(host.id);
                  setShowInspector(true);
                }}
                className="cursor-pointer transition-transform duration-200 hover:scale-105"
              >
                {/* Outer selection ring / glow */}
                {isSelected && (
                  <rect
                    x={-56}
                    y={-34}
                    width={112}
                    height={68}
                    rx={8}
                    fill="none"
                    stroke={isC2 ? '#f43f5e' : '#06b6d4'}
                    strokeWidth={2}
                    className="animate-pulse"
                    filter={isC2 ? 'url(#redGlow)' : 'url(#cyanGlow)'}
                  />
                )}

                {/* Node box container */}
                <rect
                  x={-50}
                  y={-28}
                  width={100}
                  height={56}
                  rx={6}
                  fill={isIsolated ? '#111827' : '#071329'}
                  stroke={
                    isIsolated
                      ? '#475569'
                      : isC2
                      ? '#f43f5e'
                      : isSelected
                      ? '#00f0ff'
                      : '#163868'
                  }
                  strokeWidth={isSelected ? 2 : 1.5}
                />

                {/* Left Mini icon box */}
                <rect
                  x={-42}
                  y={-18}
                  width={22}
                  height={22}
                  rx={4}
                  fill={isIsolated ? '#1f2937' : isC2 ? '#3f111e' : '#0b264a'}
                  stroke={isC2 ? '#f43f5e' : '#06b6d4'}
                  strokeWidth={1}
                />

                {/* Host icon render inside mini box */}
                <g transform="translate(-40, -16) scale(0.75)">
                  {isIsolated ? (
                    <Lock className="w-5 h-5 text-slate-400" />
                  ) : (
                    getNodeIcon(host)
                  )}
                </g>

                {/* Host label text */}
                <text
                  x={-14}
                  y={-6}
                  fill={
                    isIsolated
                      ? '#94a3b8'
                      : isC2
                      ? '#fb7185'
                      : host.id === 'srv-dc01'
                      ? '#fbbf24'
                      : '#ffffff'
                  }
                  fontSize="11"
                  fontWeight="bold"
                  fontFamily="monospace"
                >
                  {host.name}
                </text>

                {/* Host IP */}
                <text
                  x={-14}
                  y={10}
                  fill={isIsolated ? '#64748b' : '#67e8f9'}
                  fontSize="9"
                  fontFamily="monospace"
                >
                  {host.ip}
                </text>

                {/* Isolated badge status if isolated */}
                {isIsolated && (
                  <text
                    x={0}
                    y={22}
                    fill="#f43f5e"
                    fontSize="8"
                    fontWeight="bold"
                    fontFamily="monospace"
                    textAnchor="middle"
                  >
                    ● ISOLATED
                  </text>
                )}
              </g>
            );
          })}
        </svg>

        {/* Selected Host Floating Inspector Overlay */}
        {showInspector && selectedHost && (
          <div className="absolute bottom-3 left-3 sm:left-4 z-20 max-w-xs sm:max-w-sm rounded-lg border border-[#163a6f] bg-[#071329]/95 backdrop-blur-md p-3.5 shadow-2xl animate-in fade-in slide-in-from-bottom-2">
            <div className="flex items-center justify-between pb-2 border-b border-[#122b54]">
              <div className="flex items-center space-x-2">
                <span className={`w-2 h-2 rounded-full ${
                  isolatedHostIds.includes(selectedHost.id) ? 'bg-slate-500' : 'bg-cyan-400 animate-pulse'
                }`} />
                <span className="font-mono font-bold text-xs text-white">
                  {selectedHost.name} ({selectedHost.ip})
                </span>
              </div>
              <button
                onClick={() => setShowInspector(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="pt-2 space-y-1.5 text-[11px] font-mono">
              <div className="text-slate-300 font-sans">{selectedHost.role}</div>
              <div className="text-slate-400">OS: {selectedHost.os}</div>
              <div className="text-slate-400 flex items-center justify-between">
                <span>Attention Weight:</span>
                <span className="text-rose-400 font-bold">{selectedHost.attentionScore}</span>
              </div>
              <div className="text-slate-400 flex items-center justify-between">
                <span>Open Ports:</span>
                <span className="text-cyan-300">
                  {selectedHost.openPorts.join(', ')}
                </span>
              </div>

              {/* Quick actions for selected host */}
              <div className="pt-2 flex flex-col gap-1.5">
                {edges.some((e) => e.source === selectedHost.id) && (
                  <button
                    onClick={() => {
                      if (soundEnabled) playCyberTone('click');
                      const firstEdge = edges.find((e) => e.source === selectedHost.id);
                      if (firstEdge && onSelectEdge) {
                        onSelectEdge(firstEdge);
                      }
                    }}
                    className="w-full flex items-center justify-center space-x-1.5 py-1 px-2 rounded text-[11px] font-semibold border border-cyan-500/40 bg-cyan-950/40 text-cyan-300 hover:bg-cyan-900/50 transition-colors"
                  >
                    <span>Inspect Outbound Vector as Source</span>
                  </button>
                )}
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => {
                      if (soundEnabled) playCyberTone('click');
                      onIsolateToggle(selectedHost.id);
                    }}
                    className={`flex-1 flex items-center justify-center space-x-1.5 py-1 px-2 rounded text-[11px] font-semibold border transition-colors ${
                      isolatedHostIds.includes(selectedHost.id)
                        ? 'border-emerald-500/40 bg-emerald-950/30 text-emerald-300'
                        : 'border-rose-500/40 bg-rose-950/30 text-rose-300 hover:bg-rose-900/40'
                    }`}
                  >
                    {isolatedHostIds.includes(selectedHost.id) ? (
                      <>
                        <ShieldCheck className="w-3 h-3" />
                        <span>Re-attach Host</span>
                      </>
                    ) : (
                      <>
                        <Lock className="w-3 h-3" />
                        <span>Isolate Host</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Bottom legend */}
      <div className="flex items-center space-x-5 px-4 sm:px-5 py-2 bg-[#050e20] border-t border-[#102344] text-[11px] font-mono text-slate-400">
        <span className="flex items-center space-x-1.5">
          <span className="w-2 h-2 rounded-full bg-rose-500 shadow-[0_0_6px_#f43f5e]" />
          <span>High attention</span>
        </span>
        <span className="flex items-center space-x-1.5">
          <span className="w-2 h-2 rounded-full bg-amber-400 shadow-[0_0_6px_#fbbf24]" />
          <span>Elevated</span>
        </span>
        <span className="flex items-center space-x-1.5">
          <span className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_6px_#06b6d4]" />
          <span>Normal flow</span>
        </span>
      </div>
    </div>
  );
};

import React, { useState, useRef } from 'react';
import { SlidersHorizontal, Search, ShieldAlert, Server, Laptop, Database, Globe, Lock, ShieldCheck, X, RotateCcw, Move, Sparkles } from 'lucide-react';
import { NetworkHost, NetworkEdge, AppTheme } from '../types';
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
  theme?: AppTheme;
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
  soundEnabled,
  theme = 'light'
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'high_attention' | 'corporate' | 'dmz'>('all');
  const [showInspector, setShowInspector] = useState(false);

  // Drag-and-drop interactive repositioning state
  const svgRef = useRef<SVGSVGElement | null>(null);
  const hasDraggedRef = useRef<boolean>(false);
  const [customCoords, setCustomCoords] = useState<{ [id: string]: { x: number; y: number } }>({});
  const [dragState, setDragState] = useState<{
    id: string;
    startClientX: number;
    startClientY: number;
    startNodeX: number;
    startNodeY: number;
  } | null>(null);

  const isLight = theme === 'light';
  const isMidnight = theme === 'midnight';

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
    if (host.id === 'c2-ext' || host.id.includes('c2') || host.role.toLowerCase().includes('threat') || host.role.toLowerCase().includes('c2')) {
      return <Globe className="w-4 h-4 text-rose-500" />;
    }
    if (host.id.includes('db') || host.role.toLowerCase().includes('database')) {
      return <Database className="w-4 h-4 text-cyan-500" />;
    }
    if (host.id.includes('srv') || host.id.includes('dc') || host.id.includes('gw') || host.role.toLowerCase().includes('server') || host.role.toLowerCase().includes('gateway')) {
      return <Server className="w-4 h-4 text-cyan-500" />;
    }
    return <Laptop className="w-4 h-4 text-cyan-500" />;
  };

  // Node coordinate calculation over expansive 1160 x 580 canvas
  const getNodeCoords = (hostId: string): { x: number; y: number } => {
    // 1. User manual drag override
    if (customCoords[hostId]) return customCoords[hostId];

    const host = hosts.find((h) => h.id === hostId);

    // 2. Proportional layout scaling across 1160 x 580 canvas
    if (host && typeof host.x === 'number' && typeof host.y === 'number') {
      const x = Math.round(90 + (host.x / 100) * 980);
      const y = Math.round(65 + (host.y / 100) * 450);
      return { x, y };
    }

    // 3. Fallback: Zone-based distribution
    const idx = hosts.findIndex((h) => h.id === hostId);
    if (idx >= 0 && hosts.length > 0) {
      const isExt = host?.segment === 'dmz' || host?.role.toLowerCase().includes('external') || host?.role.toLowerCase().includes('c2');
      const col = isExt ? (idx % 2) : 2 + (idx % 2);
      const row = Math.floor(idx / 2);
      const x = Math.round(180 + col * 260);
      const y = Math.round(140 + row * 130);
      return { x, y };
    }
    return { x: 580, y: 290 };
  };

  const handleMouseDownNode = (e: React.MouseEvent, hostId: string) => {
    e.stopPropagation();
    hasDraggedRef.current = false;
    const current = getNodeCoords(hostId);
    setDragState({
      id: hostId,
      startClientX: e.clientX,
      startClientY: e.clientY,
      startNodeX: current.x,
      startNodeY: current.y
    });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!dragState || !svgRef.current) return;
    const dist = Math.hypot(e.clientX - dragState.startClientX, e.clientY - dragState.startClientY);
    if (dist > 4) {
      hasDraggedRef.current = true;
    }
    const rect = svgRef.current.getBoundingClientRect();
    const scaleX = 1160 / rect.width;
    const scaleY = 580 / rect.height;
    const dx = (e.clientX - dragState.startClientX) * scaleX;
    const dy = (e.clientY - dragState.startClientY) * scaleY;

    const newX = Math.max(70, Math.min(1090, Math.round(dragState.startNodeX + dx)));
    const newY = Math.max(50, Math.min(530, Math.round(dragState.startNodeY + dy)));

    setCustomCoords((prev) => ({
      ...prev,
      [dragState.id]: { x: newX, y: newY }
    }));
  };

  const handleMouseUp = () => {
    if (dragState) {
      setDragState(null);
    }
  };

  const handleResetLayout = () => {
    if (soundEnabled) playCyberTone('click');
    setCustomCoords({});
  };

  const getFriendlyHostInfo = (host: NetworkHost) => {
    const isComp = host.status === 'compromised';
    const isTgt = host.status === 'targeted';
    const isElevated = host.status === 'elevated';
    const isC2Node =
      host.role?.toLowerCase().includes('external') ||
      host.role?.toLowerCase().includes('adversary') ||
      host.role?.toLowerCase().includes('attacker') ||
      host.segment === 'dmz' ||
      host.id.includes('c2') ||
      host.id.includes('ext');

    const riskPercent = Math.round((host.attentionScore || (isTgt ? 0.85 : isComp ? 0.9 : 0.3)) * 100);

    return {
      title: host.name,
      role: host.role,
      roleDesc: `${host.role} · OS: ${host.os} · Open Ports: [${(host.openPorts || []).join(', ') || 'None'}] · Attention: ${riskPercent}%`,
      status: isC2Node || isComp
        ? '🔴 INFECTED / BREACHED'
        : isTgt
        ? `⚠️ IN IMMEDIATE DANGER (${riskPercent}%)`
        : isElevated
        ? `⚡ ELEVATED ACTIVITY (${riskPercent}%)`
        : '🟢 SAFE & HEALTHY',
      statusColor: isC2Node || isComp ? '#f43f5e' : isTgt ? '#fbbf24' : isElevated ? '#06b6d4' : '#10b981',
      bgStatus: isC2Node || isComp
        ? (isLight ? 'bg-rose-100 text-rose-900 border-rose-300' : 'bg-rose-950/80 text-rose-300 border-rose-500/40')
        : isTgt
        ? (isLight ? 'bg-amber-100 text-amber-900 border-amber-300' : 'bg-amber-950/80 text-amber-300 border-amber-500/40')
        : isElevated
        ? (isLight ? 'bg-cyan-100 text-cyan-900 border-cyan-300' : 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40')
        : (isLight ? 'bg-emerald-100 text-emerald-900 border-emerald-300' : 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40')
    };
  };

  const nodeBoxFill = (isIso: boolean, isC2: boolean, isComp: boolean, isTgt: boolean) => {
    if (isIso) return isLight ? '#f1f5f9' : '#111827';
    if (isLight) {
      if (isC2 || isComp) return '#fff1f2';
      if (isTgt) return '#fffbeb';
      return '#ffffff';
    }
    if (isMidnight) return '#071329';
    // Slate theme
    if (isC2 || isComp) return '#26121d';
    if (isTgt) return '#261d12';
    return '#1e293b';
  };

  return (
    <div className={`relative flex flex-col rounded-xl border overflow-hidden backdrop-blur-md transition-colors ${
      isLight 
        ? 'bg-white border-slate-200 shadow-sm text-slate-800'
        : isMidnight
        ? 'bg-[#061126]/90 border-[#142d54] text-slate-100'
        : 'bg-slate-800/90 border-slate-700/80 text-slate-100 shadow-xl'
    }`}>
      {/* Top section header */}
      <div className={`flex items-center justify-between px-4 sm:px-5 py-3.5 border-b ${
        isLight ? 'bg-slate-50 border-slate-200' : isMidnight ? 'bg-[#08152e]/70 border-[#12284c]' : 'bg-slate-900/60 border-slate-700/60'
      }`}>
        <div>
          <div className={`text-[11px] font-mono tracking-wider ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
            01 <span className="text-slate-500">/</span> TOPOLOGY
          </div>
          <h3 className={`text-base sm:text-lg font-bold tracking-tight ${isLight ? 'text-slate-900' : 'text-white'}`}>
            Network state graph
          </h3>
        </div>

        <div className="flex items-center space-x-2">
          <div className="px-2.5 py-1 rounded bg-rose-500/10 border border-rose-500/40 text-rose-500 text-xs font-mono font-bold tracking-wider">
            ATTENTION 0.92
          </div>
          <button
            onClick={handleResetLayout}
            title="Reset to default spacious layout"
            className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded border text-xs font-mono transition-colors ${
              isLight
                ? 'border-slate-300 bg-white text-slate-700 hover:text-slate-900 shadow-xs'
                : 'border-slate-700 bg-slate-800 text-slate-300 hover:text-white'
            }`}
          >
            <RotateCcw className="w-3.5 h-3.5 text-cyan-500" />
            <span className="hidden sm:inline">Auto Space</span>
          </button>
          <button
            onClick={() => {
              if (soundEnabled) playCyberTone('click');
              setFilterType((prev) => (prev === 'all' ? 'high_attention' : 'all'));
            }}
            title="Filter high attention nodes"
            className={`p-1.5 rounded border transition-colors ${
              filterType === 'high_attention'
                ? 'border-cyan-500 bg-cyan-500/20 text-cyan-600 dark:text-cyan-300'
                : isLight
                ? 'border-slate-300 bg-white text-slate-600 hover:text-slate-900'
                : 'border-slate-700 bg-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            <SlidersHorizontal className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Search and stats bar */}
      <div className={`flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5 px-4 sm:px-5 py-2.5 border-b text-xs font-mono ${
        isLight ? 'bg-slate-100/70 border-slate-200 text-slate-700' : isMidnight ? 'bg-[#050e20] border-[#102344] text-slate-400' : 'bg-slate-900/50 border-slate-700/60 text-slate-300'
      }`}>
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
          <input
            type="text"
            placeholder="Find host or IP"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className={`w-full rounded px-8 py-1.5 text-xs font-mono border focus:outline-none focus:border-cyan-500 ${
              isLight
                ? 'bg-white border-slate-300 text-slate-800 placeholder-slate-400'
                : 'bg-slate-800 border-slate-700 text-slate-200 placeholder-slate-500'
            }`}
          />
        </div>

        <div className="flex flex-wrap items-center gap-4 text-[11px]">
          <span className="hidden md:inline-flex text-[10px] text-slate-400 font-sans items-center gap-1">
            <Move className="w-3 h-3 text-cyan-500" /> Drag any computer to reposition
          </span>
          <span className="flex items-center space-x-1.5">
            <span className="w-2 h-2 rounded-xs bg-rose-500" />
            <span>{hosts.length} active hosts</span>
          </span>
          <span className="flex items-center space-x-1.5">
            <span className="w-2 h-2 rounded-xs bg-cyan-500" />
            <span>{edges.length} edges</span>
          </span>
        </div>
      </div>

      {/* Interactive Topology Graph Canvas / SVG (Expansive View with Space) */}
      <div 
        className={`relative w-full h-[460px] sm:h-[540px] lg:h-[620px] cyber-grid overflow-hidden select-none ${
          isLight ? 'bg-slate-50/70' : isMidnight ? 'bg-[#040b18]' : 'bg-[#0f172a]/90'
        }`}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <svg 
          ref={svgRef}
          className="w-full h-full" 
          viewBox="0 0 1160 580" 
          preserveAspectRatio="xMidYMid meet"
        >
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

          {/* Background Zone Demarcation Columns (Spacious & Clean) */}
          <g className="opacity-45 pointer-events-none">
            {/* Zone 1: Ingress / External */}
            <rect x="25" y="16" width="280" height="548" rx="8" fill={isLight ? '#f1f5f9' : '#071020'} stroke={isLight ? '#cbd5e1' : '#1e293b'} strokeWidth="1" strokeDasharray="5,5" />
            <text x="40" y="38" fill={isLight ? '#64748b' : '#64748b'} fontSize="9.5" fontWeight="bold" fontFamily="monospace" letterSpacing="1.5">
              ZONE 01: EXTERNAL VECTOR / C2
            </text>

            {/* Zone 2: DMZ & Gateway */}
            <rect x="325" y="16" width="240" height="548" rx="8" fill={isLight ? '#f1f5f9' : '#071020'} stroke={isLight ? '#cbd5e1' : '#1e293b'} strokeWidth="1" strokeDasharray="5,5" />
            <text x="340" y="38" fill={isLight ? '#64748b' : '#64748b'} fontSize="9.5" fontWeight="bold" fontFamily="monospace" letterSpacing="1.5">
              ZONE 02: DMZ & PERIMETER
            </text>

            {/* Zone 3: Enterprise Servers */}
            <rect x="585" y="16" width="260" height="548" rx="8" fill={isLight ? '#f1f5f9' : '#071020'} stroke={isLight ? '#cbd5e1' : '#1e293b'} strokeWidth="1" strokeDasharray="5,5" />
            <text x="600" y="38" fill={isLight ? '#64748b' : '#64748b'} fontSize="9.5" fontWeight="bold" fontFamily="monospace" letterSpacing="1.5">
              ZONE 03: CORE IDENTITY & DATA
            </text>

            {/* Zone 4: Workstations */}
            <rect x="865" y="16" width="270" height="548" rx="8" fill={isLight ? '#f1f5f9' : '#071020'} stroke={isLight ? '#cbd5e1' : '#1e293b'} strokeWidth="1" strokeDasharray="5,5" />
            <text x="880" y="38" fill={isLight ? '#64748b' : '#64748b'} fontSize="9.5" fontWeight="bold" fontFamily="monospace" letterSpacing="1.5">
              ZONE 04: CLIENT WORKSTATIONS
            </text>
          </g>

          {/* Render Edges */}
          {edges.map((edge) => {
            const src = getNodeCoords(edge.source);
            const tgt = getNodeCoords(edge.target);
            if (!src || !tgt) return null;

            const isSourceIsolated = isolatedHostIds.includes(edge.source);
            const isTargetIsolated = isolatedHostIds.includes(edge.target);
            const isBlocked = isSourceIsolated || isTargetIsolated;

            const isAttack = edge.type === 'attack';
            const isElevated = edge.type === 'elevated';
            const isSelected = selectedEdgeId === edge.id;

            const strokeColor = isBlocked
              ? (isLight ? '#94a3b8' : '#475569')
              : isSelected
              ? '#06b6d4'
              : isAttack
              ? '#f43f5e'
              : isElevated
              ? '#f59e0b'
              : isLight ? '#0284c7' : '#38bdf8';

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
                    stroke="#06b6d4"
                    strokeWidth={8}
                    opacity={0.3}
                  />
                )}

                {/* Attack path animation halo */}
                {!isBlocked && isAttack && (
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
                  opacity={isBlocked ? 0.35 : 0.95}
                  className={!isBlocked && isAttack ? 'animate-pulse' : ''}
                />

                {/* Edge port indicator pill on line */}
                <g transform={`translate(${midX}, ${midY})`}>
                  <rect
                    x={-28}
                    y={-9}
                    width={56}
                    height={18}
                    rx={4}
                    fill={isLight ? '#ffffff' : '#071329'}
                    stroke={isSelected ? '#06b6d4' : isAttack ? '#f43f5e' : (isLight ? '#cbd5e1' : '#1e293b')}
                    strokeWidth={isSelected ? 1.8 : 1}
                    className="shadow-sm"
                  />
                  <text
                    x={0}
                    y={3.5}
                    textAnchor="middle"
                    fill={isSelected ? '#06b6d4' : isAttack ? '#f43f5e' : (isLight ? '#475569' : '#94a3b8')}
                    fontSize="8.5"
                    fontWeight="bold"
                    fontFamily="monospace"
                  >
                    :{edge.port}
                  </text>
                </g>
              </g>
            );
          })}

          {/* Render Nodes */}
          {hosts.map((host) => {
            const coords = getNodeCoords(host.id);
            if (!coords) return null;

            const isSelected = selectedHostId === host.id;
            const isIsolated = isolatedHostIds.includes(host.id);
            const isMatching = filteredHosts.some((h) => h.id === host.id);
            const isC2 = host.id === 'c2-ext' || host.role?.toLowerCase().includes('adversary') || host.role?.toLowerCase().includes('attacker') || host.id.includes('c2') || host.id.includes('expl');
            const isTarget = host.status === 'targeted' || host.id === 'srv-dc01';
            const isCompromised = host.status === 'compromised';
            const isElevated = host.status === 'elevated';
            const riskPercent = Math.round((host.attentionScore || (isTarget ? 0.85 : isCompromised ? 0.90 : isElevated ? 0.65 : 0.20)) * 100);

            const opacity = isMatching ? 1 : 0.3;

            return (
              <g
                key={host.id}
                transform={`translate(${coords.x}, ${coords.y})`}
                opacity={opacity}
                onMouseDown={(e) => handleMouseDownNode(e, host.id)}
                onClick={() => {
                  if (hasDraggedRef.current) return;
                  if (soundEnabled) playCyberTone('click');
                  onSelectHost(host.id);
                  setShowInspector(true);
                }}
                className="cursor-grab active:cursor-grabbing transition-transform duration-150 hover:scale-105"
              >
                {/* Outer selection ring / glow */}
                {isSelected && (
                  <rect
                    x={-83}
                    y={-41}
                    width={166}
                    height={82}
                    rx={12}
                    fill="none"
                    stroke={isC2 ? '#f43f5e' : isTarget ? '#fbbf24' : '#06b6d4'}
                    strokeWidth={2}
                    className="animate-pulse"
                    filter={isC2 ? 'url(#redGlow)' : 'url(#cyanGlow)'}
                  />
                )}

                {/* Node box container */}
                <rect
                  x={-77}
                  y={-35}
                  width={154}
                  height={70}
                  rx={10}
                  fill={nodeBoxFill(isIsolated, isC2, isCompromised, isTarget)}
                  stroke={
                    isIsolated
                      ? (isLight ? '#94a3b8' : '#475569')
                      : isC2
                      ? '#f43f5e'
                      : isCompromised
                      ? '#f43f5e'
                      : isTarget
                      ? '#fbbf24'
                      : isSelected
                      ? '#06b6d4'
                      : isLight ? '#cbd5e1' : '#334155'
                  }
                  strokeWidth={isSelected ? 2.5 : isTarget || isCompromised ? 2 : 1.5}
                />

                {/* Left Mini icon box */}
                <rect
                  x={-69}
                  y={-25}
                  width={26}
                  height={26}
                  rx={6}
                  fill={
                    isIsolated
                      ? (isLight ? '#e2e8f0' : '#1f2937')
                      : isC2
                      ? (isLight ? '#fee2e2' : '#3f111e')
                      : isCompromised
                      ? (isLight ? '#fee2e2' : '#3b1219')
                      : isTarget
                      ? (isLight ? '#fef3c7' : '#362308')
                      : (isLight ? '#e0f2fe' : '#0b264a')
                  }
                  stroke={isC2 || isCompromised ? '#f43f5e' : isTarget ? '#fbbf24' : '#06b6d4'}
                  strokeWidth={1}
                />

                {/* Host icon render inside mini box */}
                <g transform="translate(-66, -22) scale(0.8)">
                  {isIsolated ? (
                    <Lock className="w-5 h-5 text-slate-400" />
                  ) : (
                    getNodeIcon(host)
                  )}
                </g>

                {/* Host Name Header */}
                <text
                  x={-34}
                  y={-14}
                  fill={
                    isIsolated
                      ? (isLight ? '#64748b' : '#94a3b8')
                      : isC2
                      ? '#e11d48'
                      : isTarget
                      ? (isLight ? '#b45309' : '#fef08a')
                      : isCompromised
                      ? '#e11d48'
                      : (isLight ? '#0f172a' : '#ffffff')
                  }
                  fontSize="10"
                  fontWeight="bold"
                  fontFamily="sans-serif"
                >
                  {host.name.length > 16 ? host.name.substring(0, 15) + '…' : host.name}
                </text>

                {/* Host IP in crisp monospace */}
                <text
                  x={-34}
                  y={-1}
                  fill={
                    isIsolated
                      ? '#64748b'
                      : isC2
                      ? '#f43f5e'
                      : isTarget
                      ? (isLight ? '#d97706' : '#fbbf24')
                      : isCompromised
                      ? '#f43f5e'
                      : (isLight ? '#0369a1' : '#38bdf8')
                  }
                  fontSize="8.5"
                  fontWeight="600"
                  fontFamily="monospace"
                >
                  {host.ip}
                </text>

                {/* Status pill badge on node */}
                <rect
                  x={-69}
                  y={13}
                  width={138}
                  height={15}
                  rx={3.5}
                  fill={
                    isIsolated
                      ? (isLight ? '#e2e8f0' : '#1e293b')
                      : isCompromised
                      ? (isLight ? '#ffe4e6' : '#4c0519')
                      : isTarget
                      ? (isLight ? '#fef3c7' : '#451a03')
                      : (isLight ? '#dcfce7' : '#062d3e')
                  }
                  stroke={
                    isIsolated
                      ? '#64748b'
                      : isCompromised
                      ? '#f43f5e'
                      : isTarget
                      ? '#f59e0b'
                      : '#10b981'
                  }
                  strokeWidth={0.8}
                />

                <text
                  x={0}
                  y={23.5}
                  fill={
                    isIsolated
                      ? (isLight ? '#475569' : '#94a3b8')
                      : isCompromised
                      ? (isLight ? '#be123c' : '#fecdd3')
                      : isTarget
                      ? (isLight ? '#b45309' : '#fde68a')
                      : (isLight ? '#047857' : '#6ee7b7')
                  }
                  fontSize="7.5"
                  fontWeight="bold"
                  fontFamily="sans-serif"
                  textAnchor="middle"
                >
                  {isIsolated
                    ? '🛡️ ISOLATED'
                    : isCompromised
                    ? '🔴 COMPROMISED'
                    : isTarget
                    ? `⚠️ TARGETED (${riskPercent}%)`
                    : isElevated
                    ? `⚡ ELEVATED (${riskPercent}%)`
                    : '🟢 NORMAL'}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected host inspector overlay modal */}
        {showInspector && selectedHost && (
          <div className={`absolute bottom-3 right-3 w-72 sm:w-80 rounded-xl border p-4 shadow-2xl z-20 backdrop-blur-md animate-in fade-in slide-in-from-bottom-2 ${
            isLight ? 'bg-white/95 border-slate-300 text-slate-800' : 'bg-slate-900/95 border-slate-700 text-slate-100'
          }`}>
            <div className={`flex items-start justify-between pb-3 border-b ${isLight ? 'border-slate-200' : 'border-slate-800'}`}>
              <div className="space-y-0.5">
                <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-500 font-bold block">
                  Computer Inspector
                </span>
                <h4 className="text-base font-bold font-sans">
                  {getFriendlyHostInfo(selectedHost).title}
                </h4>
                <span className="text-[11px] font-mono text-slate-400">
                  {selectedHost.role} · IP: {selectedHost.ip}
                </span>
              </div>
              <button
                onClick={() => setShowInspector(false)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-white p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="py-2.5 space-y-2 text-xs">
              <div className={`p-2.5 rounded-lg border ${isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-800/60 border-slate-700/60'}`}>
                <span className="text-[10px] uppercase font-bold text-slate-400 block mb-0.5">
                  What this computer does:
                </span>
                <p className="leading-snug">
                  {getFriendlyHostInfo(selectedHost).roleDesc}
                </p>
              </div>

              <div className="flex items-center justify-between px-1 text-slate-400 text-[11px]">
                <span>Operating System:</span>
                <span className="font-mono font-medium text-slate-700 dark:text-slate-200">{selectedHost.os}</span>
              </div>

              <div className="flex items-center justify-between px-1 text-slate-400 text-[11px]">
                <span>Open Doors (Ports):</span>
                <span className="font-mono text-cyan-600 dark:text-cyan-400">{(selectedHost.openPorts || []).join(', ') || 'None'}</span>
              </div>

              <div className={`flex items-center justify-between px-2.5 py-1.5 rounded-lg border ${
                isLight ? 'bg-slate-100 border-slate-200' : 'bg-slate-800 border-slate-700'
              }`}>
                <span className="text-slate-400 text-[11px]">Security Status:</span>
                <span className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono ${
                  isolatedHostIds.includes(selectedHost.id)
                    ? 'bg-slate-700 text-slate-200'
                    : getFriendlyHostInfo(selectedHost).bgStatus
                }`}>
                  {isolatedHostIds.includes(selectedHost.id)
                    ? '🛡️ QUARANTINED'
                    : getFriendlyHostInfo(selectedHost).status}
                </span>
              </div>

              {/* Quick actions */}
              <div className="pt-2 flex flex-col gap-2">
                <button
                  onClick={() => {
                    if (soundEnabled) playCyberTone('click');
                    onIsolateToggle(selectedHost.id);
                  }}
                  className={`w-full flex items-center justify-center space-x-2 py-2 px-3 rounded-lg text-xs font-bold font-sans transition-all ${
                    isolatedHostIds.includes(selectedHost.id)
                      ? 'border border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/20'
                      : 'border border-rose-500/50 bg-rose-600 hover:bg-rose-700 text-white shadow-md'
                  }`}
                >
                  {isolatedHostIds.includes(selectedHost.id) ? (
                    <>
                      <ShieldCheck className="w-4 h-4 text-emerald-500" />
                      <span>Plug Back In (Restore Connection)</span>
                    </>
                  ) : (
                    <>
                      <Lock className="w-4 h-4 text-white" />
                      <span>Unplug / Quarantine Machine</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Bottom legend */}
      <div className={`flex items-center space-x-5 px-4 sm:px-5 py-2 border-t text-[11px] font-mono ${
        isLight ? 'bg-slate-50 border-slate-200 text-slate-600' : isMidnight ? 'bg-[#050e20] border-[#102344] text-slate-400' : 'bg-slate-900/60 border-slate-700/60 text-slate-300'
      }`}>
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

import React, { useState } from 'react';
import { Radio, Check, TrendingUp, ShieldAlert, Activity, ArrowRight } from 'lucide-react';
import { ForecastPoint, KillChainStage, AppTheme } from '../types';
import { playCyberTone } from '../utils/audio';

interface TrajectoryForecastProps {
  points: ForecastPoint[];
  killChainStages: KillChainStage[];
  portEntropy: number;
  synRatio: number;
  logByteVolume: number;
  showCounterfactual: boolean;
  onToggleForecastMode?: () => void;
  soundEnabled: boolean;
  theme?: AppTheme;
}

export const TrajectoryForecast: React.FC<TrajectoryForecastProps> = ({
  points,
  killChainStages,
  portEntropy,
  synRatio,
  logByteVolume,
  showCounterfactual,
  soundEnabled,
  theme = 'light'
}) => {
  const [hoveredPoint, setHoveredPoint] = useState<ForecastPoint | null>(null);
  const [forecastHorizonWindows, setForecastHorizonWindows] = useState<number>(4);

  const isLight = theme === 'light';
  const isMidnight = theme === 'midnight';

  if (!points || points.length === 0) {
    return (
      <div className={`p-8 rounded-2xl border text-center font-mono text-sm ${
        isLight ? 'bg-white border-slate-200 text-slate-500' : 'bg-[#071329] border-[#142f5c] text-slate-400'
      }`}>
        Connecting to backend world model forecast stream...
      </div>
    );
  }

  // SVG Chart Dimensions (viewBox: 600 x 220)
  const width = 600;
  const height = 220;
  const paddingLeft = 45;
  const paddingRight = 30;
  const paddingTop = 25;
  const paddingBottom = 40;

  const chartW = width - paddingLeft - paddingRight;
  const chartH = height - paddingTop - paddingBottom;

  // X coordinate interpolation for points
  const getX = (index: number) => paddingLeft + (index / (points.length - 1)) * chartW;
  // Y coordinate interpolation (0% at bottom, 100% at top)
  const getY = (val: number) => paddingTop + chartH - (val / 100) * chartH;

  // Find index of 'NOW'
  const nowIndex = points.findIndex((p) => p.isNow);
  const nowX = nowIndex !== -1 ? getX(nowIndex) : getX(4);

  // Build SVG path for Actual / Measured past
  const pastPoints = points.slice(0, nowIndex + 1);
  const pastPath = pastPoints.reduce((acc, p, idx) => {
    const x = getX(idx);
    const y = getY(p.actual ?? p.baseline);
    return idx === 0 ? `M ${x} ${y}` : `${acc} L ${x} ${y}`;
  }, '');

  // Build SVG path for Future Counterfactual (or baseline)
  const futurePoints = points.slice(nowIndex);
  const futureCounterfactualPath = futurePoints.reduce((acc, p, idx) => {
    const actualIdx = nowIndex + idx;
    const x = getX(actualIdx);
    const val = showCounterfactual ? (p.counterfactual ?? p.baseline) : p.baseline;
    const y = getY(val);
    return idx === 0 ? `M ${x} ${y}` : `${acc} L ${x} ${y}`;
  }, '');

  // Confidence Interval Area Polygon for Future
  const ciPointsUpper = futurePoints.map((p, idx) => {
    const actualIdx = nowIndex + idx;
    return `${getX(actualIdx)},${getY(showCounterfactual ? p.ciUpper * 0.7 : p.ciUpper)}`;
  });
  const ciPointsLower = [...futurePoints].reverse().map((p, idx) => {
    const actualIdx = points.length - 1 - idx;
    return `${getX(actualIdx)},${getY(showCounterfactual ? p.ciLower * 0.3 : p.ciLower)}`;
  });
  const ciPolygon = [...ciPointsUpper, ...ciPointsLower].join(' ');

  return (
    <div
      className={`rounded-2xl border backdrop-blur-md shadow-xl overflow-hidden transition-colors ${
        isLight
          ? 'bg-white border-slate-200 text-slate-800'
          : isMidnight
          ? 'bg-[#071329]/95 border-[#142f5c] text-slate-100'
          : 'bg-[#0e1628]/95 border-[#1d2a45] text-slate-100'
      }`}
    >
      {/* 1. Header Bar: Clean, professional SOC presentation (NO AI-slop numbered eyebrow) */}
      <div
        className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-5 sm:px-6 py-4 border-b ${
          isLight
            ? 'bg-slate-50/70 border-slate-200'
            : isMidnight
            ? 'bg-[#050e21] border-[#102344]'
            : 'bg-[#0b1220] border-[#162238]'
        }`}
      >
        <div>
          <div className="flex items-center space-x-2">
            <h3 className={`text-base sm:text-lg font-bold font-sans tracking-tight ${isLight ? 'text-slate-900' : 'text-white'}`}>
              Attack Trajectory Forecast & Infiltration Curve
            </h3>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                showCounterfactual
                  ? isLight
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-300'
                    : 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40'
                  : isLight
                  ? 'bg-rose-50 text-rose-700 border-rose-300'
                  : 'bg-rose-950/80 text-rose-300 border-rose-500/40'
              }`}
            >
              {showCounterfactual ? 'Countermeasure Applied' : 'Unmitigated Threat'}
            </span>
          </div>
          <p className={`text-xs font-sans mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
            Sliding-window graph probability computed over 30-second intervals with 95% confidence intervals.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => {
              if (soundEnabled) playCyberTone('click');
              setForecastHorizonWindows((prev) => (prev === 4 ? 8 : 4));
            }}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold border transition-all ${
              isLight
                ? 'border-cyan-300 bg-cyan-50 text-cyan-800 hover:bg-cyan-100'
                : 'border-cyan-500/30 bg-cyan-950/30 text-cyan-300 hover:bg-cyan-900/50'
            }`}
          >
            <Radio className="w-3.5 h-3.5 text-cyan-500 animate-pulse" />
            <span>Horizon: K = {forecastHorizonWindows} windows ({forecastHorizonWindows * 15}s)</span>
          </button>
        </div>
      </div>

      {/* 2. Sub Legend */}
      <div
        className={`flex flex-wrap items-center justify-between gap-3 px-5 sm:px-6 py-2.5 border-b text-xs font-mono ${
          isLight
            ? 'bg-slate-100/60 border-slate-200 text-slate-600'
            : isMidnight
            ? 'bg-[#040b1a] border-[#0e1d38] text-slate-400'
            : 'bg-[#090e1a] border-[#131d2e] text-slate-400'
        }`}
      >
        <div className="flex flex-wrap items-center gap-4 sm:gap-6">
          <span className="flex items-center space-x-2">
            <span className={`w-3.5 h-1 rounded-full ${isLight ? 'bg-cyan-600' : 'bg-cyan-400'}`} />
            <span className="font-medium">Measured Infiltration History</span>
          </span>
          <span className="flex items-center space-x-2">
            <span
              className={`w-3.5 border-b-2 border-dashed ${
                showCounterfactual ? 'border-emerald-500' : 'border-rose-500'
              }`}
            />
            <span className="font-medium">
              {showCounterfactual ? 'Mitigated Future Path' : 'Projected Infiltration Path'}
            </span>
          </span>
          <span className="flex items-center space-x-1.5">
            <span
              className={`w-3 h-3 rounded-sm border ${
                isLight ? 'bg-cyan-100 border-cyan-300' : 'bg-cyan-950/60 border-cyan-600/40'
              }`}
            />
            <span className="font-medium">95% Confidence Band</span>
          </span>
        </div>

        <div className="flex items-center space-x-1.5 text-slate-500">
          <span>Marker:</span>
          <span className="text-rose-500 font-bold">T = 0s (Current Moment)</span>
        </div>
      </div>

      {/* 3. SVG Chart Area */}
      <div className="relative w-full h-[250px] sm:h-[280px] px-3 sm:px-4 py-2 select-none">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-full" preserveAspectRatio="none">
          <defs>
            <linearGradient id="ciGradientDynamic" x1="0" y1="0" x2="0" y2="1">
              <stop
                offset="0%"
                stopColor={showCounterfactual ? '#10b981' : isLight ? '#0284c7' : '#06b6d4'}
                stopOpacity={isLight ? 0.25 : 0.2}
              />
              <stop
                offset="100%"
                stopColor={showCounterfactual ? '#10b981' : isLight ? '#0284c7' : '#06b6d4'}
                stopOpacity={0.02}
              />
            </linearGradient>
            <linearGradient id="areaGlowDynamic" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={isLight ? '#0284c7' : '#06b6d4'} stopOpacity={isLight ? 0.2 : 0.25} />
              <stop offset="100%" stopColor={isLight ? '#0284c7' : '#06b6d4'} stopOpacity={0} />
            </linearGradient>
          </defs>

          {/* Horizontal Grid lines & Y-axis labels */}
          {[100, 75, 50, 25, 0].map((val) => {
            const y = getY(val);
            return (
              <g key={val}>
                <line
                  x1={paddingLeft}
                  y1={y}
                  x2={width - paddingRight}
                  y2={y}
                  stroke={isLight ? '#e2e8f0' : isMidnight ? '#122649' : '#1e293b'}
                  strokeWidth="1"
                  strokeDasharray="3, 4"
                />
                <text
                  x={paddingLeft - 8}
                  y={y + 3.5}
                  fill={isLight ? '#64748b' : '#94a3b8'}
                  fontSize="9.5"
                  fontFamily="monospace"
                  textAnchor="end"
                >
                  {val}%
                </text>
              </g>
            );
          })}

          {/* Vertical 'NOW' line */}
          <line
            x1={nowX}
            y1={paddingTop}
            x2={nowX}
            y2={height - paddingBottom}
            stroke="#f43f5e"
            strokeWidth="1.5"
            strokeDasharray="4, 4"
            opacity="0.9"
          />

          {/* NOW Label at top */}
          <text
            x={nowX}
            y={paddingTop - 7}
            fill="#f43f5e"
            fontSize="9"
            fontWeight="bold"
            fontFamily="monospace"
            textAnchor="middle"
          >
            CURRENT MOMENT
          </text>

          {/* Confidence Interval Polygon */}
          <polygon points={ciPolygon} fill="url(#ciGradientDynamic)" />

          {/* Past Area fill */}
          <path
            d={`${pastPath} L ${nowX} ${getY(0)} L ${getX(0)} ${getY(0)} Z`}
            fill="url(#areaGlowDynamic)"
          />

          {/* Past Curve (Solid high-contrast line) */}
          <path
            d={pastPath}
            fill="none"
            stroke={isLight ? '#0284c7' : '#38bdf8'}
            strokeWidth="3"
            strokeLinecap="round"
          />

          {/* Future Projected Curve */}
          <path
            d={futureCounterfactualPath}
            fill="none"
            stroke={showCounterfactual ? '#10b981' : '#f43f5e'}
            strokeWidth="2.5"
            strokeDasharray={showCounterfactual ? 'none' : '5, 4'}
            strokeLinecap="round"
          />

          {/* Data Points */}
          {points.map((p, idx) => {
            const x = getX(idx);
            const val =
              idx <= nowIndex
                ? (p.actual ?? p.baseline)
                : showCounterfactual
                ? (p.counterfactual ?? p.baseline)
                : p.baseline;
            const y = getY(val);
            const isHovered = hoveredPoint?.timeLabel === p.timeLabel;

            return (
              <g
                key={p.timeLabel}
                className="cursor-pointer"
                onMouseEnter={() => setHoveredPoint(p)}
                onMouseLeave={() => setHoveredPoint(null)}
              >
                {/* Node Circle */}
                <circle
                  cx={x}
                  cy={y}
                  r={p.isNow ? 5.5 : isHovered ? 5 : 3}
                  fill={p.isNow ? '#f43f5e' : showCounterfactual && idx > nowIndex ? '#10b981' : isLight ? '#0284c7' : '#38bdf8'}
                  stroke={isLight ? '#ffffff' : '#071329'}
                  strokeWidth={2}
                />

                {/* X-axis labels */}
                <text
                  x={x}
                  y={height - paddingBottom + 18}
                  fill={p.isNow ? '#f43f5e' : isLight ? '#475569' : '#94a3b8'}
                  fontSize="10"
                  fontWeight={p.isNow ? 'bold' : 'normal'}
                  fontFamily="monospace"
                  textAnchor="middle"
                >
                  {p.timeLabel}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Hover Tooltip */}
        {hoveredPoint && (
          <div
            className={`absolute top-3 right-6 rounded-xl p-3 text-xs font-mono shadow-2xl border pointer-events-none transition-all ${
              isLight
                ? 'bg-white/95 border-slate-300 text-slate-800'
                : 'bg-slate-900/95 border-slate-700 text-slate-100'
            }`}
          >
            <div className="flex items-center space-x-2">
              <span className="text-slate-400">Window:</span>
              <span className="font-bold">{hoveredPoint.timeLabel}</span>
            </div>
            <div className="mt-1 flex items-center space-x-2">
              <span className="text-slate-400">Risk Score:</span>
              <span
                className={`font-bold text-sm ${
                  showCounterfactual && !hoveredPoint.isNow ? 'text-emerald-500' : 'text-rose-500'
                }`}
              >
                {hoveredPoint.isNow
                  ? `${hoveredPoint.actual}% (Active Threat)`
                  : showCounterfactual
                  ? `${hoveredPoint.counterfactual}% (Counterfactual Mitigated)`
                  : `${hoveredPoint.baseline}% (Projected Attack)`}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* 4. Telemetry Sensor Metric Cards Underneath Chart */}
      <div
        className={`grid grid-cols-1 sm:grid-cols-3 gap-3 p-4 sm:p-5 border-t ${
          isLight
            ? 'bg-slate-50/80 border-slate-200'
            : isMidnight
            ? 'bg-[#050e21] border-[#102344]'
            : 'bg-[#0a111e] border-[#16233a]'
        }`}
      >
        {/* PORT ENTROPY */}
        <div
          className={`p-3.5 rounded-xl border ${
            isLight
              ? 'bg-white border-slate-200 shadow-2xs'
              : 'bg-slate-900/60 border-slate-800'
          }`}
        >
          <div className="text-[11px] font-mono tracking-wider text-slate-400 uppercase font-semibold">
            Destination Port Entropy
          </div>
          <div className="flex items-baseline justify-between mt-1">
            <span className={`text-2xl font-bold font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
              {portEntropy.toFixed(1)}
            </span>
            <span className="text-xs font-mono font-bold text-rose-500">
              High Dispersal (+0.8)
            </span>
          </div>
          <p className="text-[11px] text-slate-500 font-sans mt-0.5">
            Rapid scanning across ephemeral and privileged ports
          </p>
        </div>

        {/* SYN RATIO */}
        <div
          className={`p-3.5 rounded-xl border ${
            isLight
              ? 'bg-white border-slate-200 shadow-2xs'
              : 'bg-slate-900/60 border-slate-800'
          }`}
        >
          <div className="text-[11px] font-mono tracking-wider text-slate-400 uppercase font-semibold">
            SYN / ACK Asymmetry Ratio
          </div>
          <div className="flex items-baseline justify-between mt-1">
            <span className={`text-2xl font-bold font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
              {synRatio.toFixed(2)}
            </span>
            <span className="text-xs font-mono font-bold text-amber-500">
              Unanswered SYNs (+0.21)
            </span>
          </div>
          <p className="text-[11px] text-slate-500 font-sans mt-0.5">
            Anomalous connection requests without handshake completion
          </p>
        </div>

        {/* LOG BYTE VOLUME */}
        <div
          className={`p-3.5 rounded-xl border ${
            isLight
              ? 'bg-white border-slate-200 shadow-2xs'
              : 'bg-slate-900/60 border-slate-800'
          }`}
        >
          <div className="text-[11px] font-mono tracking-wider text-slate-400 uppercase font-semibold">
            Log Byte Volume (MB/s)
          </div>
          <div className="flex items-baseline justify-between mt-1">
            <span className={`text-2xl font-bold font-mono ${isLight ? 'text-slate-900' : 'text-white'}`}>
              {logByteVolume.toFixed(1)}
            </span>
            <span className="text-xs font-mono font-bold text-emerald-500">
              Baseline In-Range
            </span>
          </div>
          <p className="text-[11px] text-slate-500 font-sans mt-0.5">
            Network pipe throughput steady, payload concentrated in small commands
          </p>
        </div>
      </div>

      {/* 5. Kill Chain Progress Timeline (Real SOC Stages) */}
      <div
        className={`p-5 sm:p-6 border-t ${
          isLight
            ? 'bg-white border-slate-200'
            : isMidnight
            ? 'bg-[#071329] border-[#12284c]'
            : 'bg-[#0d1627] border-[#19273f]'
        }`}
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
          <div>
            <h4 className={`text-sm font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
              MITRE ATT&CK Kill Chain Traversal
            </h4>
            <p className={`text-xs font-sans ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
              Track attacker advancement through organizational network stages
            </p>
          </div>

          <span
            className={`self-start sm:self-auto px-2.5 py-1 rounded-full text-xs font-mono font-bold border ${
              isLight
                ? 'bg-amber-50 text-amber-800 border-amber-300'
                : 'bg-amber-950/80 text-amber-300 border-amber-500/40'
            }`}
          >
            Active Stage: Lateral Movement
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 pt-2">
          {killChainStages.map((st) => {
            const isCompleted = st.status === 'completed';
            const isActive = st.status === 'active';

            return (
              <div
                key={st.step}
                className={`p-3 rounded-xl border transition-all ${
                  isCompleted
                    ? isLight
                      ? 'bg-emerald-50/70 border-emerald-300 text-slate-800'
                      : 'bg-emerald-950/30 border-emerald-600/40 text-slate-200'
                    : isActive
                    ? isLight
                      ? 'bg-amber-50 border-amber-400 text-slate-900 shadow-sm ring-1 ring-amber-400/50'
                      : 'bg-amber-950/40 border-amber-500 text-white shadow-md ring-1 ring-amber-500/50'
                    : isLight
                    ? 'bg-slate-50 border-slate-200 text-slate-400'
                    : 'bg-slate-900/40 border-slate-800 text-slate-500'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono font-bold uppercase">
                    Stage 0{st.step}
                  </span>
                  <div
                    className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ${
                      isCompleted
                        ? 'bg-emerald-500 text-white'
                        : isActive
                        ? 'bg-amber-500 text-white animate-pulse'
                        : 'bg-slate-300 dark:bg-slate-700 text-slate-600 dark:text-slate-400'
                    }`}
                  >
                    {isCompleted ? <Check className="w-3 h-3 stroke-[3]" /> : st.step}
                  </div>
                </div>

                <div className="mt-2">
                  <div
                    className={`text-xs font-bold font-sans ${
                      isActive
                        ? isLight
                          ? 'text-amber-900'
                          : 'text-amber-300'
                        : isCompleted
                        ? isLight
                          ? 'text-emerald-900'
                          : 'text-emerald-300'
                        : isLight
                        ? 'text-slate-600'
                        : 'text-slate-400'
                    }`}
                  >
                    {st.name}
                  </div>
                  <span className="text-[10px] font-mono text-slate-400">
                    {st.tacticId}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

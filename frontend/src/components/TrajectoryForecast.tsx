import React, { useState } from 'react';
import { Radio, Check, TrendingUp } from 'lucide-react';
import { ForecastPoint, KillChainStage } from '../types';
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
}

export const TrajectoryForecast: React.FC<TrajectoryForecastProps> = ({
  points,
  killChainStages,
  portEntropy,
  synRatio,
  logByteVolume,
  showCounterfactual,
  soundEnabled
}) => {
  const [hoveredPoint, setHoveredPoint] = useState<ForecastPoint | null>(null);
  const [forecastHorizonWindows, setForecastHorizonWindows] = useState<number>(4);

  // SVG Chart Dimensions (viewBox: 600 x 240)
  const width = 600;
  const height = 210;
  const paddingLeft = 45;
  const paddingRight = 30;
  const paddingTop = 20;
  const paddingBottom = 35;

  const chartW = width - paddingLeft - paddingRight;
  const chartH = height - paddingTop - paddingBottom;

  // X coordinate interpolation for points (9 points from index 0 to 8)
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
    return `${getX(actualIdx)},${getY(showCounterfactual ? (p.ciUpper * 0.7) : p.ciUpper)}`;
  });
  const ciPointsLower = [...futurePoints].reverse().map((p, idx) => {
    const actualIdx = points.length - 1 - idx;
    return `${getX(actualIdx)},${getY(showCounterfactual ? (p.ciLower * 0.3) : p.ciLower)}`;
  });
  const ciPolygon = [...ciPointsUpper, ...ciPointsLower].join(' ');

  return (
    <div className="flex flex-col rounded-xl border border-[#142d54] bg-[#061126]/90 overflow-hidden backdrop-blur-md">
      {/* Header */}
      <div className="flex items-center justify-between px-4 sm:px-5 py-3.5 border-b border-[#12284c] bg-[#08152e]/70">
        <div>
          <div className="text-[11px] font-mono tracking-wider text-slate-400">
            02 <span className="text-slate-600">/</span> FUTURE STATE
          </div>
          <h3 className="text-base sm:text-lg font-bold text-white tracking-tight">
            Trajectory forecast
          </h3>
        </div>

        <button
          onClick={() => {
            if (soundEnabled) playCyberTone('click');
            setForecastHorizonWindows((prev) => (prev === 4 ? 8 : 4));
          }}
          className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full border border-emerald-500/30 bg-emerald-950/20 text-emerald-400 text-xs font-mono font-semibold hover:bg-emerald-950/40 transition-colors"
        >
          <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
          <span>K = {forecastHorizonWindows} windows</span>
        </button>
      </div>

      {/* Sub legend */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 sm:px-5 py-2 bg-[#050e20] border-b border-[#102344] text-[11px] font-mono text-slate-400">
        <div className="flex items-center space-x-4">
          <span className="flex items-center space-x-1.5">
            <span className="w-4 h-0.5 bg-cyan-400" />
            <span>Infiltration probability</span>
          </span>
          <span className="flex items-center space-x-1.5">
            <span className="w-4 border-b border-dashed border-rose-400" />
            <span>Forecast horizon</span>
          </span>
        </div>
        <span className="text-slate-500">95% CI</span>
      </div>

      {/* SVG Chart Area */}
      <div className="relative w-full h-[220px] px-2 py-1 select-none">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-full"
          preserveAspectRatio="none"
        >
          <defs>
            <linearGradient id="ciGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.04" />
            </linearGradient>
            <linearGradient id="areaGlow" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.3" />
              <stop offset="100%" stopColor="#00f0ff" stopOpacity="0" />
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
                  stroke="#102344"
                  strokeWidth="1"
                  strokeDasharray="2, 4"
                />
                <text
                  x={paddingLeft - 8}
                  y={y + 3}
                  fill="#64748b"
                  fontSize="9"
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
            strokeDasharray="3, 3"
            opacity="0.85"
          />

          {/* Confidence Interval Polygon */}
          <polygon points={ciPolygon} fill="url(#ciGradient)" />

          {/* Past Curve (Bright cyan solid line) */}
          <path
            d={pastPath}
            fill="none"
            stroke="#00f0ff"
            strokeWidth="3"
            strokeLinecap="round"
          />

          {/* Past Area fill */}
          <path
            d={`${pastPath} L ${nowX} ${getY(0)} L ${getX(0)} ${getY(0)} Z`}
            fill="url(#areaGlow)"
          />

          {/* Future Projected Curve */}
          <path
            d={futureCounterfactualPath}
            fill="none"
            stroke={showCounterfactual ? '#00f0ff' : '#f43f5e'}
            strokeWidth="2.5"
            strokeDasharray={showCounterfactual ? 'none' : '4, 4'}
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
                  r={p.isNow ? 5 : isHovered ? 4 : 2.5}
                  fill={p.isNow ? '#f43f5e' : '#00f0ff'}
                  stroke="#071329"
                  strokeWidth={2}
                />

                {/* X-axis labels */}
                <text
                  x={x}
                  y={height - paddingBottom + 16}
                  fill={p.isNow ? '#f43f5e' : '#64748b'}
                  fontSize="9"
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
          <div className="absolute top-2 right-4 bg-[#08152e] border border-cyan-500/40 rounded px-2.5 py-1 text-[11px] font-mono text-cyan-200 shadow-xl pointer-events-none">
            <span>{hoveredPoint.timeLabel}: </span>
            <span className="font-bold text-white">
              {hoveredPoint.isNow
                ? `${hoveredPoint.actual}% (Current Threat)`
                : showCounterfactual
                ? `${hoveredPoint.counterfactual}% (Counterfactual)`
                : `${hoveredPoint.baseline}% (Projected Unmitigated)`}
            </span>
          </div>
        )}
      </div>

      {/* 3 Metric Pills below chart */}
      <div className="grid grid-cols-3 gap-2 px-4 sm:px-5 py-3 bg-[#050e20] border-t border-[#102344]">
        {/* PORT ENTROPY */}
        <div className="space-y-0.5">
          <div className="text-[10px] font-mono tracking-wider text-slate-500 uppercase">
            Port Entropy
          </div>
          <div className="flex items-baseline space-x-1.5">
            <span className="text-base sm:text-lg font-bold font-mono text-white">
              {portEntropy.toFixed(1)}
            </span>
            <span className="text-[11px] font-mono font-semibold text-rose-400">
              ↗ 0.8
            </span>
          </div>
        </div>

        {/* SYN RATIO */}
        <div className="space-y-0.5">
          <div className="text-[10px] font-mono tracking-wider text-slate-500 uppercase">
            SYN Ratio
          </div>
          <div className="flex items-baseline space-x-1.5">
            <span className="text-base sm:text-lg font-bold font-mono text-white">
              {synRatio.toFixed(2)}
            </span>
            <span className="text-[11px] font-mono font-semibold text-rose-400">
              ↗ 0.21
            </span>
          </div>
        </div>

        {/* LOG BYTE VOLUME */}
        <div className="space-y-0.5">
          <div className="text-[10px] font-mono tracking-wider text-slate-500 uppercase">
            Log Byte Volume
          </div>
          <div className="flex items-baseline space-x-1.5">
            <span className="text-base sm:text-lg font-bold font-mono text-white">
              {logByteVolume.toFixed(1)}
            </span>
            <span className="text-[11px] font-mono text-slate-400">
              stable
            </span>
          </div>
        </div>
      </div>

      {/* Kill Chain Progress Timeline (Steps 1 to 7) */}
      <div className="px-4 sm:px-5 py-3.5 bg-[#071329]/60 border-t border-[#102344]">
        <div className="relative flex items-center justify-between">
          {/* Connecting background track */}
          <div className="absolute left-3 right-3 top-1/2 -translate-y-1/2 h-0.5 bg-[#12284c] z-0" />

          {killChainStages.map((st) => {
            const isCompleted = st.status === 'completed';
            const isActive = st.status === 'active';

            return (
              <div
                key={st.step}
                className="relative z-10 flex flex-col items-center group cursor-pointer"
                title={`${st.step}. ${st.name} (${st.tacticId})`}
              >
                {/* Circle badge */}
                <div
                  className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold font-mono transition-all ${
                    isCompleted
                      ? 'bg-emerald-950 border border-emerald-500 text-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.3)]'
                      : isActive
                      ? 'bg-amber-950 border-2 border-amber-400 text-amber-300 shadow-[0_0_12px_rgba(245,158,11,0.5)] ring-2 ring-amber-500/30'
                      : 'bg-[#08152e] border border-[#163868] text-slate-500'
                  }`}
                >
                  {isCompleted ? (
                    <Check className="w-3.5 h-3.5 stroke-[2.5]" />
                  ) : (
                    <span>{st.step}</span>
                  )}
                </div>

                {/* Stage name label */}
                <span
                  className={`mt-1.5 text-[10px] font-mono tracking-tight transition-colors whitespace-nowrap ${
                    isActive
                      ? 'text-amber-400 font-bold'
                      : isCompleted
                      ? 'text-slate-300'
                      : 'text-slate-600'
                  }`}
                >
                  {st.name}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

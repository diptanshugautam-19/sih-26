import React from 'react';
import { Gauge, ArrowUpRight, Target, Database } from 'lucide-react';

interface MetricCardsProps {
  infiltrationRisk: number;
  riskTrend: string;
  leadTime: string;
  leadTimeDelta: string;
  predictedStage: string;
  mitreTactic: string;
  modelConfidence: number;
  uncertainty: number;
}

export const MetricCards: React.FC<MetricCardsProps> = ({
  infiltrationRisk,
  riskTrend,
  leadTime,
  leadTimeDelta,
  predictedStage,
  mitreTactic,
  modelConfidence,
  uncertainty
}) => {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 sm:gap-4 my-3">
      {/* 1. Infiltration risk */}
      <div className="relative overflow-hidden rounded-xl border border-[#142d54] bg-[#071329]/80 p-4 sm:p-5 backdrop-blur-sm group hover:border-rose-500/40 transition-colors">
        <div className="flex items-start space-x-3.5">
          <div className="p-2.5 rounded-lg border border-rose-500/30 bg-rose-950/20 text-rose-400">
            <Gauge className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <span className="text-xs font-mono tracking-wider text-slate-400 uppercase">
              Infiltration risk
            </span>
            <div className="text-3xl sm:text-4xl font-extrabold font-mono text-rose-500 drop-shadow-[0_0_12px_rgba(244,63,94,0.35)]">
              {infiltrationRisk}%
            </div>
            <div className="flex items-center space-x-1.5 text-xs font-mono text-rose-400">
              <span className="font-bold">+{riskTrend}%</span>
              <span>Attack imminent</span>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Proactive lead-time */}
      <div className="relative overflow-hidden rounded-xl border border-[#142d54] bg-[#071329]/80 p-4 sm:p-5 backdrop-blur-sm group hover:border-cyan-500/40 transition-colors">
        <div className="flex items-start space-x-3.5">
          <div className="p-2.5 rounded-lg border border-cyan-500/30 bg-cyan-950/20 text-cyan-400">
            <ArrowUpRight className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <span className="text-xs font-mono tracking-wider text-slate-400 uppercase">
              Proactive lead-time
            </span>
            <div className="text-3xl sm:text-4xl font-extrabold font-mono text-slate-100">
              {leadTime}
            </div>
            <div className="flex items-center space-x-1.5 text-xs font-mono text-cyan-400">
              <span className="font-bold">{leadTimeDelta}</span>
              <span>vs reactive baseline</span>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Predicted stage */}
      <div className="relative overflow-hidden rounded-xl border border-[#142d54] bg-[#071329]/80 p-4 sm:p-5 backdrop-blur-sm group hover:border-amber-500/40 transition-colors">
        <div className="flex items-start space-x-3.5">
          <div className="p-2.5 rounded-lg border border-amber-500/30 bg-amber-950/20 text-amber-400">
            <Target className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <span className="text-xs font-mono tracking-wider text-slate-400 uppercase">
              Predicted stage
            </span>
            <div className="text-2xl sm:text-3xl font-extrabold font-sans text-amber-400">
              {predictedStage}
            </div>
            <div className="text-xs font-mono text-slate-400">
              {mitreTactic}
            </div>
          </div>
        </div>
      </div>

      {/* 4. Model confidence */}
      <div className="relative overflow-hidden rounded-xl border border-[#142d54] bg-[#071329]/80 p-4 sm:p-5 backdrop-blur-sm group hover:border-emerald-500/40 transition-colors">
        <div className="flex items-start space-x-3.5">
          <div className="p-2.5 rounded-lg border border-emerald-500/30 bg-emerald-950/20 text-emerald-400">
            <Database className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <span className="text-xs font-mono tracking-wider text-slate-400 uppercase">
              Model confidence
            </span>
            <div className="text-3xl sm:text-4xl font-extrabold font-mono text-emerald-400 drop-shadow-[0_0_12px_rgba(16,185,129,0.3)]">
              {modelConfidence}%
            </div>
            <div className="flex items-center space-x-1.5 text-xs font-mono text-slate-400">
              <span className="text-rose-400 font-semibold">stable</span>
              <span>Uncertainty ± {uncertainty}%</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

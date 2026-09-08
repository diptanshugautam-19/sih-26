import React from 'react';
import { Gauge, ArrowUpRight, Target, Database } from 'lucide-react';
import { AppTheme } from '../types';

interface MetricCardsProps {
  infiltrationRisk: number;
  riskTrend: string;
  leadTime: string;
  leadTimeDelta: string;
  predictedStage: string;
  mitreTactic: string;
  modelConfidence: number;
  uncertainty: number;
  theme?: AppTheme;
}

export const MetricCards: React.FC<MetricCardsProps> = ({
  infiltrationRisk,
  riskTrend,
  leadTime,
  leadTimeDelta,
  predictedStage,
  mitreTactic,
  modelConfidence,
  uncertainty,
  theme = 'light'
}) => {
  const isLight = theme === 'light';

  const cardBaseClass = `relative overflow-hidden rounded-xl border p-4 sm:p-5 backdrop-blur-sm transition-all ${
    isLight
      ? 'bg-white border-slate-200 shadow-sm hover:border-slate-300'
      : theme === 'midnight'
      ? 'bg-[#071329]/80 border-[#142d54] hover:border-slate-600'
      : 'bg-slate-800/90 border-slate-700/70 shadow-lg hover:border-slate-600'
  }`;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 sm:gap-4 my-3">
      {/* 1. Infiltration risk */}
      <div className={cardBaseClass}>
        <div className="flex items-start space-x-3.5">
          <div className={`p-2.5 rounded-lg border ${
            isLight
              ? 'border-rose-200 bg-rose-50 text-rose-600'
              : 'border-rose-500/30 bg-rose-950/30 text-rose-400'
          }`}>
            <Gauge className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className={`text-xs font-mono tracking-wider uppercase ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                Danger Level
              </span>
              <span className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold border ${
                isLight ? 'bg-rose-100 text-rose-700 border-rose-200' : 'bg-rose-950 text-rose-300 border-rose-500/30'
              }`}>
                CRITICAL
              </span>
            </div>
            <div className="text-3xl sm:text-4xl font-extrabold font-mono text-rose-500">
              {infiltrationRisk}%
            </div>
            <p className={`text-[11px] font-sans ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
              Likelihood the hacker breaches the next computer
            </p>
          </div>
        </div>
      </div>

      {/* 2. Proactive lead-time */}
      <div className={cardBaseClass}>
        <div className="flex items-start space-x-3.5">
          <div className={`p-2.5 rounded-lg border ${
            isLight
              ? 'border-cyan-200 bg-cyan-50 text-cyan-600'
              : 'border-cyan-500/30 bg-cyan-950/30 text-cyan-400'
          }`}>
            <ArrowUpRight className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className={`text-xs font-mono tracking-wider uppercase ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                Time to React
              </span>
              <span className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold border ${
                isLight ? 'bg-cyan-100 text-cyan-800 border-cyan-200' : 'bg-cyan-950 text-cyan-300 border-cyan-500/30'
              }`}>
                COUNTDOWN
              </span>
            </div>
            <div className={`text-3xl sm:text-4xl font-extrabold font-mono ${isLight ? 'text-slate-900' : 'text-slate-100'}`}>
              {leadTime}
            </div>
            <p className={`text-[11px] font-sans ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
              Estimated seconds left before hacker strikes target
            </p>
          </div>
        </div>
      </div>

      {/* 3. Predicted stage */}
      <div className={cardBaseClass}>
        <div className="flex items-start space-x-3.5">
          <div className={`p-2.5 rounded-lg border ${
            isLight
              ? 'border-amber-200 bg-amber-50 text-amber-600'
              : 'border-amber-500/30 bg-amber-950/30 text-amber-400'
          }`}>
            <Target className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className={`text-xs font-mono tracking-wider uppercase ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                Current Attack Step
              </span>
            </div>
            <div className={`text-xl sm:text-2xl font-bold font-sans ${isLight ? 'text-amber-700' : 'text-amber-300'}`}>
              Spreading Sideways
            </div>
            <p className={`text-[11px] font-sans ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
              {mitreTactic} (jumping between internal computers)
            </p>
          </div>
        </div>
      </div>

      {/* 4. Model confidence */}
      <div className={cardBaseClass}>
        <div className="flex items-start space-x-3.5">
          <div className={`p-2.5 rounded-lg border ${
            isLight
              ? 'border-emerald-200 bg-emerald-50 text-emerald-600'
              : 'border-emerald-500/30 bg-emerald-950/30 text-emerald-400'
          }`}>
            <Database className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className={`text-xs font-mono tracking-wider uppercase ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                AI Accuracy
              </span>
              <span className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold border ${
                isLight ? 'bg-emerald-100 text-emerald-800 border-emerald-200' : 'bg-emerald-950 text-emerald-300 border-emerald-500/30'
              }`}>
                CONFIRMED
              </span>
            </div>
            <div className="text-3xl sm:text-4xl font-extrabold font-mono text-emerald-500">
              {modelConfidence}%
            </div>
            <p className={`text-[11px] font-sans ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
              Reliability score calculated from live packet flows
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

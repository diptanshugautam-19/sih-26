import React from 'react';
import { RefreshCw, Zap } from 'lucide-react';
import { playCyberTone } from '../utils/audio';

interface HeroSectionProps {
  sequence: number;
  isRefreshing: boolean;
  onRefreshModel: () => void;
  onRunCounterfactual: () => void;
  soundEnabled: boolean;
}

export const HeroSection: React.FC<HeroSectionProps> = ({
  sequence,
  isRefreshing,
  onRefreshModel,
  onRunCounterfactual,
  soundEnabled
}) => {
  return (
    <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pt-4 pb-2">
      <div className="space-y-1.5">
        {/* Eyebrow status */}
        <div className="flex items-center space-x-2 text-xs font-mono tracking-wider text-slate-400">
          <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399] animate-pulse" />
          <span className="text-emerald-400 font-semibold">MODEL STATUS</span>
          <span className="text-slate-600">/</span>
          <span>INFERENCE RUNNING</span>
        </div>

        {/* Title */}
        <h2 className="text-2xl sm:text-3xl md:text-4xl font-extrabold tracking-tight text-white font-sans">
          Defence <span className="text-cyan-400 drop-shadow-[0_0_15px_rgba(6,182,212,0.4)]">cockpit</span>
        </h2>

        {/* Subtitle */}
        <p className="text-xs sm:text-sm font-mono text-slate-400">
          Proactive network state intelligence <span className="text-slate-600">·</span> sequence {sequence} / 5 windows
        </p>
      </div>

      {/* Action buttons */}
      <div className="flex items-center space-x-3">
        <button
          onClick={() => {
            if (soundEnabled) playCyberTone('click');
            onRefreshModel();
          }}
          disabled={isRefreshing}
          className="flex items-center space-x-2 px-4 py-2.5 rounded-lg border border-[#17386c] bg-[#071329] hover:bg-[#0c234a] hover:border-cyan-500/40 text-slate-200 hover:text-white text-xs sm:text-sm font-mono transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span>Refresh model</span>
        </button>

        <button
          onClick={() => {
            if (soundEnabled) playCyberTone('sim');
            onRunCounterfactual();
          }}
          className="flex items-center space-x-2 px-4 sm:px-5 py-2.5 rounded-lg bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs sm:text-sm font-mono shadow-[0_0_20px_rgba(6,182,212,0.45)] hover:shadow-[0_0_25px_rgba(6,182,212,0.65)] transition-all transform active:scale-98"
        >
          <Zap className="w-4 h-4 fill-slate-950" />
          <span>Run counterfactual</span>
        </button>
      </div>
    </div>
  );
};

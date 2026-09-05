import React, { useState } from 'react';
import { ChevronRight, Cpu, Activity, ShieldAlert, X, ArrowRight, Layers } from 'lucide-react';
import { FeatureImportance, NetworkEdge, SourceExplainabilityProfile } from '../types';
import { playCyberTone } from '../utils/audio';

interface ExplainabilitySectionProps {
  features: FeatureImportance[];
  edges: NetworkEdge[];
  selectedEdge?: NetworkEdge | null;
  onSelectEdge: (edge: NetworkEdge) => void;
  profile?: SourceExplainabilityProfile | null;
  onSelectSource?: (sourceId: string) => void;
  soundEnabled: boolean;
}

export const ExplainabilitySection: React.FC<ExplainabilitySectionProps> = ({
  features,
  edges,
  selectedEdge,
  onSelectEdge,
  profile,
  onSelectSource,
  soundEnabled
}) => {
  const [showAttentionModal, setShowAttentionModal] = useState(false);

  // Group unique sources from edges
  const sourceIds: string[] = Array.from(new Set(edges.map((e) => e.source)));

  return (
    <div className="flex flex-col rounded-xl border border-[#142d54] bg-[#061126]/90 overflow-hidden backdrop-blur-md my-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-4 sm:px-6 py-3.5 border-b border-[#12284c] bg-[#08152e]/70">
        <div>
          <div className="text-[11px] font-mono tracking-wider text-slate-400">
            04 <span className="text-slate-600">/</span> EXPLAINABILITY & SOURCE VECTORS
          </div>
          <h3 className="text-base sm:text-lg font-bold text-white tracking-tight flex items-center space-x-2">
            <span>Why is the model alerting?</span>
            {profile && (
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-rose-950/80 border border-rose-600/40 text-rose-300">
                SOURCE: {profile.sourceName}
              </span>
            )}
          </h3>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => {
              if (soundEnabled) playCyberTone('click');
              setShowAttentionModal(true);
            }}
            disabled={!profile || !selectedEdge}
            className="flex items-center space-x-1 text-xs sm:text-sm font-mono text-cyan-400 hover:text-cyan-300 font-semibold transition-colors group disabled:opacity-40"
          >
            <span>View attention matrix</span>
            <ChevronRight className="w-4 h-4 transform group-hover:translate-x-0.5 transition-transform" />
          </button>
        </div>
      </div>

      {!profile || !selectedEdge || features.length === 0 ? (
        <div className="flex flex-col items-center justify-center p-10 text-center">
          <div className="p-3.5 rounded-xl border border-cyan-500/20 bg-cyan-950/20 mb-3 text-cyan-400">
            <Cpu className="w-8 h-8 animate-pulse text-cyan-400/80" />
          </div>
          <h4 className="text-slate-200 font-mono font-bold text-sm tracking-wider uppercase">
            No Explainability Attribution Data
          </h4>
          <p className="text-slate-400 text-xs font-mono max-w-sm mt-1.5 leading-relaxed">
            Spatial GAT attention weights and feature salience will compute dynamically once telemetry flows are loaded.
          </p>
        </div>
      ) : (
        <>
          {/* Source Host Quick Selector Bar */}
          <div className="px-4 sm:px-6 py-2.5 bg-[#050e21] border-b border-[#0f244a] flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
            <div className="flex items-center space-x-2">
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
                Attack Source:
              </span>
              <div className="flex flex-wrap items-center gap-1.5">
                {sourceIds.map((srcId) => {
                  const isSelected = selectedEdge.source === srcId;
                  const matchingEdge = edges.find((e) => e.source === srcId) || edges[0];
                  return (
                    <button
                      key={srcId}
                      onClick={() => {
                        if (soundEnabled) playCyberTone('click');
                        if (onSelectSource) onSelectSource(srcId);
                        else onSelectEdge(matchingEdge);
                      }}
                      className={`px-2.5 py-1 rounded text-[11px] font-mono font-bold transition-all ${
                        isSelected
                          ? 'bg-rose-500 text-slate-950 shadow-[0_0_10px_rgba(244,63,94,0.4)] ring-1 ring-rose-300'
                          : 'bg-[#081733] text-slate-300 border border-[#143261] hover:border-cyan-500/50 hover:text-white'
                      }`}
                    >
                      {srcId.toUpperCase()}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Current Active Vector Path indicator */}
            <div className="flex items-center space-x-2 text-[11px] font-mono text-slate-300">
              <span className="text-slate-500">Active Path:</span>
              <span className="text-rose-400 font-bold">{selectedEdge.source.toUpperCase()}</span>
              <ArrowRight className="w-3 h-3 text-cyan-400" />
              <span className="text-amber-400 font-bold">{selectedEdge.target.toUpperCase()}</span>
              <span className="text-slate-500">({selectedEdge.protocol} :{selectedEdge.port})</span>
            </div>
          </div>

      {/* Narrative Alert Summary */}
      {profile && (
        <div className="mx-4 sm:mx-6 mt-4 p-3 rounded-lg border border-cyan-500/20 bg-[#071735]/60 text-xs font-mono flex items-start space-x-3">
          <ShieldAlert className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <div className="space-y-0.5">
            <span className="text-cyan-300 font-bold">Source Vector Diagnosis: </span>
            <span className="text-slate-300 font-sans">{profile.summary}</span>
          </div>
        </div>
      )}

      {/* Main Content: Left feature importance bars + Right Spatial Attention card */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 p-4 sm:p-6 items-center">
        {/* Left: 4 Feature ranking bars (Span 8 columns on lg) */}
        <div className="lg:col-span-8 space-y-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 pb-1 border-b border-[#0f244a]">
            <span>Contributing telemetry features from {selectedEdge.source.toUpperCase()}</span>
            <span>SHAP / GNN weight</span>
          </div>

          {features.map((feat, index) => {
            const numStr = String(index + 1).padStart(2, '0');
            const isHigh = feat.severity === 'high';
            return (
              <div key={feat.id} className="space-y-1.5 font-mono">
                <div className="flex items-baseline justify-between text-xs">
                  <div className="flex items-baseline space-x-3">
                    <span className="text-slate-500 font-semibold text-[11px]">{numStr}</span>
                    <span className="text-slate-100 font-bold">{feat.code}</span>
                    <span className="text-slate-400 text-[11px] hidden sm:inline">{feat.label}</span>
                  </div>
                  <span className={isHigh ? 'text-rose-400 font-bold' : 'text-amber-400 font-bold'}>
                    +{feat.percentage}%
                  </span>
                </div>

                {/* Animated Horizontal Progress Bar */}
                <div className="relative h-2.5 w-full rounded-full bg-[#0c1d38] overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-700 ${
                      isHigh
                        ? 'bg-gradient-to-r from-amber-500 via-rose-500 to-rose-400 shadow-[0_0_8px_rgba(244,63,94,0.4)]'
                        : 'bg-gradient-to-r from-cyan-600 to-cyan-400'
                    }`}
                    style={{ width: `${Math.min(100, feat.percentage * 2)}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>

        {/* Right: Spatial Attention Orbit Card (Span 4 columns on lg) */}
        <div className="lg:col-span-4 rounded-xl border border-[#143261] bg-[#07152f]/70 p-5 flex flex-col items-center justify-center text-center relative overflow-hidden group">
          {/* Subtle animated orbital rings behind icon */}
          <div className="relative flex items-center justify-center w-24 h-24 my-2">
            {/* Outer spinning ring */}
            <div className="absolute inset-0 rounded-full border border-cyan-500/20 animate-spin" style={{ animationDuration: '10s' }} />
            {/* Middle orbital ellipse */}
            <div className="absolute inset-2 rounded-full border border-cyan-400/40 rotate-45 animate-pulse" />
            <div className="absolute inset-2 rounded-full border border-cyan-400/40 -rotate-45" />

            {/* Center pulsing pulse waveform */}
            <div className="relative z-10 flex items-center justify-center w-12 h-12 rounded-full bg-cyan-950/80 border border-cyan-400 text-cyan-300 shadow-[0_0_15px_rgba(6,182,212,0.5)]">
              <Activity className="w-6 h-6 animate-pulse" />
            </div>
          </div>

          <h4 className="text-sm font-bold text-white font-sans mt-2">
            Spatial attention
          </h4>
          <p className="text-xs font-mono text-cyan-300 font-bold mt-0.5">
            {selectedEdge.source.toUpperCase()} ➔ {selectedEdge.target.toUpperCase()}
          </p>
          <p className="text-[11px] font-mono text-slate-400">
            {selectedEdge.protocol} :{selectedEdge.port}
          </p>

          <div className="mt-3 text-2xl sm:text-3xl font-extrabold font-mono text-cyan-400 drop-shadow-[0_0_12px_rgba(6,182,212,0.45)]">
            {selectedEdge.attention.toFixed(2)} <span className="text-xs text-slate-400 font-normal">edge weight</span>
          </div>

          {/* Quick edge cycler */}
          <div className="mt-3 flex items-center space-x-1.5">
            {edges.map((e) => (
              <button
                key={e.id}
                onClick={() => {
                  if (soundEnabled) playCyberTone('click');
                  onSelectEdge(e);
                }}
                title={`Select vector: ${e.source} -> ${e.target}`}
                className={`h-2 rounded-full transition-all ${
                  selectedEdge.id === e.id
                    ? 'w-6 bg-cyan-400 shadow-[0_0_8px_#38bdf8]'
                    : 'w-2 bg-slate-600 hover:bg-slate-400'
                }`}
              />
            ))}
          </div>
        </div>
      </div>
      </>
      )}

      {/* Attention Map Modal */}
      {showAttentionModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in">
          <div className="relative w-full max-w-2xl rounded-xl border border-[#173a72] bg-[#071329] p-6 shadow-2xl">
            <div className="flex items-center justify-between pb-4 border-b border-[#11264c]">
              <div className="flex items-center space-x-2.5">
                <Cpu className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white font-mono">
                  Full Graph Attention Matrix
                </h3>
              </div>
              <button
                onClick={() => setShowAttentionModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="py-4 space-y-3 font-mono text-xs">
              <p className="text-slate-400 font-sans text-xs leading-relaxed">
                The World Model Graph Neural Network dynamically computes pairwise attention coefficients between all hosts in the sequence. High scores indicate vectors of malicious lateral propagation.
              </p>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse border border-[#142f5c]">
                  <thead>
                    <tr className="bg-[#0b1c3a] text-slate-300">
                      <th className="p-2 border border-[#142f5c]">Source</th>
                      <th className="p-2 border border-[#142f5c]">Target</th>
                      <th className="p-2 border border-[#142f5c]">Port / Vector</th>
                      <th className="p-2 border border-[#142f5c]">Attention Weight</th>
                      <th className="p-2 border border-[#142f5c]">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#102447]">
                    {edges.map((e) => (
                      <tr
                        key={e.id}
                        onClick={() => {
                          onSelectEdge(e);
                          setShowAttentionModal(false);
                        }}
                        className={`hover:bg-[#0d234a] cursor-pointer transition-colors ${
                          selectedEdge && selectedEdge.id === e.id ? 'bg-[#0e2752]' : ''
                        }`}
                      >
                        <td className="p-2 font-bold text-rose-400 border border-[#142f5c]">
                          {e.source.toUpperCase()}
                        </td>
                        <td className="p-2 font-bold text-slate-200 border border-[#142f5c]">
                          {e.target.toUpperCase()}
                        </td>
                        <td className="p-2 text-cyan-300 border border-[#142f5c]">
                          {e.protocol} :{e.port}
                        </td>
                        <td className="p-2 font-bold text-amber-400 border border-[#142f5c]">
                          {e.attention.toFixed(2)}
                        </td>
                        <td className="p-2 border border-[#142f5c]">
                          <span
                            className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-800/50"
                          >
                            Inspect Source
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="pt-3 border-t border-[#11264c] flex justify-end">
              <button
                onClick={() => setShowAttentionModal(false)}
                className="px-4 py-1.5 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs transition-colors"
              >
                Close Matrix
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

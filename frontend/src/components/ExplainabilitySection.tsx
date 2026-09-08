import React, { useState } from 'react';
import { ChevronRight, Cpu, Activity, ShieldAlert, X, ArrowRight, Layers, Table, Network } from 'lucide-react';
import { FeatureImportance, NetworkEdge, SourceExplainabilityProfile, AppTheme } from '../types';
import { playCyberTone } from '../utils/audio';

interface ExplainabilitySectionProps {
  features: FeatureImportance[];
  edges: NetworkEdge[];
  selectedEdge: NetworkEdge;
  onSelectEdge: (edge: NetworkEdge) => void;
  profile?: SourceExplainabilityProfile;
  onSelectSource?: (sourceId: string) => void;
  soundEnabled: boolean;
  theme?: AppTheme;
}

export const ExplainabilitySection: React.FC<ExplainabilitySectionProps> = ({
  features,
  edges,
  selectedEdge,
  onSelectEdge,
  profile,
  onSelectSource,
  soundEnabled,
  theme = 'light'
}) => {
  const [showAttentionModal, setShowAttentionModal] = useState(false);

  const isLight = theme === 'light';
  const isMidnight = theme === 'midnight';

  // Group unique sources from edges
  const sourceIds: string[] = Array.from(new Set(edges.map((e) => e.source)));

  return (
    <div className="space-y-6">
      {/* 1. Header Context Banner */}
      <div
        className={`p-5 sm:p-6 rounded-2xl border shadow-lg transition-colors ${
          isLight
            ? 'bg-white border-slate-200 text-slate-900'
            : isMidnight
            ? 'bg-[#071329]/95 border-[#142f5c] text-white'
            : 'bg-[#0e1628]/95 border-[#1d2a45] text-white'
        }`}
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-3 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 shrink-0 mt-0.5">
              <Network className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-lg sm:text-xl font-bold font-sans tracking-tight">
                  Feature Attribution & Graph Attention Explainability
                </h2>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                    isLight
                      ? 'bg-cyan-50 text-cyan-700 border-cyan-200'
                      : 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40'
                  }`}
                >
                  Forensic Attribution
                </span>
              </div>
              <p className={`text-xs font-sans mt-1 max-w-2xl ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                Neural edge attention coefficients and telemetry feature importance scores showing why the World Model classified this network traversal as an active cyber attack.
              </p>
            </div>
          </div>

          <button
            onClick={() => {
              if (soundEnabled) playCyberTone('click');
              setShowAttentionModal(true);
            }}
            className={`flex items-center space-x-2 px-4 py-2.5 rounded-xl border text-xs font-mono font-bold transition-all ${
              isLight
                ? 'border-cyan-300 bg-cyan-50 text-cyan-800 hover:bg-cyan-100'
                : 'border-cyan-500/30 bg-cyan-950/30 text-cyan-300 hover:bg-cyan-900/50'
            }`}
          >
            <Table className="w-4 h-4" />
            <span>Full Attention Matrix</span>
          </button>
        </div>
      </div>

      {/* 2. Source Selector Chips & Current Vector Breadcrumb */}
      <div
        className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-5 py-3 rounded-xl border text-xs font-mono transition-colors ${
          isLight
            ? 'bg-white border-slate-200 text-slate-700'
            : isMidnight
            ? 'bg-[#071329]/95 border-[#142f5c] text-slate-300'
            : 'bg-[#0e1628]/95 border-[#1d2a45] text-slate-300'
        }`}
      >
        <div className="flex items-center space-x-2.5">
          <Layers className="w-4 h-4 text-cyan-500" />
          <span className="text-slate-400 font-semibold uppercase text-[11px]">
            Attacking Host Vector:
          </span>
          <div className="flex flex-wrap items-center gap-2">
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
                  className={`px-3 py-1 rounded-lg text-xs font-mono font-bold transition-all ${
                    isSelected
                      ? isLight
                        ? 'bg-rose-500 text-white shadow-xs'
                        : 'bg-rose-600 text-white shadow-[0_0_10px_rgba(244,63,94,0.4)]'
                      : isLight
                      ? 'bg-slate-100 hover:bg-slate-200 text-slate-700'
                      : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                  }`}
                >
                  {srcId.toUpperCase()}
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex items-center space-x-2 text-xs font-mono">
          <span className="text-slate-400">Inspecting Link:</span>
          <span className="text-rose-500 font-bold">{selectedEdge.source.toUpperCase()}</span>
          <ArrowRight className="w-3.5 h-3.5 text-cyan-500" />
          <span className="text-amber-500 font-bold">{selectedEdge.target.toUpperCase()}</span>
          <span className="text-slate-400">({selectedEdge.protocol} :{selectedEdge.port})</span>
        </div>
      </div>

      {/* 3. Narrative Diagnosis Summary */}
      {profile && (
        <div
          className={`p-4 rounded-xl border text-xs flex items-start space-x-3 transition-colors ${
            isLight
              ? 'bg-cyan-50/70 border-cyan-200 text-slate-800'
              : 'bg-cyan-950/20 border-cyan-500/30 text-slate-200'
          }`}
        >
          <ShieldAlert className="w-4 h-4 text-cyan-500 shrink-0 mt-0.5" />
          <div className="space-y-0.5">
            <span className="font-bold text-cyan-600 dark:text-cyan-300 font-mono">Attack Vector Diagnosis: </span>
            <span className="font-sans leading-relaxed">{profile.summary}</span>
          </div>
        </div>
      )}

      {/* 4. Main 12-Column Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Telemetry Feature Importance Bars (7 cols) */}
        <div
          className={`lg:col-span-7 rounded-2xl border p-5 sm:p-6 shadow-xl space-y-4 transition-colors ${
            isLight
              ? 'bg-white border-slate-200 text-slate-800'
              : isMidnight
              ? 'bg-[#071329]/95 border-[#142f5c] text-slate-100'
              : 'bg-[#0e1628]/95 border-[#1d2a45] text-slate-100'
          }`}
        >
          <div className="flex items-center justify-between border-b pb-3 text-xs font-mono text-slate-400">
            <span className="font-bold uppercase tracking-wider">Contributing Telemetry Factors</span>
            <span>Feature Weight (%)</span>
          </div>

          <div className="space-y-4 pt-1">
            {features.map((feat, index) => {
              const numStr = String(index + 1).padStart(2, '0');
              const isHigh = feat.severity === 'high';
              return (
                <div key={feat.id} className="space-y-1.5 font-mono">
                  <div className="flex items-baseline justify-between text-xs">
                    <div className="flex items-baseline space-x-2.5">
                      <span className="text-slate-400 font-semibold">{numStr}</span>
                      <span className={`font-bold ${isLight ? 'text-slate-900' : 'text-slate-100'}`}>
                        {feat.code}
                      </span>
                      <span className="text-slate-400 text-[11px] font-sans hidden sm:inline">
                        — {feat.label}
                      </span>
                    </div>
                    <span className={`font-bold ${isHigh ? 'text-rose-500' : 'text-amber-500'}`}>
                      +{feat.percentage}% weight
                    </span>
                  </div>

                  <div className="relative h-2.5 w-full rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${
                        isHigh
                          ? 'bg-gradient-to-r from-amber-500 to-rose-500'
                          : 'bg-gradient-to-r from-cyan-600 to-cyan-400'
                      }`}
                      style={{ width: `${Math.min(100, feat.percentage * 2)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Link Attention Diagnostic Card (5 cols) */}
        <div
          className={`lg:col-span-5 rounded-2xl border p-5 sm:p-6 shadow-xl space-y-5 transition-colors ${
            isLight
              ? 'bg-white border-slate-200 text-slate-800'
              : isMidnight
              ? 'bg-[#071329]/95 border-[#142f5c] text-slate-100'
              : 'bg-[#0e1628]/95 border-[#1d2a45] text-slate-100'
          }`}
        >
          <div className="border-b pb-3">
            <h4 className={`text-sm font-bold font-sans ${isLight ? 'text-slate-900' : 'text-white'}`}>
              Spatial Edge Attention Coefficient
            </h4>
            <p className={`text-xs font-sans mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
              Pairwise neural weight across lateral propagation path
            </p>
          </div>

          {/* Metric Box */}
          <div
            className={`p-4 rounded-xl border text-center space-y-2 ${
              isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/60 border-slate-800'
            }`}
          >
            <div className="text-xs font-mono text-slate-400 uppercase font-semibold">
              Attention Weight (α)
            </div>
            <div className="text-4xl sm:text-5xl font-extrabold font-mono text-cyan-500">
              {selectedEdge.attention.toFixed(2)}
            </div>
            <p className="text-xs font-sans text-slate-400">
              Scores above 0.70 indicate prioritized lateral movement propagation
            </p>
          </div>

          {/* Vector Details Table */}
          <div className="space-y-2 text-xs font-mono">
            <div
              className={`p-3 rounded-xl border flex items-center justify-between ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/40 border-slate-800'
              }`}
            >
              <span className="text-slate-400">Source Host:</span>
              <span className="font-bold text-rose-500">{selectedEdge.source.toUpperCase()}</span>
            </div>

            <div
              className={`p-3 rounded-xl border flex items-center justify-between ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/40 border-slate-800'
              }`}
            >
              <span className="text-slate-400">Destination Target:</span>
              <span className="font-bold text-amber-500">{selectedEdge.target.toUpperCase()}</span>
            </div>

            <div
              className={`p-3 rounded-xl border flex items-center justify-between ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/40 border-slate-800'
              }`}
            >
              <span className="text-slate-400">Port / Protocol:</span>
              <span className="font-bold text-cyan-500">{selectedEdge.protocol} (Port {selectedEdge.port})</span>
            </div>
          </div>

          {/* Edge Selector Dots */}
          <div className="pt-2 border-t flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Cycle Graph Edges:</span>
            <div className="flex items-center space-x-2">
              {edges.map((e) => (
                <button
                  key={e.id}
                  onClick={() => {
                    if (soundEnabled) playCyberTone('click');
                    onSelectEdge(e);
                  }}
                  title={`${e.source} -> ${e.target}`}
                  className={`h-2.5 rounded-full transition-all ${
                    selectedEdge.id === e.id
                      ? 'w-7 bg-cyan-500'
                      : isLight
                      ? 'w-2.5 bg-slate-300 hover:bg-slate-400'
                      : 'w-2.5 bg-slate-700 hover:bg-slate-500'
                  }`}
                />
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 5. Full Attention Matrix Modal */}
      {showAttentionModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in">
          <div
            className={`relative w-full max-w-3xl rounded-2xl border p-6 shadow-2xl transition-colors ${
              isLight
                ? 'bg-white border-slate-300 text-slate-900'
                : 'bg-slate-900 border-slate-700 text-slate-100'
            }`}
          >
            <div className="flex items-center justify-between pb-4 border-b">
              <div className="flex items-center space-x-2.5">
                <Cpu className="w-5 h-5 text-cyan-500" />
                <h3 className="text-base font-bold font-sans">
                  Graph Attention Weight Matrix
                </h3>
              </div>
              <button
                onClick={() => setShowAttentionModal(false)}
                className="text-slate-400 hover:text-slate-100 p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="py-4 space-y-3 font-mono text-xs">
              <p className="text-slate-500 font-sans text-xs leading-relaxed">
                Pairwise attention coefficients dynamically assigned to internal network hops. Highest attention links correlate directly with attacker traversal paths.
              </p>

              <div className="overflow-x-auto rounded-xl border">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className={isLight ? 'bg-slate-100 text-slate-700' : 'bg-slate-800 text-slate-300'}>
                      <th className="p-3">Source Node</th>
                      <th className="p-3">Target Node</th>
                      <th className="p-3">Protocol / Port</th>
                      <th className="p-3">Attention Weight</th>
                      <th className="p-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                    {edges.map((e) => (
                      <tr
                        key={e.id}
                        onClick={() => {
                          onSelectEdge(e);
                          setShowAttentionModal(false);
                        }}
                        className={`cursor-pointer transition-colors ${
                          selectedEdge.id === e.id
                            ? isLight
                              ? 'bg-cyan-50'
                              : 'bg-cyan-950/40'
                            : isLight
                            ? 'hover:bg-slate-50'
                            : 'hover:bg-slate-800/60'
                        }`}
                      >
                        <td className="p-3 font-bold text-rose-500">{e.source.toUpperCase()}</td>
                        <td className="p-3 font-bold">{e.target.toUpperCase()}</td>
                        <td className="p-3 text-cyan-500">{e.protocol} :{e.port}</td>
                        <td className="p-3 font-bold text-amber-500">{e.attention.toFixed(2)}</td>
                        <td className="p-3 text-right">
                          <span className="px-2 py-1 rounded text-[10px] font-bold bg-cyan-500 text-white">
                            Select
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="pt-3 border-t flex justify-end">
              <button
                onClick={() => setShowAttentionModal(false)}
                className="px-4 py-2 rounded-xl bg-slate-200 dark:bg-slate-800 text-slate-800 dark:text-slate-200 font-sans font-bold text-xs"
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

import React, { useRef } from 'react';
import { RefreshCw, Zap, Upload, Radio } from 'lucide-react';
import { playCyberTone } from '../utils/audio';

interface HeroSectionProps {
  sequence: number;
  isRefreshing: boolean;
  onRefreshModel: () => void;
  onRunCounterfactual: () => void;
  soundEnabled: boolean;
  hasData: boolean;
  backendConnected: boolean;
  onUploadTelemetry: (file: File) => void;
  onFetchBackendStream: () => void;
  isUploading: boolean;
}

export const HeroSection: React.FC<HeroSectionProps> = ({
  sequence,
  isRefreshing,
  onRefreshModel,
  onRunCounterfactual,
  soundEnabled,
  hasData,
  backendConnected,
  onUploadTelemetry,
  onFetchBackendStream,
  isUploading
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (soundEnabled) playCyberTone('click');
      onUploadTelemetry(file);
    }
  };

  return (
    <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pt-4 pb-2">
      <div className="space-y-1.5">
        {/* Eyebrow status */}
        <div className="flex items-center space-x-2 text-xs font-mono tracking-wider text-slate-400">
          <span
            className={`inline-block w-2 h-2 rounded-full ${
              backendConnected && hasData
                ? 'bg-emerald-400 shadow-[0_0_8px_#34d399] animate-pulse'
                : backendConnected
                ? 'bg-cyan-400 shadow-[0_0_8px_#22d3ee] animate-pulse'
                : 'bg-rose-500 shadow-[0_0_8px_#f43f5e]'
            }`}
          />
          <span
            className={`font-semibold ${
              backendConnected && hasData
                ? 'text-emerald-400'
                : backendConnected
                ? 'text-cyan-400'
                : 'text-rose-400'
            }`}
          >
            {backendConnected ? 'FASTAPI BACKEND: ONLINE (PORT 8000)' : 'BACKEND: OFFLINE'}
          </span>
          <span className="text-slate-600">/</span>
          <span>{hasData ? `INFERENCE ACTIVE (SEQ ${sequence})` : 'NO TELEMETRY STREAM'}</span>
        </div>

        {/* Title */}
        <h2 className="text-2xl sm:text-3xl md:text-4xl font-extrabold tracking-tight text-white font-sans">
          Defence <span className="text-cyan-400 drop-shadow-[0_0_15px_rgba(6,182,212,0.4)]">cockpit</span>
        </h2>

        {/* Subtitle */}
        <p className="text-xs sm:text-sm font-mono text-slate-400">
          {hasData
            ? `Proactive network state intelligence · sequence ${sequence} / 10 windows`
            : 'Awaiting network flow telemetry stream from backend API or file upload'}
        </p>
      </div>

      {/* Action buttons */}
      <div className="flex flex-wrap items-center gap-2.5">
        <input
          ref={fileInputRef}
          type="file"
          accept=".csv"
          onChange={handleFileChange}
          className="hidden"
        />

        <button
          onClick={() => fileInputRef.current?.click()}
          disabled={isUploading}
          className="flex items-center space-x-2 px-3.5 py-2 rounded-lg border border-cyan-500/40 bg-[#07193b] hover:bg-[#0c2a61] text-cyan-300 hover:text-white text-xs sm:text-sm font-mono transition-all disabled:opacity-50"
        >
          <Upload className={`w-3.5 h-3.5 text-cyan-400 ${isUploading ? 'animate-bounce' : ''}`} />
          <span>{isUploading ? 'Ingesting CSV...' : 'Upload Telemetry CSV'}</span>
        </button>

        <button
          onClick={() => {
            if (soundEnabled) playCyberTone('click');
            onFetchBackendStream();
          }}
          disabled={isRefreshing || isUploading}
          className="flex items-center space-x-2 px-3.5 py-2 rounded-lg border border-[#17386c] bg-[#071329] hover:bg-[#0c234a] hover:border-cyan-500/40 text-slate-200 hover:text-white text-xs sm:text-sm font-mono transition-all disabled:opacity-50"
        >
          <Radio className={`w-3.5 h-3.5 text-emerald-400 ${isRefreshing ? 'animate-pulse' : ''}`} />
          <span>Fetch Backend Sample</span>
        </button>

        <button
          onClick={() => {
            if (soundEnabled) playCyberTone('click');
            onRefreshModel();
          }}
          disabled={isRefreshing}
          className="flex items-center space-x-2 px-3.5 py-2 rounded-lg border border-[#17386c] bg-[#071329] hover:bg-[#0c234a] hover:border-cyan-500/40 text-slate-200 hover:text-white text-xs sm:text-sm font-mono transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>

        <button
          onClick={() => {
            if (soundEnabled) playCyberTone('sim');
            onRunCounterfactual();
          }}
          disabled={!hasData}
          className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs sm:text-sm font-mono shadow-[0_0_20px_rgba(6,182,212,0.45)] hover:shadow-[0_0_25px_rgba(6,182,212,0.65)] transition-all transform active:scale-98 disabled:opacity-40 disabled:pointer-events-none"
        >
          <Zap className="w-4 h-4 fill-slate-950" />
          <span>Run counterfactual</span>
        </button>
      </div>
    </div>
  );
};

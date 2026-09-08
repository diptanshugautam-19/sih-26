import React from 'react';
import { HardDrive, Upload, RefreshCw } from 'lucide-react';
import { CaptureMetadata, AppTheme } from '../types';
import { playCyberTone } from '../utils/audio';

interface CaptureUtilityBarProps {
  activeCapture?: CaptureMetadata | null;
  onOpenUploadModal?: () => void;
  onRefreshData?: () => void;
  isRefreshing?: boolean;
  soundEnabled?: boolean;
  theme?: AppTheme;
  titleOverride?: string;
  subtitleOverride?: string;
}

export const CaptureUtilityBar: React.FC<CaptureUtilityBarProps> = ({
  activeCapture,
  onOpenUploadModal,
  onRefreshData,
  isRefreshing = false,
  soundEnabled = false,
  theme = 'light',
  titleOverride,
  subtitleOverride
}) => {
  const isLight = theme === 'light';
  const isMidnight = theme === 'midnight';

  return (
    <div
      className={`flex flex-col sm:flex-row sm:items-center justify-between gap-4 px-5 py-4 rounded-2xl border backdrop-blur-md transition-colors ${
        isLight
          ? 'bg-white border-slate-200 shadow-sm text-slate-800'
          : isMidnight
          ? 'bg-[#071329]/95 border-[#142f5c] text-slate-100'
          : 'bg-[#0e1628]/95 border-[#1d2a45] text-slate-100 shadow-lg'
      }`}
    >
      <div className="flex items-center space-x-3.5">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
          <HardDrive className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className={`text-sm font-mono font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>
              {titleOverride || (activeCapture ? activeCapture.fileName : 'Live Network Recording')}
            </span>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border ${
                isLight
                  ? 'bg-cyan-50 text-cyan-700 border-cyan-200'
                  : 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40'
              }`}
            >
              {activeCapture ? activeCapture.fileType : 'PCAP'}
            </span>
            {activeCapture && (
              <span className="flex items-center space-x-1 text-[11px] font-sans text-emerald-500">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                <span className="font-semibold">Analyzed</span>
              </span>
            )}
          </div>
          <p className={`text-xs font-sans mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
            {subtitleOverride ||
              (activeCapture
                ? `${activeCapture.packetCount.toLocaleString()} packets processed · ${activeCapture.durationSeconds}s window · ${activeCapture.threatNodesDetected} threat hosts isolated`
                : 'Real-time telemetry stream active · Continuous lateral movement detection')}
          </p>
        </div>
      </div>

      <div className="flex items-center space-x-2.5">
        <button
          onClick={() => {
            if (soundEnabled) playCyberTone('click');
            if (onOpenUploadModal) onOpenUploadModal();
          }}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold font-sans transition-all duration-200 transform hover:-translate-y-0.5 active:translate-y-0 shadow-md ${
            activeCapture
              ? isLight
                ? 'border border-cyan-300 bg-cyan-50 text-cyan-800 hover:bg-cyan-100'
                : 'border border-cyan-500/40 bg-cyan-950/40 text-cyan-300 hover:bg-cyan-900/60'
              : 'border border-cyan-400 bg-gradient-to-r from-cyan-600 via-cyan-500 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-[0_0_18px_rgba(6,182,212,0.35)]'
          }`}
        >
          <Upload className="w-4 h-4 text-white" />
          <span>{activeCapture ? 'Switch / Ingest New File' : 'Upload Capture File (PCAP)'}</span>
        </button>

        {onRefreshData && (
          <button
            onClick={() => {
              if (soundEnabled) playCyberTone('click');
              onRefreshData();
            }}
            disabled={isRefreshing}
            title="Resync state from backend"
            className={`flex items-center space-x-1.5 px-3 py-2 rounded-xl border text-xs font-sans font-medium transition-colors ${
              isLight
                ? 'border-slate-300 bg-slate-100 hover:bg-slate-200 text-slate-700'
                : 'border-[#1e2a44] bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white'
            }`}
          >
            <RefreshCw className={`w-3.5 h-3.5 text-cyan-500 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span className="hidden sm:inline">Sync</span>
          </button>
        )}
      </div>
    </div>
  );
};

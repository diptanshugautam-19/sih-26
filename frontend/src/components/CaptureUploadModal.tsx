import React, { useState, useRef, useEffect } from 'react';
import {
  Upload,
  CheckCircle2,
  AlertTriangle,
  X,
  ArrowRight,
  RefreshCw,
  Cpu,
  Download
} from 'lucide-react';
import { CaptureMetadata, PresetCapture, AppTheme } from '../types';
import {
  fetchPresetCaptures,
  apiLoadPresetCapture,
  apiUploadCapture,
  apiUploadCaptureBinary,
  apiResetCapture
} from '../utils/api';
import { playCyberTone } from '../utils/audio';

interface CaptureUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  activeCapture: CaptureMetadata | null;
  onCaptureLoaded: () => void | Promise<void>;
  soundEnabled: boolean;
  theme?: AppTheme;
}

export const CaptureUploadModal: React.FC<CaptureUploadModalProps> = ({
  isOpen,
  onClose,
  activeCapture,
  onCaptureLoaded,
  soundEnabled,
  theme = 'light'
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [processingStage, setProcessingStage] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [presets, setPresets] = useState<PresetCapture[]>([]);
  const [loadingPresetId, setLoadingPresetId] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const isLight = theme === 'light';

  // Load presets on mount or open
  useEffect(() => {
    if (isOpen) {
      fetchPresetCaptures()
        .then((data) => setPresets(data))
        .catch((err) => console.warn('Could not load preset captures:', err));
    }
  }, [isOpen]);

  if (!isOpen) return null;

  // Process uploaded file
  const handleProcessFile = async (file: File) => {
    setErrorMsg(null);
    setIsProcessing(true);
    const sizeMb = (file.size / (1024 * 1024)).toFixed(1);
    const sizeKb = (file.size / 1024).toFixed(1);
    const displaySize = file.size > 1024 * 1024 ? `${sizeMb} MB` : `${sizeKb} KB`;

    try {
      if (soundEnabled) playCyberTone('click');

      setProcessingStage(`Streaming ${file.name} (${displaySize}) directly to VASHIKARAN engine...`);
      await apiUploadCaptureBinary(file);

      setProcessingStage('Executing GNN (GATConv) + Temporal Transformer Forward Pass...');
      // Brief pause to allow stage text to be visually visible
      await new Promise((r) => setTimeout(r, 400));

      setProcessingStage('Updating dynamic network topology and host states...');
      await onCaptureLoaded();
      if (soundEnabled) playCyberTone('success');
      onClose();
    } catch (err: any) {
      console.error('Capture upload error:', err);
      setErrorMsg(err.message || 'Failed to parse and process capture file');
      if (soundEnabled) playCyberTone('alert');
    } finally {
      setIsProcessing(false);
      setProcessingStage('');
    }
  };

  // Drag and Drop handlers
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      handleProcessFile(files[0]);
    }
  };

  // Manual file input click
  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleProcessFile(files[0]);
    }
  };

  // Load a preset capture
  const handleLoadPreset = async (presetId: string) => {
    setLoadingPresetId(presetId);
    setErrorMsg(null);
    try {
      if (soundEnabled) playCyberTone('click');
      await apiLoadPresetCapture(presetId);
      if (soundEnabled) playCyberTone('success');
      onCaptureLoaded();
      onClose();
    } catch (err: any) {
      console.error('Preset loading error:', err);
      setErrorMsg(err.message || 'Failed to load preset capture');
    } finally {
      setLoadingPresetId(null);
    }
  };

  // Reset to live default
  const handleResetToDefault = async () => {
    setIsProcessing(true);
    try {
      if (soundEnabled) playCyberTone('click');
      await apiResetCapture();
      if (soundEnabled) playCyberTone('success');
      onCaptureLoaded();
      onClose();
    } catch (err: any) {
      console.error('Reset error:', err);
      setErrorMsg('Failed to reset network capture');
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className={`fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 backdrop-blur-md animate-in fade-in duration-200 ${
      isLight ? 'bg-slate-900/40' : 'bg-[#020611]/85'
    }`}>
      <div className={`relative w-full max-w-2xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh] transition-colors border ${
        isLight
          ? 'bg-white border-slate-200 text-slate-800'
          : 'bg-[#061126] border-[#143261] text-slate-100'
      }`}>
        {/* Header */}
        <div className={`flex items-center justify-between px-5 py-4 border-b ${
          isLight
            ? 'bg-slate-50 border-slate-200'
            : 'bg-[#040c1d] border-[#0d2347]'
        }`}>
          <div className="flex items-center space-x-3">
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
              isLight
                ? 'bg-cyan-50 border border-cyan-200 text-cyan-700'
                : 'bg-cyan-950/60 border border-cyan-500/40 text-cyan-400'
            }`}>
              <Upload className="w-4 h-4" />
            </div>
            <div>
              <h3 className={`text-sm sm:text-base font-bold font-mono tracking-wide ${
                isLight ? 'text-slate-900' : 'text-slate-100'
              }`}>
                UPLOAD NETWORK RECORDING
              </h3>
              <p className={`text-[11px] font-sans ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                Ingest PCAP, PCAPNG, NetFlow, or JSON captures into VASHIKARAN
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className={`p-1 rounded-md transition-colors ${
              isLight
                ? 'text-slate-400 hover:text-slate-700 hover:bg-slate-200'
                : 'text-slate-400 hover:text-white hover:bg-[#0a1e3f]'
            }`}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable Body */}
        <div className="p-5 overflow-y-auto space-y-5">
          {/* Active Capture Banner if present */}
          {activeCapture && (
            <div className={`p-3.5 rounded-lg border flex items-center justify-between ${
              isLight
                ? 'border-emerald-200 bg-emerald-50 text-emerald-900'
                : 'border-cyan-500/30 bg-cyan-950/20 text-cyan-200'
            }`}>
              <div className="flex items-center space-x-3">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-cyan-400 shrink-0" />
                <div className="text-xs">
                  <p className="font-mono font-bold">
                    CURRENT ACTIVE CAPTURE: {activeCapture.fileName}
                  </p>
                  <p className={`text-[11px] ${isLight ? 'text-emerald-700' : 'text-slate-400'}`}>
                    {activeCapture.packetCount.toLocaleString()} packets · {activeCapture.flowCount} flows · Protocols: {activeCapture.protocolsDetected.join(', ')}
                  </p>
                </div>
              </div>
              <button
                onClick={handleResetToDefault}
                disabled={isProcessing}
                className={`px-2.5 py-1 text-[11px] font-mono rounded border transition-colors shrink-0 ${
                  isLight
                    ? 'border-slate-300 hover:border-slate-400 text-slate-700 hover:bg-white bg-slate-100'
                    : 'border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white bg-[#0b1c3a]'
                }`}
              >
                Reset to Live Telemetry
              </button>
            </div>
          )}

          {/* Drag & Drop Upload Zone (meets usability guidelines) */}
          <div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng,.cap,.csv,.json,.log,.txt"
              className="hidden"
              onChange={handleFileInputChange}
            />

            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-6 sm:p-8 text-center cursor-pointer transition-all ${
                isDragging
                  ? isLight
                    ? 'border-cyan-500 bg-cyan-50/80 shadow-md'
                    : 'border-cyan-400 bg-cyan-950/40 shadow-[0_0_20px_rgba(6,182,212,0.25)]'
                  : isLight
                  ? 'border-slate-300 hover:border-cyan-500 bg-slate-50/70 hover:bg-slate-100/80'
                  : 'border-[#143261] hover:border-cyan-500/60 bg-[#040c1d]/60 hover:bg-[#071530]'
              }`}
            >
              <div className="flex flex-col items-center justify-center space-y-3">
                <div className={`w-12 h-12 rounded-full flex items-center justify-center ${
                  isLight
                    ? 'bg-cyan-100 border border-cyan-300 text-cyan-700'
                    : 'bg-cyan-950/40 border border-cyan-500/30 text-cyan-400'
                }`}>
                  <Upload className="w-6 h-6 animate-pulse" />
                </div>
                <div>
                  <p className={`text-xs sm:text-sm font-semibold font-mono ${
                    isLight ? 'text-slate-800' : 'text-slate-200'
                  }`}>
                    DRAG & DROP NETWORK CAPTURE FILE HERE
                  </p>
                  <p className={`text-[11px] mt-1 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                    or <span className="text-cyan-600 dark:text-cyan-400 underline font-semibold">browse local files</span> from your computer
                  </p>
                </div>

                {/* Formats Supported Pills */}
                <div className="flex flex-wrap items-center justify-center gap-1.5 pt-2">
                  {['.pcap', '.pcapng', '.csv', '.json', '.log', '.cap'].map((fmt) => (
                    <span
                      key={fmt}
                      className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-medium border ${
                        isLight
                          ? 'bg-slate-100 border-slate-200 text-slate-700'
                          : 'bg-[#081733] border-[#132d59] text-cyan-300'
                      }`}
                    >
                      {fmt}
                    </span>
                  ))}
                </div>
                <p className={`text-[10px] font-mono ${isLight ? 'text-slate-500' : 'text-slate-500'}`}>
                  Supported: Wireshark PCAPs, NetFlow/IPFIX, Zeek/Bro Logs, Suricata EVE
                </p>
              </div>
            </div>
          </div>

          {/* Processing state indicator */}
          {isProcessing && (
            <div className={`p-3.5 rounded-lg border flex items-center space-x-3 animate-pulse ${
              isLight
                ? 'border-cyan-300 bg-cyan-50 text-cyan-800'
                : 'border-cyan-500/50 bg-cyan-950/30 text-cyan-200'
            }`}>
              <RefreshCw className="w-4 h-4 text-cyan-500 animate-spin" />
              <div className="text-xs font-mono">
                {processingStage || 'Processing network capture...'}
              </div>
            </div>
          )}

          {/* Error Message */}
          {errorMsg && (
            <div className="p-3 rounded-lg border border-rose-300 dark:border-rose-500/40 bg-rose-50 dark:bg-rose-950/30 flex items-center space-x-2.5 text-xs text-rose-700 dark:text-rose-300">
              <AlertTriangle className="w-4 h-4 text-rose-500 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Divider with Presets */}
          <div className="relative py-1">
            <div className="absolute inset-0 flex items-center">
              <div className={`w-full border-t ${isLight ? 'border-slate-200' : 'border-[#10274c]'}`} />
            </div>
            <div className="relative flex justify-center text-[10px] uppercase font-mono tracking-wider">
              <span className={`px-3 ${isLight ? 'bg-white text-slate-500' : 'bg-[#061126] text-slate-400'}`}>
                or load realistic preset captures
              </span>
            </div>
          </div>

          {/* Preset Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {presets.map((preset) => {
              const isLoading = loadingPresetId === preset.id;
              return (
                <div
                  key={preset.id}
                  className={`p-3 rounded-lg border transition-all flex flex-col justify-between space-y-2 group ${
                    isLight
                      ? 'border-slate-200 bg-slate-50/70 hover:border-cyan-400 hover:bg-white'
                      : 'border-[#122c54] bg-[#040b1b] hover:border-cyan-500/40'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center justify-between">
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase font-bold border ${
                        isLight
                          ? 'bg-slate-200 text-slate-700 border-slate-300'
                          : 'bg-cyan-950/70 text-cyan-300 border border-cyan-500/30'
                      }`}>
                        {preset.fileType}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">{preset.sizeLabel}</span>
                    </div>
                    <h4 className={`text-xs font-bold font-mono transition-colors ${
                      isLight
                        ? 'text-slate-800 group-hover:text-cyan-700'
                        : 'text-slate-200 group-hover:text-cyan-300'
                    }`}>
                      {preset.title}
                    </h4>
                    <p className={`text-[10px] line-clamp-2 leading-relaxed font-sans ${
                      isLight ? 'text-slate-600' : 'text-slate-400'
                    }`}>
                      {preset.description}
                    </p>
                  </div>

                  <div className={`pt-2 border-t flex items-center justify-between ${
                    isLight ? 'border-slate-200' : 'border-[#0d213e]'
                  }`}>
                    <div className="text-[10px] font-mono text-slate-400">
                      Target: <span className="text-rose-600 dark:text-rose-400 font-semibold">{preset.targetFocus}</span> ({preset.probability}%)
                    </div>
                    <div className="flex items-center space-x-1.5">
                      <a
                        href={`/api/captures/download/${preset.fileName}`}
                        download={preset.fileName}
                        onClick={(e) => e.stopPropagation()}
                        title={`Download ${preset.fileName}`}
                        className={`flex items-center space-x-1 px-2 py-1 rounded text-[10px] font-mono font-semibold transition-colors ${
                          isLight
                            ? 'bg-slate-100 hover:bg-slate-200 border border-slate-300 text-slate-700'
                            : 'bg-[#0a1e3f] hover:bg-[#122c54] border border-cyan-500/30 text-cyan-300'
                        }`}
                      >
                        <Download className="w-3 h-3 text-cyan-500" />
                        <span>Download</span>
                      </a>

                      <button
                        onClick={() => handleLoadPreset(preset.id)}
                        disabled={isLoading || isProcessing}
                        className={`flex items-center space-x-1 px-2.5 py-1 rounded text-[10px] font-mono font-semibold transition-colors ${
                          isLight
                            ? 'bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 hover:text-cyan-800'
                            : 'bg-[#0a1e3f] hover:bg-cyan-950 border border-cyan-500/30 hover:border-cyan-500 text-cyan-300'
                        }`}
                      >
                        {isLoading ? (
                          <>
                            <RefreshCw className="w-3 h-3 animate-spin" />
                            <span>Loading...</span>
                          </>
                        ) : (
                          <>
                            <span>Load</span>
                            <ArrowRight className="w-3 h-3" />
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Footer */}
        <div className={`px-5 py-3 border-t flex items-center justify-between text-xs font-mono ${
          isLight
            ? 'border-slate-200 bg-slate-50 text-slate-600'
            : 'border-[#0d2347] bg-[#040c1d] text-slate-400'
        }`}>
          <div className="flex items-center space-x-2">
            <Cpu className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
            <span className="text-[11px]">Hardware accelerated packet parser active</span>
          </div>
          <button
            onClick={onClose}
            className={`px-3 py-1 rounded border transition-colors ${
              isLight
                ? 'border-slate-300 hover:border-slate-400 text-slate-700 bg-white hover:bg-slate-50'
                : 'border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white bg-[#0a1b38]'
            }`}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

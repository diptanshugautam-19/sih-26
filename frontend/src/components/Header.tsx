import React, { useState, useEffect } from 'react';
import { Shield, Wifi, Pause, Play, Bell, Volume2, VolumeX, CheckCircle2, AlertTriangle, AlertCircle, X } from 'lucide-react';
import { TelemetryAlert } from '../types';
import { playCyberTone } from '../utils/audio';

interface HeaderProps {
  windowSeq: number;
  isPaused: boolean;
  onTogglePause: () => void;
  alerts: TelemetryAlert[];
  soundEnabled: boolean;
  onToggleSound: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  windowSeq,
  isPaused,
  onTogglePause,
  alerts,
  soundEnabled,
  onToggleSound
}) => {
  const [utcTime, setUtcTime] = useState('');
  const [showAlertsDropdown, setShowAlertsDropdown] = useState(false);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const hours = String(now.getUTCHours()).padStart(2, '0');
      const minutes = String(now.getUTCMinutes()).padStart(2, '0');
      const seconds = String(now.getUTCSeconds()).padStart(2, '0');
      setUtcTime(`${hours}:${minutes}:${seconds} UTC`);
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <header className="relative w-full border-b border-[#0d213e] bg-[#040a18]/90 backdrop-blur-md px-4 sm:px-6 py-3 z-30">
      <div className="max-w-[1720px] mx-auto flex items-center justify-between">
        {/* Left branding */}
        <div className="flex items-center space-x-3.5">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-lg border border-cyan-500/40 bg-cyan-950/20 shadow-[0_0_15px_rgba(6,182,212,0.25)]">
            <Shield className="w-5 h-5 text-cyan-400" />
            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-cyan-400 animate-ping opacity-75" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-sm sm:text-base font-bold tracking-widest text-slate-100 uppercase font-mono">
                DA-VASKA
              </h1>
            </div>
            <p className="text-[11px] font-mono tracking-wider text-slate-400">
              WORLD MODEL <span className="text-slate-600">/</span> SOC COCKPIT
            </p>
          </div>
        </div>

        {/* Right status & telemetry controls */}
        <div className="flex items-center space-x-3 sm:space-x-5 text-xs font-mono">
          {/* Live telemetry indicator */}
          <div className="hidden md:flex items-center space-x-2 px-2.5 py-1 rounded-full border border-emerald-500/20 bg-emerald-950/20 text-emerald-400">
            <span className={`w-2 h-2 rounded-full bg-emerald-400 ${!isPaused ? 'animate-pulse' : 'opacity-40'}`} />
            <span className="text-[11px] font-semibold tracking-wider">
              {isPaused ? 'TELEMETRY PAUSED' : 'LIVE TELEMETRY'}
            </span>
          </div>

          {/* Window seq & UTC time */}
          <div className="flex items-center space-x-2 text-slate-400 bg-[#071329] px-3 py-1.5 rounded border border-[#11264c]">
            <Wifi className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span className="text-slate-300 font-semibold">WINDOW {windowSeq}</span>
            <span className="text-slate-600">·</span>
            <span className="text-slate-200">{utcTime || '14:32:18 UTC'}</span>
          </div>

          {/* Pause / Resume Button */}
          <button
            onClick={() => {
              if (soundEnabled) playCyberTone('click');
              onTogglePause();
            }}
            title={isPaused ? 'Resume live simulation' : 'Pause live stream'}
            className="flex items-center justify-center w-8 h-8 rounded border border-[#142f5c] bg-[#071329] hover:bg-[#0c2044] text-slate-300 hover:text-cyan-400 transition-colors"
          >
            {isPaused ? <Play className="w-3.5 h-3.5 fill-current" /> : <Pause className="w-3.5 h-3.5 fill-current" />}
          </button>

          {/* Audio toggle */}
          <button
            onClick={() => {
              onToggleSound();
              if (!soundEnabled) playCyberTone('click');
            }}
            title={soundEnabled ? 'Disable Cyber Audio FX' : 'Enable Cyber Audio FX'}
            className="hidden sm:flex items-center justify-center w-8 h-8 rounded border border-[#142f5c] bg-[#071329] hover:bg-[#0c2044] text-slate-300 hover:text-cyan-400 transition-colors"
          >
            {soundEnabled ? <Volume2 className="w-3.5 h-3.5 text-cyan-400" /> : <VolumeX className="w-3.5 h-3.5 text-slate-500" />}
          </button>

          {/* Alerts Bell */}
          <div className="relative">
            <button
              onClick={() => {
                if (soundEnabled) playCyberTone('click');
                setShowAlertsDropdown(!showAlertsDropdown);
              }}
              title="View active alerts"
              className="relative flex items-center justify-center w-8 h-8 rounded border border-[#142f5c] bg-[#071329] hover:bg-[#0c2044] text-slate-300 hover:text-cyan-400 transition-colors"
            >
              <Bell className="w-3.5 h-3.5" />
              <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-rose-500 ring-2 ring-[#071329]" />
            </button>

            {/* Alerts Dropdown Modal */}
            {showAlertsDropdown && (
              <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-lg border border-[#132c57] bg-[#071329] shadow-2xl p-4 z-50 animate-in fade-in slide-in-from-top-2">
                <div className="flex items-center justify-between pb-3 border-b border-[#11264c]">
                  <div className="flex items-center space-x-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    <span className="font-semibold text-slate-200 text-xs tracking-wide">
                      ACTIVE THREAT TELEMETRY ({alerts.length})
                    </span>
                  </div>
                  <button
                    onClick={() => setShowAlertsDropdown(false)}
                    className="text-slate-400 hover:text-white"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <div className="divide-y divide-[#0d213e] max-h-72 overflow-y-auto mt-2 pr-1">
                  {alerts.map((alt) => (
                    <div key={alt.id} className="py-2.5 space-y-1 text-left">
                      <div className="flex items-center justify-between">
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                          alt.severity === 'critical'
                            ? 'bg-rose-950/60 text-rose-400 border border-rose-800/40'
                            : 'bg-amber-950/60 text-amber-400 border border-amber-800/40'
                        }`}>
                          {alt.severity.toUpperCase()}
                        </span>
                        <span className="text-[10px] text-slate-400">{alt.timestamp}</span>
                      </div>
                      <p className="text-[11px] text-slate-200 font-sans leading-snug">{alt.message}</p>
                      <p className="text-[10px] font-mono text-cyan-400/80">
                        {alt.source} ➔ {alt.target} {alt.port ? `:${alt.port}` : ''}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* User Profile Badge */}
          <div className="flex items-center space-x-2 border-l border-[#12284f] pl-3">
            <div className="w-8 h-8 rounded-full border border-cyan-500/30 bg-gradient-to-br from-cyan-950 to-slate-900 flex items-center justify-center text-[11px] font-bold text-cyan-300 shadow-inner">
              AR
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};

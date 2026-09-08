import React, { useState, useEffect } from 'react';
import {
  Pause,
  Play,
  Bell,
  Volume2,
  VolumeX,
  AlertTriangle,
  X,
  Network,
  TrendingUp,
  FlaskConical,
  Cpu,
  Upload,
  Sun,
  Moon,
  Palette,
  Clock
} from 'lucide-react';
import { TelemetryAlert, NavigationTab, CaptureMetadata, AppTheme } from '../types';
import { playCyberTone } from '../utils/audio';
import { VashikaranChakraLogo } from './VashikaranChakraLogo';

interface HeaderProps {
  windowSeq: number;
  isPaused: boolean;
  onTogglePause: () => void;
  alerts: TelemetryAlert[];
  soundEnabled: boolean;
  onToggleSound: () => void;
  activeTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  attackedCount?: number;
  predictedTargetName?: string;
  predictedProbability?: number;
  backendConnected?: boolean;
  activeCapture?: CaptureMetadata | null;
  onOpenUploadModal?: () => void;
  theme?: AppTheme;
  onSelectTheme?: (theme: AppTheme) => void;
}

export const Header: React.FC<HeaderProps> = ({
  windowSeq,
  isPaused,
  onTogglePause,
  alerts,
  soundEnabled,
  onToggleSound,
  activeTab,
  onSelectTab,
  attackedCount = 2,
  predictedTargetName = 'SRV-DC01',
  predictedProbability = 94.2,
  backendConnected = true,
  activeCapture = null,
  onOpenUploadModal,
  theme = 'light',
  onSelectTheme
}) => {
  const [istTime, setIstTime] = useState('');
  const [showAlertsDropdown, setShowAlertsDropdown] = useState(false);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      // Formatted in Indian Standard Time (IST, UTC+5:30)
      const istString = now.toLocaleTimeString('en-IN', {
        timeZone: 'Asia/Kolkata',
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
      const istDate = now.toLocaleDateString('en-IN', {
        timeZone: 'Asia/Kolkata',
        day: 'numeric',
        month: 'short'
      });
      setIstTime(`${istDate}, ${istString} IST`);
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  const navTabs: {
    id: NavigationTab;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: string;
    badgeColor?: string;
  }[] = [
    {
      id: 'main_topology',
      label: 'LIVE NETWORK FEED',
      icon: Network,
      badge: `${attackedCount} Infected · Target: ${predictedTargetName} (${predictedProbability.toFixed(0)}%)`,
      badgeColor: 'bg-rose-950/80 text-rose-300 border-rose-500/40'
    },
    {
      id: 'trajectory',
      label: 'Attack Forecast & Timeline',
      icon: TrendingUp
    },
    {
      id: 'what_if',
      label: 'What-If Defense Simulator',
      icon: FlaskConical
    },
    {
      id: 'explainability',
      label: 'Why the AI Thinks This (Explainability)',
      icon: Cpu
    }
  ];

  const cycleTheme = () => {
    if (!onSelectTheme) return;
    if (soundEnabled) playCyberTone('click');
    if (theme === 'light') onSelectTheme('slate');
    else if (theme === 'slate') onSelectTheme('midnight');
    else onSelectTheme('light');
  };

  const isLight = theme === 'light';
  const isMidnight = theme === 'midnight';

  return (
    <header className={`relative w-full border-b transition-colors z-30 ${
      isLight 
        ? 'bg-white border-slate-200 shadow-xs text-slate-800'
        : isMidnight
        ? 'bg-[#050b16] border-[#102340] text-slate-100'
        : 'bg-[#0b0f19] border-[#182234] text-slate-100'
    }`}>
      {/* 1. TOP BAR: STRICTLY ONLY THE APPLICATION NAME (ENLARGED & APPEALING) */}
      <div className={`max-w-[1720px] mx-auto px-4 sm:px-6 lg:px-8 py-4 sm:py-4.5 flex items-center border-b ${
        isLight ? 'border-slate-100' : isMidnight ? 'border-[#0e1c33]' : 'border-[#141d2d]'
      }`}>
        <div className="flex items-center space-x-3.5 sm:space-x-4">
          <VashikaranChakraLogo size="md" />
          <div>
            <div className="flex items-center space-x-2.5 sm:space-x-3">
              <h1 className={`text-2xl sm:text-3xl font-black tracking-wider uppercase font-mono leading-none ${
                isLight ? 'text-slate-900' : 'text-white'
              }`}>
                VASHIKARAN
              </h1>
              <span className={`px-2.5 py-0.5 rounded text-[10px] sm:text-[11px] font-mono uppercase font-bold tracking-wider ${
                isLight 
                  ? 'bg-cyan-50 text-cyan-700 border border-cyan-200' 
                  : 'bg-cyan-950/70 text-cyan-300 border border-cyan-500/40'
              }`}>
                SOC WORLD MODEL
              </span>
            </div>
            <p className={`text-[11px] sm:text-xs font-mono tracking-wide mt-1 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
              AUTONOMOUS NETWORK FORENSICS & ATTACK PREDICTION
            </p>
          </div>
        </div>
      </div>

      {/* 2. MIDDLE BAR: BACKEND LIVE, DATE/IST & CONTROLS (ABOVE LIVE NETWORK FEED & BELOW VASHIKARAN) */}
      <div className={`w-full border-b transition-colors ${
        isLight 
          ? 'bg-slate-50/80 border-slate-200' 
          : isMidnight 
          ? 'bg-[#040813]/95 border-[#0f1d35]' 
          : 'bg-[#080d17]/95 border-[#152033]'
      }`}>
        <div className="max-w-[1720px] mx-auto px-4 sm:px-6 lg:px-8 py-2 flex items-center justify-end flex-wrap gap-2 sm:gap-2.5">
          {/* Backend Live Badge shifted to right side */}
          <div className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-mono ${
            isLight
              ? 'border-slate-200 bg-white text-slate-600'
              : 'border-slate-800 bg-slate-900/60 text-slate-400'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${backendConnected ? 'bg-emerald-400' : 'bg-amber-400 animate-pulse'}`} />
            <span className="text-[11px] font-medium">
              {backendConnected ? 'Backend Live' : 'Connecting...'}
            </span>
          </div>

          {/* Date & Indian Standard Time (IST) Clock */}
          <div className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-mono ${
            isLight
              ? 'bg-white border-slate-200 text-slate-600'
              : 'bg-slate-900/60 border-slate-800 text-slate-300'
          }`}>
            <Clock className="w-3 h-3 text-slate-400" />
            <span className="font-semibold text-slate-300 text-[11px]">
              {istTime || '15:25:00 IST'}
            </span>
          </div>

            {/* Theme Switcher Button */}
            <button
              onClick={cycleTheme}
              title={`Current theme: ${theme.toUpperCase()}. Click to switch theme.`}
              className={`flex items-center space-x-1 px-2.5 py-1.5 rounded-lg border transition-colors text-xs font-sans font-medium ${
                isLight
                  ? 'bg-white border-slate-300 text-slate-700 hover:bg-slate-100'
                  : 'bg-slate-900/60 border-slate-800 text-slate-300 hover:bg-slate-800'
              }`}
            >
              {theme === 'light' ? (
                <>
                  <Sun className="w-3 h-3 text-amber-500" />
                  <span className="text-[11px]">Light</span>
                </>
              ) : theme === 'slate' ? (
                <>
                  <Palette className="w-3 h-3 text-indigo-400" />
                  <span className="text-[11px]">App Dark</span>
                </>
              ) : (
                <>
                  <Moon className="w-3 h-3 text-cyan-400" />
                  <span className="text-[11px]">Midnight</span>
                </>
              )}
            </button>

            {/* Pause / Resume Button */}
            <button
              onClick={() => {
                if (soundEnabled) playCyberTone('click');
                onTogglePause();
              }}
              title={isPaused ? 'Resume live simulation' : 'Pause live stream'}
              className={`flex items-center justify-center w-7 h-7 rounded-lg border transition-colors ${
                isLight
                  ? 'border-slate-300 bg-white hover:bg-slate-100 text-slate-700'
                  : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-300 hover:text-white'
              }`}
            >
              {isPaused ? <Play className="w-3 h-3 fill-current" /> : <Pause className="w-3 h-3 fill-current" />}
            </button>

            {/* Audio toggle */}
            <button
              onClick={() => {
                onToggleSound();
                if (!soundEnabled) playCyberTone('click');
              }}
              title={soundEnabled ? 'Disable Cyber Audio FX' : 'Enable Cyber Audio FX'}
              className={`flex items-center justify-center w-7 h-7 rounded-lg border transition-colors ${
                isLight
                  ? 'border-slate-300 bg-white hover:bg-slate-100 text-slate-700'
                  : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-300 hover:text-white'
              }`}
            >
              {soundEnabled ? <Volume2 className="w-3 h-3 text-cyan-400" /> : <VolumeX className="w-3 h-3 text-slate-500" />}
            </button>

            {/* Alerts Bell */}
            <div className="relative">
              <button
                onClick={() => {
                  if (soundEnabled) playCyberTone('click');
                  setShowAlertsDropdown(!showAlertsDropdown);
                }}
                title="View active alerts"
                className={`relative flex items-center justify-center w-7 h-7 rounded-lg border transition-colors ${
                  isLight
                    ? 'border-slate-300 bg-white hover:bg-slate-100 text-slate-700'
                    : 'border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-300 hover:text-white'
                }`}
              >
                <Bell className="w-3 h-3" />
                <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-rose-500" />
              </button>

              {/* Alerts Dropdown Modal */}
              {showAlertsDropdown && (
                <div className={`absolute right-0 mt-2 w-80 sm:w-96 rounded-xl border shadow-2xl p-4 z-50 animate-in fade-in slide-in-from-top-2 ${
                  isLight ? 'border-slate-200 bg-white text-slate-800' : 'border-slate-700 bg-slate-900 text-slate-100'
                }`}>
                  <div className={`flex items-center justify-between pb-3 border-b ${
                    isLight ? 'border-slate-200' : 'border-slate-800'
                  }`}>
                    <div className="flex items-center space-x-2">
                      <AlertTriangle className="w-4 h-4 text-amber-500" />
                      <span className="font-mono text-xs font-bold">
                        LIVE ALERTS FEED ({alerts.length})
                      </span>
                    </div>
                    <button
                      onClick={() => setShowAlertsDropdown(false)}
                      className="text-slate-400 hover:text-slate-600 dark:hover:text-white"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                  <div className="divide-y divide-slate-200 dark:divide-slate-800 max-h-72 overflow-y-auto mt-2 pr-1">
                    {alerts.map((alt) => (
                      <div key={alt.id} className="py-2.5 space-y-1 text-left">
                        <div className="flex items-center justify-between">
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                            alt.severity === 'critical'
                              ? 'bg-rose-100 dark:bg-rose-950/60 text-rose-700 dark:text-rose-400 border border-rose-300 dark:border-rose-800/40'
                              : 'bg-amber-100 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 border border-amber-300 dark:border-amber-800/40'
                          }`}>
                            {alt.severity.toUpperCase()}
                          </span>
                          <span className="text-[10px] text-slate-400">{alt.timestamp}</span>
                        </div>
                        <p className="text-[11px] font-sans leading-snug">{alt.message}</p>
                        <p className="text-[10px] font-mono text-cyan-600 dark:text-cyan-400">
                          {alt.source} ➔ {alt.target} {alt.port ? `:${alt.port}` : ''}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

      {/* 3. ROW 3: COCKPIT NAVIGATION (LIVE NETWORK FEED, FORECAST, WHAT-IF, EXPLAINABILITY) */}
      <div className={`w-full overflow-x-auto scrollbar-none transition-colors ${
        isLight ? 'bg-white' : isMidnight ? 'bg-[#03060f]' : 'bg-[#070b14]'
      }`}>
        <div className="max-w-[1720px] mx-auto px-4 sm:px-6 lg:px-8 flex items-center space-x-1 sm:space-x-1.5 py-2">
          {navTabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => {
                  if (soundEnabled) playCyberTone('click');
                  onSelectTab(tab.id);
                }}
                className={`flex items-center space-x-2 px-3 sm:px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium whitespace-nowrap transition-all ${
                  isActive
                    ? isLight
                      ? 'bg-slate-100 text-cyan-950 border border-slate-300 shadow-xs'
                      : 'bg-slate-800/90 text-cyan-300 border border-cyan-500/40 shadow-xs'
                    : isLight
                    ? 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-transparent'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-500' : isLight ? 'text-slate-400' : 'text-slate-500'}`} />
                <span className="font-semibold">{tab.label}</span>
                {tab.id === 'main_topology' && (
                  <span className="relative flex h-2 w-2 ml-0.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500" />
                  </span>
                )}
                {tab.badge && (
                  <span className={`hidden xl:inline-block ml-1 px-1.5 py-0.2 rounded text-[10px] border ${tab.badgeColor || 'bg-slate-700 text-slate-300'}`}>
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};

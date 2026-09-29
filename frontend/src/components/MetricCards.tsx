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

      {/* 3. Predicted stage / Attack Type */}
      <div className={cardBaseClass}>
        <div className="flex items-start space-x-3.5">
          <div className={`p-2.5 rounded-lg border ${
            isLight
              ? 'border-rose-200 bg-rose-50 text-rose-600'
              : 'border-rose-500/30 bg-rose-950/30 text-rose-400'
          }`}>
            <Target className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className={`text-xs font-mono tracking-wider uppercase ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                Detected Attack Type
              </span>
            </div>
            <div className={`text-base sm:text-lg font-bold font-sans leading-tight ${isLight ? 'text-rose-700' : 'text-rose-300'}`}>
              {(() => {
                const text = `${predictedStage} ${mitreTactic}`.toLowerCase();
                if (text.includes('kerberoast') || text.includes('t1558') || text.includes('kerberos')) {
                  return 'Kerberoasting (T1558.003)';
                }
                if (text.includes('psexec') || (text.includes('smb') && text.includes('lateral')) || text.includes('t1021')) {
                  return 'Remote Services: SMB (T1021.002)';
                }
                if (text.includes('eternalblue') || text.includes('doublepulsar') || text.includes('ms17-010') || text.includes('t1210')) {
                  return 'Exploit Remote Services (T1210)';
                }
                if (text.includes('sql') || text.includes('t1190')) {
                  return 'Exploit Public-Facing App (T1190)';
                }
                if (text.includes('modbus') || text.includes('scada') || text.includes('plc') || text.includes('t0855')) {
                  return 'Modbus Override (T0855)';
                }
                if (text.includes('beacon') || text.includes('c2') || text.includes('t1071')) {
                  return 'C2 Application Layer (T1071.001)';
                }
                if (text.includes('syn') || text.includes('flood') || text.includes('t1498')) {
                  return 'Network Denial of Service (T1498)';
                }
                if (text.includes('exfiltration') || text.includes('t1041')) {
                  return 'Exfiltration Over C2 (T1041)';
                }
                if (text.includes('scanning') || text.includes('t1595') || text.includes('recon')) {
                  return 'Active Scanning (T1595)';
                }
                if (text.includes('benign') || text.includes('routine')) {
                  return 'Benign / Routine Traffic';
                }
                return predictedStage || 'Active Network Infiltration';
              })()}
            </div>
            <p className={`text-[11px] font-mono ${isLight ? 'text-slate-600' : 'text-slate-300'}`}>
              {mitreTactic}
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

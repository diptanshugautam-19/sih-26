import React, { useState } from 'react';
import { Lock, User, Eye, EyeOff } from 'lucide-react';
import { AppTheme, AuthUser } from '../types';
import { VashikaranChakraLogo } from './VashikaranChakraLogo';
import { playCyberTone } from '../utils/audio';

interface LoginPageProps {
  onLoginSuccess: (user: AuthUser) => void;
  theme?: AppTheme;
  onSelectTheme?: (theme: AppTheme) => void;
  soundEnabled?: boolean;
}

export const LoginPage: React.FC<LoginPageProps> = ({
  onLoginSuccess,
  theme = 'light',
  soundEnabled = true
}) => {
  const isLight = theme === 'light';
  const isMidnight = theme === 'midnight';

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    const trimmedUser = username.trim();
    const trimmedPass = password.trim();

    if (!trimmedUser) {
      setErrorMessage('Please enter your username');
      return;
    }

    if (!trimmedPass) {
      setErrorMessage('Please enter your password');
      return;
    }

    setIsSubmitting(true);
    if (soundEnabled) playCyberTone('click');

    const displayName = trimmedUser.includes('@') ? trimmedUser.split('@')[0] : trimmedUser;
    const authUser: AuthUser = {
      id: `usr-${Date.now().toString().slice(-6)}`,
      email: trimmedUser.includes('@') ? trimmedUser : `${trimmedUser}@vashikaran.soc`,
      name: displayName,
      role: 'Lead Threat Analyst',
      clearance: 'LEVEL-4 CLEARANCE',
      callsign: displayName.slice(0, 8).toUpperCase(),
      badgeId: `VASH-${Math.floor(1000 + Math.random() * 9000)}`,
      station: 'PRIMARY CONSOLE',
      loginTime: new Date().toLocaleTimeString('en-US', { hour12: false })
    };

    try {
      localStorage.setItem('vashikaran_user', JSON.stringify(authUser));
    } catch {
      // LocalStorage fallback
    }

    if (soundEnabled) playCyberTone('policy');
    onLoginSuccess(authUser);
  };

  return (
    <div className={`min-h-screen flex items-center justify-center p-4 transition-colors duration-200 ${
      isLight
        ? 'bg-slate-100 text-slate-900'
        : isMidnight
        ? 'bg-[#030712] text-slate-100'
        : 'bg-[#0a0f1d] text-slate-100'
    }`}>
      <div className="w-full max-w-md">
        {/* Logo & Header */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center mb-3">
            <VashikaranChakraLogo size="lg" />
          </div>
          <h1 className={`text-2xl sm:text-3xl font-black tracking-wider uppercase font-mono leading-none ${
            isLight ? 'text-slate-900' : 'text-white'
          }`}>
            VASHIKARAN
          </h1>
          <p className={`text-xs font-mono mt-1.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
            Sign in to access the system
          </p>
        </div>

        {/* Clean Login Card */}
        <div className={`rounded-2xl border p-6 sm:p-8 transition-all ${
          isLight
            ? 'bg-white border-slate-200 shadow-lg'
            : isMidnight
            ? 'bg-[#050b17] border-[#132546] shadow-2xl'
            : 'bg-[#0d1527] border-slate-800 shadow-2xl'
        }`}>
          {errorMessage && (
            <div className="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-500 text-xs font-mono">
              {errorMessage}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username Input */}
            <div>
              <label className={`block text-xs font-mono font-semibold uppercase mb-1.5 ${
                isLight ? 'text-slate-700' : 'text-slate-300'
              }`}>
                Username
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  autoFocus
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter your username"
                  className={`w-full pl-9 pr-3 py-2.5 rounded-lg border text-sm font-sans transition-colors outline-none focus:ring-2 focus:ring-cyan-500/30 ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900 focus:border-cyan-500'
                      : 'bg-[#080d19] border-slate-700 text-slate-100 focus:border-cyan-400'
                  }`}
                />
              </div>
            </div>

            {/* Password Input */}
            <div>
              <label className={`block text-xs font-mono font-semibold uppercase mb-1.5 ${
                isLight ? 'text-slate-700' : 'text-slate-300'
              }`}>
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className={`w-full pl-9 pr-10 py-2.5 rounded-lg border text-sm font-sans transition-colors outline-none focus:ring-2 focus:ring-cyan-500/30 ${
                    isLight
                      ? 'bg-slate-50 border-slate-300 text-slate-900 focus:border-cyan-500'
                      : 'bg-[#080d19] border-slate-700 text-slate-100 focus:border-cyan-400'
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-200 cursor-pointer"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Submit Button */}
            <div className="pt-2">
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-2.5 px-4 rounded-lg font-mono text-xs font-bold uppercase tracking-wider bg-cyan-500 hover:bg-cyan-400 text-slate-950 flex items-center justify-center space-x-2 transition-colors cursor-pointer shadow-sm disabled:opacity-50"
              >
                <span>{isSubmitting ? 'Signing In...' : 'Log In'}</span>
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, Eye, EyeOff, Lock, AlertTriangle, Database, Activity,
  FileCheck, Brain, ShieldCheck, CheckCircle,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuthStore } from '@/store/auth.store';
import { authApi } from '@/api/auth.api';
import toast from 'react-hot-toast';

// ─── CSS-only network node positions ────────────────
const NODES = [
  { x: 18, y: 22, highlight: false },
  { x: 52, y: 12, highlight: true },
  { x: 78, y: 28, highlight: false },
  { x: 32, y: 48, highlight: true },
  { x: 65, y: 45, highlight: false },
  { x: 45, y: 70, highlight: true },
  { x: 20, y: 68, highlight: false },
  { x: 75, y: 65, highlight: false },
];

const CONNECTIONS = [
  [0, 1], [1, 2], [0, 3], [1, 4], [3, 4],
  [3, 5], [4, 5], [5, 6], [4, 7], [5, 7],
];

function NetworkVisualization() {
  return (
    <div className="relative w-full h-full">
      {CONNECTIONS.map(([a, b], i) => {
        const nA = NODES[a];
        const nB = NODES[b];
        const dx = nB.x - nA.x;
        const dy = nB.y - nA.y;
        const length = Math.sqrt(dx * dx + dy * dy);
        const angle  = Math.atan2(dy, dx) * (180 / Math.PI);
        return (
          <div
            key={`line-${i}`}
            className="absolute border-t border-[#2D3642]/50"
            style={{
              left: `${nA.x}%`, top: `${nA.y}%`,
              width: `${length}%`,
              transformOrigin: '0 0',
              transform: `rotate(${angle}deg)`,
            }}
          />
        );
      })}
      {NODES.map((node, i) => (
        <div
          key={`node-${i}`}
          className={`absolute w-3 h-3 rounded-full border -translate-x-1/2 -translate-y-1/2 ${
            node.highlight
              ? 'bg-[#16A34A]/30 border-[#16A34A]/50 shadow-[0_0_8px_rgba(22,163,74,0.4)]'
              : 'bg-[#1F2530] border-[#2D3642]'
          }`}
          style={{
            left: `${node.x}%`, top: `${node.y}%`,
            animation: `pulse-node ${2 + (i % 3) * 0.8}s ease-in-out infinite`,
            animationDelay: `${i * 0.3}s`,
          }}
        />
      ))}
      <style>{`
        @keyframes pulse-node {
          0%, 100% { opacity: 0.4; }
          50% { opacity: 1; }
        }
      `}</style>
    </div>
  );
}

const FEATURES = [
  { icon: Shield,     title: 'Zero Trust Authorization',   description: 'Continuous identity verification on every request. Never trust, always verify.' },
  { icon: Brain,      title: 'AI Threat Detection',        description: 'ML-based anomaly detection and pattern recognition across all access layers.' },
  { icon: Database,   title: 'Database Encryption',        description: 'AES-256 field-level encryption protecting sensitive records at rest and in transit.' },
  { icon: Activity,   title: 'Real-Time Monitoring',       description: 'Sub-millisecond event forwarding across infrastructure with live threat feeds.' },
  { icon: FileCheck,  title: 'Enterprise Audit Logging',   description: 'SHA-256 cryptographic hash chaining across every audit event for tamper detection.' },
  { icon: ShieldCheck, title: 'RAG-Powered Incident Analysis', description: 'Retrieval-Augmented Generation for deep, context-aware incident investigation.' },
];

export function LoginPage() {
  const [email,    setEmail]    = useState('');
  const [password, setPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');

  const { login, isAuthenticated } = useAuthStore();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) navigate('/dashboard', { replace: true });
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const response = await authApi.login({ email, password });
      login(response);
      toast.success(`Welcome to Syvora, ${response.user.firstName}!`);
      navigate('/dashboard', { replace: true });
    } catch (err: any) {
      const msg = err?.response?.data?.message ?? 'Invalid credentials. Please try again.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const fillDemo = (role: 'admin' | 'analyst') => {
    if (role === 'admin') { setEmail('admin@zerotrust.com'); setPassword('Admin@123'); }
    else { setEmail('analyst@zerotrust.com'); setPassword('Analyst@123'); }
    setError('');
  };

  return (
    <div className="min-h-screen flex flex-col lg:flex-row bg-[#0E1117]">
      {/* ─── Left Panel (55%) ──────────────────────── */}
      <div className="hidden lg:flex lg:w-[55%] bg-[#0E1117] relative flex-col justify-between p-12">
        {/* Branding */}
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#16A34A]/15 border border-[#16A34A]/25 flex items-center justify-center">
              <span className="text-[#16A34A] font-bold text-xl leading-none">S</span>
            </div>
            <div>
              <p className="text-2xl font-bold text-[#F8FAFC] tracking-tight leading-none">SYVORA</p>
              <p className="text-[11px] text-[#64748B] mt-0.5 tracking-wider uppercase">AI-Powered Zero Trust Security Platform</p>
            </div>
          </div>
        </div>

        {/* Network Graph */}
        <div className="flex-1 relative my-8 max-h-[280px]">
          <NetworkVisualization />
        </div>

        {/* Tagline */}
        <div className="mb-6">
          <p className="text-xl font-semibold text-[#F8FAFC] leading-snug">Secure Every Access.</p>
          <p className="text-xl font-semibold text-[#16A34A] leading-snug">Trust Every Decision.</p>
          <p className="text-sm text-[#64748B] mt-2">Intelligent Zero Trust Security for Modern Enterprises</p>
        </div>

        {/* Trusted stats row */}
        <div className="grid grid-cols-3 gap-3 mb-8">
          {[
            { label: '99.9% Uptime',       desc: 'Enterprise SLA' },
            { label: '< 50ms Detection',   desc: 'Real-time protection' },
            { label: 'Zero Breaches',       desc: 'Cryptographic integrity' },
          ].map((st, i) => (
            <div key={i} className="bg-[#171B22] border border-[#2D3642] rounded-lg px-3 py-3 text-center">
              <p className="text-sm font-semibold text-[#F8FAFC]">{st.label}</p>
              <p className="text-[10px] text-[#64748B] mt-0.5">{st.desc}</p>
            </div>
          ))}
        </div>

        {/* Feature List */}
        <div className="grid grid-cols-2 gap-3">
          {FEATURES.map((f, i) => (
            <div key={i} className="flex items-start gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-[#16A34A]/10 border border-[#16A34A]/20 flex items-center justify-center shrink-0 mt-0.5">
                <f.icon className="w-3.5 h-3.5 text-[#16A34A]" />
              </div>
              <div>
                <p className="text-xs text-[#F8FAFC] font-semibold">{f.title}</p>
                <p className="text-[11px] text-[#64748B] mt-0.5 leading-relaxed">{f.description}</p>
              </div>
            </div>
          ))}
        </div>

        <p className="text-xs text-[#475569] mt-6 flex items-center gap-2">
          <CheckCircle className="w-3.5 h-3.5 text-[#16A34A]" />
          Trusted by Enterprise Security Operations Centers
        </p>
      </div>

      {/* ─── Right Panel (45%) ──────────────────────── */}
      <div className="flex-1 lg:w-[45%] bg-[#171B22] lg:border-l border-[#2D3642] flex items-center justify-center p-8 sm:p-12">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, ease: 'easeOut' }}
          className="w-full max-w-sm"
        >
          {/* Mobile branding */}
          <div className="flex items-center gap-3 mb-8 lg:hidden">
            <div className="w-10 h-10 rounded-xl bg-[#16A34A]/15 border border-[#16A34A]/25 flex items-center justify-center">
              <span className="text-[#16A34A] font-bold text-xl">S</span>
            </div>
            <div>
              <span className="text-xl font-bold text-[#F8FAFC]">SYVORA</span>
              <p className="text-[10px] text-[#64748B] uppercase tracking-wider">AI-Powered Zero Trust Security</p>
            </div>
          </div>

          {/* Platform badge */}
          <div className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-[#1F2530] border border-[#2D3642] text-[10px] text-[#94A3B8] uppercase tracking-wider font-semibold mb-6">
            <Shield className="w-3 h-3 text-[#16A34A]" />
            Syvora Enterprise
          </div>

          {/* Heading */}
          <h1 className="text-xl font-semibold text-[#F8FAFC] mb-1">Welcome Back</h1>
          <p className="text-sm text-[#64748B] mb-6">Sign in to Syvora Security Platform</p>

          {/* Error */}
          <AnimatePresence>
            {error && (
              <motion.div
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="mb-5 p-3 bg-[#DC2626]/10 border border-[#DC2626]/20 rounded-xl flex items-start gap-2"
              >
                <AlertTriangle className="w-4 h-4 text-[#DC2626] shrink-0 mt-0.5" />
                <p className="text-xs text-[#DC2626]">{error}</p>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-xs font-semibold text-[#94A3B8] block mb-1.5">Organization Email</label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@organization.com"
                required
                autoComplete="email"
                className="sentinel-input"
              />
            </div>

            <div>
              <div className="flex justify-between items-center mb-1.5">
                <label className="text-xs font-semibold text-[#94A3B8]">Password</label>
                <a href="#forgot" className="text-[11px] text-[#64748B] hover:text-[#94A3B8] transition-colors">
                  Forgot Password?
                </a>
              </div>
              <div className="relative">
                <input
                  id="password"
                  type={showPass ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                  autoComplete="current-password"
                  className="sentinel-input pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#64748B] hover:text-[#94A3B8] transition-colors"
                >
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Remember Me + MFA */}
            <div className="flex items-center justify-between py-1">
              <label className="flex items-center gap-2 cursor-pointer text-xs text-[#64748B] hover:text-[#94A3B8]">
                <input type="checkbox" className="rounded bg-[#1F2530] border-[#2D3642] text-[#16A34A] focus:ring-0 w-3.5 h-3.5" />
                Remember Me
              </label>
              <span className="text-xs text-[#475569] flex items-center gap-1">
                <ShieldCheck className="w-3 h-3 text-[#16A34A]" />
                MFA Available
              </span>
            </div>

            <button
              type="submit"
              disabled={loading}
              id="login-submit"
              className="sentinel-btn-primary w-full justify-center py-2.5 mt-2 flex items-center gap-2"
            >
              {loading ? (
                <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              ) : <Lock className="w-4 h-4 shrink-0" />}
              {loading ? 'Authenticating…' : 'Secure Login'}
            </button>
          </form>

          {/* Demo Credentials */}
          <div className="mt-6 pt-5 border-t border-[#2D3642]">
            <p className="text-xs text-[#64748B] mb-3 text-center font-medium">Demo Access — Quick Login</p>
            <div className="flex gap-3">
              <button onClick={() => fillDemo('admin')}   className="sentinel-btn-secondary flex-1 text-xs py-2 justify-center">Admin Account</button>
              <button onClick={() => fillDemo('analyst')} className="sentinel-btn-secondary flex-1 text-xs py-2 justify-center">Analyst Account</button>
            </div>
          </div>

          {/* Footer */}
          <div className="mt-8 text-center space-y-1">
            <p className="text-xs text-[#475569] flex items-center justify-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-[#16A34A]" />
              Protected by Syvora Security Engine
            </p>
            <p className="text-[11px] text-[#374151]">Version 1.0 · Enterprise Edition</p>
          </div>
        </motion.div>
      </div>
    </div>
  );
}

import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff, Lock, AlertTriangle } from 'lucide-react'
import { useAuthStore } from '@/store/auth.store'
import { authApi } from '@/api/auth.api'
import toast from 'react-hot-toast'

export function LoginPage() {
  const [email, setEmail]       = useState('')
  const [password, setPassword] = useState('')
  const [showPass, setShowPass] = useState(false)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')

  const { login, isAuthenticated } = useAuthStore()
  const navigate = useNavigate()

  useEffect(() => {
    if (isAuthenticated) navigate('/dashboard', { replace: true })
  }, [isAuthenticated, navigate])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const response = await authApi.login({ email, password })
      login(response)
      toast.success(`Welcome back, ${response.user.firstName}!`)
      navigate('/dashboard', { replace: true })
    } catch (err: any) {
      const msg = err?.response?.data?.message ?? 'Invalid email or password'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const fillDemo = (role: 'admin' | 'analyst') => {
    if (role === 'admin') { setEmail('admin@zerotrust.com'); setPassword('Admin@123') }
    else { setEmail('analyst@zerotrust.com'); setPassword('Analyst@123') }
    setError('')
  }

  return (
    <div className="min-h-screen login-bg flex items-center justify-center p-4">
      {/* Animated background orbs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-brand-600/10 rounded-full blur-3xl animate-pulse" />
        <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-violet-600/10 rounded-full blur-3xl animate-pulse delay-1000" />
      </div>

      <div className="w-full max-w-md relative z-10 animate-in">
        {/* Card */}
        <div className="glass rounded-2xl p-8 shadow-2xl shadow-black/50">
          {/* Logo */}
          <div className="flex flex-col items-center mb-8">
            <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-brand-500 to-violet-600 flex items-center justify-center mb-4 shadow-lg shadow-brand-500/30">
              <Shield className="w-7 h-7 text-white" />
            </div>
            <h1 className="text-2xl font-bold text-white">ZeroTrust Platform</h1>
            <p className="text-sm text-slate-400 mt-1 text-center">
              AI-Powered Security Intelligence
            </p>
          </div>

          {/* Demo Credentials */}
          <div className="mb-5 p-3 rounded-xl bg-brand-500/8 border border-brand-500/15">
            <p className="text-xs text-slate-400 mb-2 font-medium">Quick demo access:</p>
            <div className="flex gap-2">
              <button onClick={() => fillDemo('admin')}
                className="flex-1 py-1.5 px-3 rounded-lg text-xs font-medium bg-violet-500/15 text-violet-300 border border-violet-500/25 hover:bg-violet-500/25 transition-all">
                👤 Admin
              </button>
              <button onClick={() => fillDemo('analyst')}
                className="flex-1 py-1.5 px-3 rounded-lg text-xs font-medium bg-blue-500/15 text-blue-300 border border-blue-500/25 hover:bg-blue-500/25 transition-all">
                🔍 Analyst
              </button>
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="mb-4 p-3 rounded-xl bg-red-500/10 border border-red-500/25 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-xs font-medium text-slate-400 block mb-1.5">Email Address</label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@zerotrust.com"
                required
                autoComplete="email"
                className="input-dark"
              />
            </div>

            <div>
              <label className="text-xs font-medium text-slate-400 block mb-1.5">Password</label>
              <div className="relative">
                <input
                  id="password"
                  type={showPass ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                  autoComplete="current-password"
                  className="input-dark pr-10"
                />
                <button type="button" onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors">
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              id="login-submit"
              className="btn-primary w-full justify-center py-3 mt-2"
            >
              {loading ? (
                <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              ) : (
                <Lock className="w-4 h-4" />
              )}
              {loading ? 'Authenticating…' : 'Sign In Securely'}
            </button>
          </form>

          {/* Security notes */}
          <div className="mt-6 pt-4 border-t border-slate-700/50">
            <div className="flex items-center gap-4 text-xs text-slate-600">
              <span className="flex items-center gap-1"><span className="text-emerald-400">●</span> JWT Auth</span>
              <span className="flex items-center gap-1"><span className="text-blue-400">●</span> RBAC</span>
              <span className="flex items-center gap-1"><span className="text-violet-400">●</span> Zero Trust</span>
            </div>
          </div>
        </div>

        <p className="text-center text-xs text-slate-600 mt-4">
          Zero Trust Security Platform v1.0 — All access is logged and monitored
        </p>
      </div>
    </div>
  )
}

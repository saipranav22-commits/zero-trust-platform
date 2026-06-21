import { Shield, Settings, Key, Bell, Database } from 'lucide-react'
import { Layout } from '@/components/layout/Layout'
import { useAuthStore } from '@/store/auth.store'
import { RoleBadge } from '@/components/ui/Badge'

export function SettingsPage() {
  const { user } = useAuthStore()

  return (
    <Layout title="Settings" subtitle="Platform configuration and account preferences">
      <div className="max-w-2xl space-y-4">

        {/* Account Info */}
        <div className="card p-5">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-8 h-8 rounded-lg bg-brand-500/15 flex items-center justify-center">
              <Shield className="w-4 h-4 text-brand-400" />
            </div>
            <h2 className="font-semibold text-slate-100">Account Information</h2>
          </div>
          <div className="space-y-3">
            {[
              { label: 'Name', val: `${user?.firstName} ${user?.lastName}` },
              { label: 'Email', val: user?.email },
              { label: 'User ID', val: user?.id, mono: true },
            ].map(({ label, val, mono }) => (
              <div key={label} className="flex items-center justify-between py-2 border-b border-slate-700/40 last:border-0">
                <span className="text-sm text-slate-400">{label}</span>
                <span className={`text-sm text-slate-200 ${mono ? 'font-mono text-xs' : ''}`}>{val}</span>
              </div>
            ))}
            <div className="flex items-center justify-between py-2">
              <span className="text-sm text-slate-400">Roles</span>
              <div className="flex gap-1">{user?.roles?.map((r) => <RoleBadge key={r} role={r} />)}</div>
            </div>
          </div>
        </div>

        {/* Security Settings */}
        <div className="card p-5">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-8 h-8 rounded-lg bg-amber-500/15 flex items-center justify-center">
              <Key className="w-4 h-4 text-amber-400" />
            </div>
            <h2 className="font-semibold text-slate-100">Security Settings</h2>
          </div>
          <div className="space-y-3">
            {[
              { label: 'JWT Authentication', val: 'HS256 • 15 min expiry', status: 'active' },
              { label: 'Refresh Token', val: '7 day rotation', status: 'active' },
              { label: 'Brute Force Protection', val: '5 attempts → 15 min lockout', status: 'active' },
              { label: 'Audit Logging', val: 'SHA-256 hash chaining', status: 'active' },
              { label: 'Threat Detection', val: 'SQLi • XSS • Brute Force • Path Traversal', status: 'active' },
              { label: 'AI Assistant (Gemini)', val: 'Configure API key in application.yml', status: 'config' },
            ].map(({ label, val, status }) => (
              <div key={label} className="flex items-center justify-between py-2.5 border-b border-slate-700/40 last:border-0">
                <div>
                  <p className="text-sm text-slate-200">{label}</p>
                  <p className="text-xs text-slate-500 mt-0.5">{val}</p>
                </div>
                <span className={`badge ${
                  status === 'active' ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/25' :
                  'bg-amber-500/15 text-amber-300 border-amber-500/25'
                } border`}>
                  {status === 'active' ? '● Active' : '⚙ Configure'}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Platform Info */}
        <div className="card p-5">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-8 h-8 rounded-lg bg-slate-500/15 flex items-center justify-center">
              <Database className="w-4 h-4 text-slate-400" />
            </div>
            <h2 className="font-semibold text-slate-100">Platform Stack</h2>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {[
              { label: 'Backend', val: 'Spring Boot 3.3.2 • Java 21' },
              { label: 'Database', val: 'PostgreSQL + Flyway' },
              { label: 'Authentication', val: 'JWT + RBAC' },
              { label: 'Frontend', val: 'React 18 + TypeScript' },
              { label: 'AI Provider', val: 'Google Gemini (provider-agnostic)' },
              { label: 'Containerization', val: 'Docker + Docker Compose' },
            ].map(({ label, val }) => (
              <div key={label} className="bg-surface-700 rounded-lg p-3 border border-slate-700/50">
                <p className="text-xs text-slate-500 mb-0.5">{label}</p>
                <p className="text-xs text-slate-300 font-medium">{val}</p>
              </div>
            ))}
          </div>
        </div>

      </div>
    </Layout>
  )
}

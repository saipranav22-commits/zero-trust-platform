import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, ShieldAlert, FileText, Users, Activity,
  Settings, LogOut, Shield, ChevronRight, Lock
} from 'lucide-react'
import { useAuthStore } from '@/store/auth.store'
import { authApi } from '@/api/auth.api'
import toast from 'react-hot-toast'
import clsx from 'clsx'

const navItems = [
  { to: '/dashboard',  icon: LayoutDashboard, label: 'Dashboard'        },
  { to: '/threats',    icon: ShieldAlert,      label: 'Threat Analytics' },
  { to: '/audit',      icon: FileText,         label: 'Audit Logs'       },
  { to: '/activity',   icon: Activity,         label: 'User Activity'    },
  { to: '/users',      icon: Users,            label: 'User Management', adminOnly: true },
  { to: '/ai',         icon: Shield,           label: 'AI Assistant'     },
  { to: '/settings',   icon: Settings,         label: 'Settings'         },
]

export function Sidebar() {
  const { user, refreshToken, logout, hasRole } = useAuthStore()
  const navigate = useNavigate()

  const handleLogout = async () => {
    try {
      if (refreshToken) await authApi.logout(refreshToken)
    } catch { /* swallow */ }
    logout()
    navigate('/login')
    toast.success('Logged out successfully')
  }

  const initials = user
    ? `${user.firstName?.[0] ?? ''}${user.lastName?.[0] ?? ''}`.toUpperCase()
    : '?'

  const isAdmin = hasRole('ADMIN') || hasRole('ROLE_ADMIN')

  return (
    <aside className="fixed left-0 top-0 h-screen w-64 flex flex-col bg-surface-900 border-r border-slate-700/50 z-40">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-slate-700/50">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-brand-500 to-violet-600 flex items-center justify-center shadow-lg shadow-brand-500/25 animate-pulse-glow">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <p className="font-bold text-white text-sm tracking-wide">ZeroTrust</p>
            <p className="text-xs text-slate-500">Security Platform</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
        <p className="px-3 mb-2 text-xs font-semibold text-slate-500 uppercase tracking-widest">
          Security
        </p>
        {navItems.map(({ to, icon: Icon, label, adminOnly }) => {
          if (adminOnly && !isAdmin) return null
          return (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 group',
                isActive
                  ? 'bg-brand-500/15 text-brand-400 border border-brand-500/20'
                  : 'text-slate-400 hover:bg-surface-700 hover:text-slate-200 border border-transparent'
              )}
            >
              {({ isActive }) => (
                <>
                  <Icon className={clsx('w-4 h-4 shrink-0', isActive ? 'text-brand-400' : 'text-slate-500 group-hover:text-slate-300')} />
                  <span className="flex-1">{label}</span>
                  {isActive && <ChevronRight className="w-3 h-3 text-brand-400" />}
                </>
              )}
            </NavLink>
          )
        })}
      </nav>

      {/* User Profile */}
      <div className="px-3 py-3 border-t border-slate-700/50">
        <div className="flex items-center gap-3 px-3 py-2 rounded-lg bg-surface-800 border border-slate-700/30 mb-2">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-brand-500/80 to-violet-600/80 flex items-center justify-center text-xs font-bold text-white shrink-0">
            {initials}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-semibold text-slate-200 truncate">
              {user?.firstName} {user?.lastName}
            </p>
            <p className="text-xs text-slate-500 truncate">{user?.email}</p>
          </div>
          {isAdmin && (
            <span className="text-xs bg-brand-500/20 text-brand-400 px-1.5 py-0.5 rounded border border-brand-500/30 font-medium">
              Admin
            </span>
          )}
        </div>
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-red-400 hover:bg-red-500/10 hover:text-red-300 transition-all duration-150 border border-transparent hover:border-red-500/20"
        >
          <LogOut className="w-4 h-4" />
          Sign Out
        </button>
      </div>
    </aside>
  )
}

import { useState, useEffect } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard,
  ShieldAlert,
  FileText,
  Activity,
  Users,
  Brain,
  Settings,
  ChevronLeft,
  ChevronRight,
  LogOut,
  Cpu,
  Bell,
} from 'lucide-react';
import clsx from 'clsx';
import { useAuthStore } from '@/store/auth.store';
import { authApi } from '@/api/auth.api';
import toast from 'react-hot-toast';

// ─── Navigation Structure ────────────────────────────
interface NavItem {
  label: string;
  icon: React.ElementType;
  path: string;
  requiredRoles?: string[];
  end?: boolean;
}

interface NavGroup {
  group: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    group: 'Overview',
    items: [
      { label: 'Dashboard', icon: LayoutDashboard, path: '/dashboard', end: true },
    ],
  },
  {
    group: 'Threat Center',
    items: [
      { label: 'Threats',  icon: ShieldAlert, path: '/threats',  requiredRoles: ['ADMIN', 'SECURITY_ANALYST', 'AUDITOR'] },
      { label: 'Activity', icon: Activity,    path: '/activity', requiredRoles: ['ADMIN', 'SECURITY_ANALYST', 'AUDITOR'] },
    ],
  },
  {
    group: 'Audit Explorer',
    items: [
      { label: 'Audit Logs', icon: FileText, path: '/audit', requiredRoles: ['ADMIN', 'SECURITY_ANALYST', 'AUDITOR'] },
    ],
  },
  {
    group: 'Notifications',
    items: [
      { label: 'Security Alerts', icon: Bell, path: '/alerts', requiredRoles: ['ADMIN', 'SECURITY_ANALYST', 'AUDITOR'] },
    ],
  },
  {
    group: 'Access Control',
    items: [
      { label: 'Users', icon: Users, path: '/users', requiredRoles: ['ADMIN'] },
    ],
  },
  {
    group: 'AI Security',
    items: [
      { label: 'Syvora AI', icon: Brain, path: '/ai', requiredRoles: ['ADMIN', 'SECURITY_ANALYST'] },
    ],
  },
  {
    group: 'System',
    items: [
      { label: 'Settings', icon: Settings, path: '/settings' },
    ],
  },
];

// ─── Animation variants ──────────────────────────────
const labelVar = {
  visible: { opacity: 1, x: 0,  transition: { duration: 0.15, ease: 'easeOut' as const } },
  hidden:  { opacity: 0, x: -8, transition: { duration: 0.1,  ease: 'easeIn'  as const } },
};

interface SidebarProps {
  collapsed?: boolean;
  onCollapse?: (c: boolean) => void;
}

export default function Sidebar({ collapsed: controlled, onCollapse }: SidebarProps) {
  const [internalCollapsed, setInternalCollapsed] = useState(false);
  const collapsed = controlled ?? internalCollapsed;

  const navigate  = useNavigate();
  const { user, refreshToken, logout, hasRole } = useAuthStore();

  const toggle = () => {
    const next = !collapsed;
    setInternalCollapsed(next);
    onCollapse?.(next);
  };

  useEffect(() => {
    if (controlled !== undefined) setInternalCollapsed(controlled);
  }, [controlled]);

  const handleLogout = async () => {
    try { if (refreshToken) await authApi.logout(refreshToken); } catch {}
    logout();
    toast.success('Signed out of Syvora');
    navigate('/login');
  };

  const userInitial = user
    ? `${user.firstName?.[0] ?? ''}${user.lastName?.[0] ?? ''}`.toUpperCase()
    : '?';

  // Filter nav groups/items by role
  const visibleGroups = NAV_GROUPS.map((g) => ({
    ...g,
    items: g.items.filter((item) => {
      if (!item.requiredRoles) return true;
      return item.requiredRoles.some((r) => hasRole(r));
    }),
  })).filter((g) => g.items.length > 0);

  return (
    <motion.aside
      initial={false}
      animate={{ width: collapsed ? 64 : 240 }}
      transition={{ duration: 0.22, ease: 'easeInOut' as const }}
      className="fixed inset-y-0 left-0 z-40 flex flex-col bg-[#0E1117] border-r border-[#2D3642] overflow-hidden"
    >
      {/* ─── Logo ─────────────────────────────────── */}
      <div className="flex items-center h-14 px-4 gap-3 shrink-0 border-b border-[#2D3642]">
        {/* Syvora logo mark: stylized S */}
        <div className="w-7 h-7 rounded-lg bg-[#16A34A]/15 border border-[#16A34A]/30 flex items-center justify-center shrink-0">
          <span className="text-[#16A34A] font-bold text-sm leading-none tracking-tight select-none">S</span>
        </div>
        <AnimatePresence mode="wait">
          {!collapsed && (
            <motion.div key="brand" variants={labelVar} initial="hidden" animate="visible" exit="hidden">
              <p className="text-sm font-bold text-[#F8FAFC] whitespace-nowrap tracking-tight">SYVORA</p>
              <p className="text-[9px] text-[#475569] whitespace-nowrap tracking-wider uppercase font-medium">AI-Powered Zero Trust Security</p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* ─── Navigation ───────────────────────────── */}
      <nav className="flex-1 overflow-y-auto overflow-x-hidden py-3 px-2 space-y-0">
        {visibleGroups.map((group) => (
          <div key={group.group}>
            <AnimatePresence mode="wait">
              {!collapsed && (
                <motion.p
                  key={`grp-${group.group}`}
                  variants={labelVar}
                  initial="hidden"
                  animate="visible"
                  exit="hidden"
                  className="nav-group-label"
                >
                  {group.group}
                </motion.p>
              )}
            </AnimatePresence>

            {group.items.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.end}
                title={collapsed ? item.label : undefined}
                className={({ isActive }) =>
                  clsx('nav-item', isActive && 'nav-item-active', collapsed && 'justify-center px-0')
                }
              >
                <item.icon className="w-[18px] h-[18px] shrink-0" />
                <AnimatePresence mode="wait">
                  {!collapsed && (
                    <motion.span
                      key={`lbl-${item.label}`}
                      variants={labelVar}
                      initial="hidden"
                      animate="visible"
                      exit="hidden"
                      className="whitespace-nowrap text-sm"
                    >
                      {item.label}
                    </motion.span>
                  )}
                </AnimatePresence>
              </NavLink>
            ))}

            <div className="h-1" />
          </div>
        ))}
      </nav>

      {/* ─── Bottom section ───────────────────────── */}
      <div className="border-t border-[#2D3642] px-2 py-3 space-y-0.5 shrink-0">
        {/* Platform health */}
        <AnimatePresence mode="wait">
          {!collapsed && (
            <motion.div
              key="health"
              variants={labelVar}
              initial="hidden"
              animate="visible"
              exit="hidden"
              className="flex items-center gap-2 px-3 py-2"
            >
              <Cpu className="w-3.5 h-3.5 text-[#475569] shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-[11px] text-[#475569]">Platform Status</p>
                <div className="flex items-center gap-1 mt-0.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#16A34A]" />
                  <span className="text-[10px] text-[#16A34A] font-medium">Operational</span>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* User profile */}
        <div className={clsx('flex items-center gap-3 rounded-lg px-3 py-2', collapsed ? 'justify-center' : '')}>
          <div className="w-7 h-7 rounded-full bg-[#16A34A]/15 border border-[#16A34A]/30 flex items-center justify-center shrink-0">
            <span className="text-xs text-[#16A34A] font-bold">{userInitial}</span>
          </div>
          <AnimatePresence mode="wait">
            {!collapsed && (
              <motion.div key="user" variants={labelVar} initial="hidden" animate="visible" exit="hidden" className="flex flex-col min-w-0">
                <span className="text-xs text-[#F8FAFC] font-semibold truncate">
                  {user ? `${user.firstName} ${user.lastName}` : 'User'}
                </span>
                <span className="text-[11px] text-[#475569] truncate">{user?.email}</span>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Sign out */}
        <button
          onClick={handleLogout}
          title={collapsed ? 'Sign out' : undefined}
          className={clsx(
            'flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-[#64748B] w-full',
            'transition-colors duration-150 hover:text-[#DC2626] hover:bg-[#DC2626]/5',
            collapsed && 'justify-center'
          )}
        >
          <LogOut className="w-[18px] h-[18px] shrink-0" />
          <AnimatePresence mode="wait">
            {!collapsed && (
              <motion.span key="so" variants={labelVar} initial="hidden" animate="visible" exit="hidden" className="whitespace-nowrap">
                Sign Out
              </motion.span>
            )}
          </AnimatePresence>
        </button>

        {/* Collapse toggle */}
        <button
          onClick={toggle}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className={clsx(
            'flex items-center gap-3 rounded-lg px-3 py-2 text-sm text-[#475569] w-full',
            'transition-colors duration-150 hover:text-[#64748B] hover:bg-[#1F2530]',
            collapsed && 'justify-center'
          )}
        >
          {collapsed ? <ChevronRight className="w-[18px] h-[18px]" /> : <ChevronLeft className="w-[18px] h-[18px]" />}
          <AnimatePresence mode="wait">
            {!collapsed && (
              <motion.span key="col" variants={labelVar} initial="hidden" animate="visible" exit="hidden" className="whitespace-nowrap">
                Collapse
              </motion.span>
            )}
          </AnimatePresence>
        </button>
      </div>
    </motion.aside>
  );
}

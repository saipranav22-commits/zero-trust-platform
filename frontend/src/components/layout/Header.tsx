import { RefreshCw, Bell } from 'lucide-react';
import { motion } from 'framer-motion';
import clsx from 'clsx';
import { useAuthStore } from '@/store/auth.store';

interface HeaderProps {
  title?: string;
  subtitle?: string;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export default function Header({ title, subtitle, onRefresh, isRefreshing }: HeaderProps) {
  const { user } = useAuthStore();

  return (
    <header className="h-14 shrink-0 flex items-center justify-between px-6 bg-[#0F1117] border-b border-[#2A2F3A]">
      {/* Left — Page title */}
      <div className="flex flex-col justify-center gap-0.5">
        {title && (
          <h1 className="text-[#F3F4F6] font-medium text-sm leading-tight">{title}</h1>
        )}
        {subtitle && (
          <p className="text-[#6B7280] text-xs leading-tight">{subtitle}</p>
        )}
      </div>

      {/* Right — Controls */}
      <div className="flex items-center gap-1">
        {/* Environment badge */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#171A21] border border-[#2A2F3A] mr-2">
          <span className="relative flex h-1.5 w-1.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#10B981] opacity-75" />
            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-[#10B981]" />
          </span>
          <span className="text-[11px] text-[#9CA3AF] font-medium">Live</span>
        </div>

        {/* Refresh button */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className={clsx(
              'p-2 rounded-lg text-[#6B7280] transition-colors duration-150',
              'hover:text-[#9CA3AF] hover:bg-[#1D212B]',
              'disabled:opacity-50 disabled:cursor-not-allowed'
            )}
          >
            <motion.div
              animate={isRefreshing ? { rotate: 360 } : { rotate: 0 }}
              transition={
                isRefreshing
                  ? { duration: 1, repeat: Infinity, ease: 'linear' }
                  : { duration: 0 }
              }
            >
              <RefreshCw className="w-4 h-4" />
            </motion.div>
          </button>
        )}

        {/* Notification bell */}
        <button
          className="p-2 rounded-lg text-[#6B7280] transition-colors duration-150 hover:text-[#9CA3AF] hover:bg-[#1D212B] relative"
        >
          <Bell className="w-4 h-4" />
          <span className="absolute top-1.5 right-1.5 h-1.5 w-1.5 rounded-full bg-[#EF4444]" />
        </button>
      </div>
    </header>
  );
}

import { useState, type ReactNode } from 'react';
import { motion } from 'framer-motion';
import Sidebar from '@/components/layout/Sidebar';
import { TopBar } from '@/components/layout/TopBar';

interface LayoutProps {
  children: ReactNode;
  title?: string;
  subtitle?: string;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export function Layout({ children, onRefresh, isRefreshing }: LayoutProps) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <div className="flex h-screen bg-[#0E1117] overflow-hidden">
      {/* Sidebar */}
      <Sidebar collapsed={sidebarCollapsed} onCollapse={setSidebarCollapsed} />

      {/* Main area */}
      <motion.div
        className="flex flex-col flex-1 min-w-0"
        initial={false}
        animate={{ marginLeft: sidebarCollapsed ? 64 : 240 }}
        transition={{ duration: 0.22, ease: 'easeInOut' as const }}
      >
        {/* TopBar */}
        <TopBar onRefresh={onRefresh} isRefreshing={isRefreshing} />

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-8">
          <div className="max-w-screen-2xl mx-auto">
            {children}
          </div>
        </main>
      </motion.div>
    </div>
  );
}

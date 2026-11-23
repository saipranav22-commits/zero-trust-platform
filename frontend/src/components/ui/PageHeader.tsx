import { type ReactNode } from 'react';
import { RefreshCw, Download, Brain } from 'lucide-react';

interface PageHeaderProps {
  title: string;
  description?: string;
  icon?: ReactNode;
  lastUpdated?: string;
  onRefresh?: () => void;
  isRefreshing?: boolean;
  onExport?: () => void;
  onAiInsight?: () => void;
  actions?: ReactNode;
}

export function PageHeader({
  title,
  description,
  icon,
  lastUpdated,
  onRefresh,
  isRefreshing,
  onExport,
  onAiInsight,
  actions,
}: PageHeaderProps) {
  return (
    <div className="flex flex-col gap-4 mb-8">
      {/* Title Row */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          {icon && (
            <div className="w-9 h-9 rounded-lg bg-[#16A34A]/10 border border-[#16A34A]/20 flex items-center justify-center shrink-0">
              <span className="text-[#16A34A]">{icon}</span>
            </div>
          )}
          <div>
            <h1 className="text-lg font-semibold text-[#F8FAFC] leading-tight">{title}</h1>
            {description && (
              <p className="text-sm text-[#64748B] mt-0.5">{description}</p>
            )}
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-2 shrink-0">
          {actions}

          {onAiInsight && (
            <button
              onClick={onAiInsight}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium
                         bg-[#16A34A]/10 border border-[#16A34A]/20 text-[#16A34A]
                         hover:bg-[#16A34A]/15 hover:border-[#16A34A]/35 transition-colors"
            >
              <Brain className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">AI Insight</span>
            </button>
          )}

          {onExport && (
            <button
              onClick={onExport}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium
                         bg-[#1F2530] border border-[#2D3642] text-[#94A3B8]
                         hover:text-[#F8FAFC] hover:border-[#3A4150] transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Export</span>
            </button>
          )}

          {onRefresh && (
            <button
              onClick={onRefresh}
              className="w-8 h-8 flex items-center justify-center rounded-lg
                         bg-[#1F2530] border border-[#2D3642] text-[#64748B]
                         hover:text-[#94A3B8] hover:border-[#3A4150] transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
          )}
        </div>
      </div>

      {/* Separator */}
      <div className="border-b border-[#2D3642]" />

      {/* Meta row (last updated) */}
      {lastUpdated && (
        <p className="text-xs text-[#475569]">
          Last updated: <span className="text-[#64748B]">{lastUpdated}</span>
        </p>
      )}
    </div>
  );
}

import React, { type ReactNode } from 'react';
import clsx from 'clsx';
import { ChevronLeft, ChevronRight } from 'lucide-react';

/* ─── Skeleton ─── */

interface SkeletonProps {
  className?: string;
}

export const Skeleton: React.FC<SkeletonProps> = ({ className }) => {
  return <div className={clsx('skeleton', className)} />;
};

/* ─── Empty State ─── */

interface EmptyStateProps {
  icon: ReactNode;
  message: string;
  description?: string;
  action?: ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ icon, message, description, action }) => {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3 text-center px-4">
      <div className="w-12 h-12 rounded-xl bg-[#1F2530] border border-[#2D3642] flex items-center justify-center text-[#64748B] mb-2">
        {icon}
      </div>
      <p className="text-sm font-medium text-[#94A3B8]">{message}</p>
      {description && <p className="text-xs text-[#64748B] max-w-xs">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
};

/* ─── Pagination ─── */

interface PaginationProps {
  page: number;
  totalPages: number;
  totalElements: number;
  size: number;
  onPageChange: (page: number) => void;
}

export const Pagination: React.FC<PaginationProps> = ({
  page,
  totalPages,
  totalElements,
  size,
  onPageChange,
}) => {
  if (totalPages <= 1) return null;

  const startItem = page * size + 1;
  const endItem = Math.min((page + 1) * size, totalElements);

  const getPageNumbers = (): (number | '...')[] => {
    const pages: (number | '...')[] = [];
    const maxVisible = 5;

    if (totalPages <= maxVisible + 2) {
      for (let i = 0; i < totalPages; i++) pages.push(i);
      return pages;
    }

    pages.push(0);

    let start = Math.max(1, page - 1);
    let end = Math.min(totalPages - 2, page + 1);

    if (page <= 2) {
      start = 1;
      end = Math.min(maxVisible - 1, totalPages - 2);
    } else if (page >= totalPages - 3) {
      start = Math.max(1, totalPages - maxVisible);
      end = totalPages - 2;
    }

    if (start > 1) pages.push('...');
    for (let i = start; i <= end; i++) pages.push(i);
    if (end < totalPages - 2) pages.push('...');

    pages.push(totalPages - 1);
    return pages;
  };

  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-[#2D3642] bg-[#171B22]">
      <span className="text-xs text-[#64748B]">
        Showing <span className="font-medium text-[#94A3B8]">{startItem}</span> to{' '}
        <span className="font-medium text-[#94A3B8]">{endItem}</span> of{' '}
        <span className="font-medium text-[#94A3B8]">{totalElements.toLocaleString()}</span> entries
      </span>
      <div className="flex items-center gap-1">
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={page === 0}
          className="p-1.5 rounded bg-[#1F2530] border border-[#2D3642] text-[#94A3B8] hover:text-[#F8FAFC] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          title="Previous Page"
        >
          <ChevronLeft className="w-4 h-4" />
        </button>
        {getPageNumbers().map((p, i) =>
          p === '...' ? (
            <span key={`ellipsis-${i}`} className="px-2 text-xs text-[#64748B]">
              …
            </span>
          ) : (
            <button
              key={p}
              onClick={() => onPageChange(p)}
              className={clsx(
                'min-w-[28px] h-7 px-2 text-xs font-medium rounded transition-colors',
                p === page
                  ? 'bg-[#16A34A] text-white'
                  : 'bg-[#1F2530] border border-[#2D3642] text-[#94A3B8] hover:text-[#F8FAFC]'
              )}
            >
              {p + 1}
            </button>
          )
        )}
        <button
          onClick={() => onPageChange(page + 1)}
          disabled={page >= totalPages - 1}
          className="p-1.5 rounded bg-[#1F2530] border border-[#2D3642] text-[#94A3B8] hover:text-[#F8FAFC] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          title="Next Page"
        >
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};

/* ─── Section Header ─── */

interface SectionHeaderProps {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}

export const SectionHeader: React.FC<SectionHeaderProps> = ({
  title,
  subtitle,
  actions,
}) => {
  return (
    <div className="flex items-center justify-between mb-4">
      <div>
        <h3 className="text-sm font-semibold text-[#F8FAFC]">{title}</h3>
        {subtitle && (
          <p className="text-xs text-[#64748B] mt-0.5">{subtitle}</p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
};

/* ─── Security Score Ring ─── */

interface SecurityScoreRingProps {
  score: number;
}

function getScoreColor(score: number): string {
  if (score >= 80) return '#16A34A';
  if (score >= 60) return '#D97706';
  return '#DC2626';
}

export const SecurityScoreRing: React.FC<SecurityScoreRingProps> = ({ score }) => {
  const size = 120;
  const strokeWidth = 8;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = Math.min(Math.max(score, 0), 100);
  const offset = circumference - (progress / 100) * circumference;
  const color = getScoreColor(score);

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        {/* Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#1F2530"
          strokeWidth={strokeWidth}
        />
        {/* Fill */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.8s ease-out, stroke 0.3s ease' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold text-[#F8FAFC]">{score}</span>
        <span className="text-[10px] text-[#64748B] uppercase tracking-wider">Score</span>
      </div>
    </div>
  );
};

/* ─── Live Dot ─── */

export const LiveDot: React.FC = () => {
  return (
    <span className="relative flex h-2 w-2 mr-1">
      <span className="ping-dot absolute inline-flex h-full w-full rounded-full bg-[#16A34A] opacity-75"></span>
      <span className="relative inline-flex rounded-full h-2 w-2 bg-[#16A34A] live-dot"></span>
    </span>
  );
};

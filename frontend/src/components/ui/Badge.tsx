import React from 'react';
import clsx from 'clsx';
import type {
  Severity,
  ThreatStatus,
  AuditStatus,
  ThreatType,
} from '@/types';

/* ─── Severity Badge ─── */

const severityConfig: Record<Severity, { className: string; label: string }> = {
  CRITICAL: { className: 'severity-critical', label: 'Critical' },
  HIGH: { className: 'severity-high', label: 'High' },
  MEDIUM: { className: 'severity-medium', label: 'Medium' },
  LOW: { className: 'severity-low', label: 'Low' },
};

const severityDotColors: Record<Severity, string> = {
  CRITICAL: 'bg-[#DC2626]',
  HIGH: 'bg-[#D97706]',
  MEDIUM: 'bg-[#64748B]',
  LOW: 'bg-[#16A34A]',
};

export const SeverityBadge: React.FC<{ severity: Severity }> = ({ severity }) => {
  const config = severityConfig[severity];
  if (!config) return null;
  return (
    <span className={clsx(config.className)}>
      <span className={clsx('w-1.5 h-1.5 rounded-full', severityDotColors[severity])} />
      {config.label}
    </span>
  );
};

/* ─── Threat Status Badge ─── */

const statusConfig: Record<ThreatStatus, { className: string; label: string }> = {
  DETECTED: { className: 'status-detected', label: 'Detected' },
  INVESTIGATING: { className: 'status-investigating', label: 'Investigating' },
  RESOLVED: { className: 'status-resolved', label: 'Resolved' },
  FALSE_POSITIVE: { className: 'status-false_positive', label: 'False Positive' },
};

const statusDotColors: Record<ThreatStatus, string> = {
  DETECTED: 'bg-[#DC2626]',
  INVESTIGATING: 'bg-[#D97706]',
  RESOLVED: 'bg-[#16A34A]',
  FALSE_POSITIVE: 'bg-[#64748B]',
};

export const ThreatStatusBadge: React.FC<{ status: ThreatStatus }> = ({ status }) => {
  const config = statusConfig[status];
  if (!config) return null;
  return (
    <span className={clsx(config.className)}>
      <span className={clsx('w-1.5 h-1.5 rounded-full', statusDotColors[status])} />
      {config.label}
    </span>
  );
};

/* ─── Incident Status Badge ─── */

const incidentStatusConfig: Record<import('@/types').IncidentStatus, { className: string; label: string; dotColor: string }> = {
  OPEN:          { className: 'status-detected',      label: 'Open',          dotColor: 'bg-[#DC2626]' },
  ACKNOWLEDGED:  { className: 'status-investigating', label: 'Acknowledged',  dotColor: 'bg-[#3B82F6]' },
  INVESTIGATING: { className: 'status-investigating', label: 'Investigating', dotColor: 'bg-[#D97706]' },
  RESOLVED:      { className: 'status-resolved',      label: 'Resolved',      dotColor: 'bg-[#16A34A]' },
};

export const IncidentStatusBadge: React.FC<{ status: import('@/types').IncidentStatus }> = ({ status }) => {
  const config = incidentStatusConfig[status] || incidentStatusConfig.OPEN;
  return (
    <span className={clsx(config.className)}>
      <span className={clsx('w-1.5 h-1.5 rounded-full', config.dotColor)} />
      {config.label}
    </span>
  );
};

/* ─── Audit Status Badge ─── */

const auditConfig: Record<AuditStatus, { className: string; label: string }> = {
  SUCCESS: { className: 'audit-success', label: 'Success' },
  FAILURE: { className: 'audit-failure', label: 'Failure' },
  BLOCKED: { className: 'audit-blocked', label: 'Blocked' },
};

const auditDotColors: Record<AuditStatus, string> = {
  SUCCESS: 'bg-[#16A34A]',
  FAILURE: 'bg-[#DC2626]',
  BLOCKED: 'bg-[#D97706]',
};

export const AuditStatusBadge: React.FC<{ status: AuditStatus }> = ({ status }) => {
  const config = auditConfig[status];
  if (!config) return null;
  return (
    <span className={clsx(config.className)}>
      <span className={clsx('w-1.5 h-1.5 rounded-full', auditDotColors[status])} />
      {config.label}
    </span>
  );
};

/* ─── Role Badge ─── */

const roleConfig: Record<string, { className: string; label: string }> = {
  ADMIN: { className: 'role-admin', label: 'Admin' },
  SECURITY_ANALYST: { className: 'role-analyst', label: 'Analyst' },
  AUDITOR: { className: 'role-auditor', label: 'Auditor' },
  EMPLOYEE: { className: 'role-employee', label: 'Employee' },
};

export const RoleBadge: React.FC<{ role: string }> = ({ role }) => {
  const clean = role.replace('ROLE_', '').toUpperCase();
  const config = roleConfig[clean] || { className: 'role-employee', label: clean };
  return (
    <span className={clsx(config.className)}>
      {config.label}
    </span>
  );
};

/* ─── Threat Type Label ─── */

const threatTypeLabels: Record<ThreatType, string> = {
  SQL_INJECTION: 'SQL Injection',
  XSS: 'Cross-Site Scripting',
  BRUTE_FORCE: 'Brute Force',
  CREDENTIAL_STUFFING: 'Credential Stuffing',
  DATA_EXFILTRATION: 'Data Exfiltration',
  SUSPICIOUS_ACTIVITY: 'Suspicious Activity',
  PATH_TRAVERSAL: 'Path Traversal',
  COMMAND_INJECTION: 'Command Injection',
};

export const ThreatTypeLabel: React.FC<{ type: ThreatType }> = ({ type }) => {
  return (
    <span className="sentinel-badge bg-[#1F2530] border border-[#2D3642] text-[#94A3B8] text-xs px-2 py-0.5 rounded font-medium">
      {threatTypeLabels[type] ?? type}
    </span>
  );
};

/* ─── Risk Score Badge ─── */

function getRiskScoreColor(score: number): { bg: string; text: string; border: string } {
  if (score >= 70) return { bg: 'bg-[#DC2626]/10', text: 'text-[#FCA5A5]', border: 'border-[#DC2626]/20' };
  if (score >= 40) return { bg: 'bg-[#D97706]/10', text: 'text-[#FCD34D]', border: 'border-[#D97706]/20' };
  return { bg: 'bg-[#16A34A]/10', text: 'text-[#86EFAC]', border: 'border-[#16A34A]/20' };
}

export const RiskScoreBadge: React.FC<{ score: number }> = ({ score }) => {
  const colors = getRiskScoreColor(score);
  return (
    <span
      className={clsx(
        'inline-flex items-center justify-center min-w-[28px] px-1.5 py-0.5 text-xs font-semibold rounded border',
        colors.bg,
        colors.text,
        colors.border
      )}
    >
      {score}
    </span>
  );
};

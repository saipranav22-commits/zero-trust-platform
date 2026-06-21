import clsx from 'clsx'
import type { Severity, ThreatStatus, AuditStatus, ThreatType } from '@/types'

// ─── Severity Badge ──────────────────────────────────
export function SeverityBadge({ severity }: { severity: Severity }) {
  const styles: Record<Severity, string> = {
    CRITICAL: 'severity-critical',
    HIGH:     'severity-high',
    MEDIUM:   'severity-medium',
    LOW:      'severity-low',
  }
  const dots: Record<Severity, string> = {
    CRITICAL: 'bg-red-400',
    HIGH:     'bg-orange-400',
    MEDIUM:   'bg-amber-400',
    LOW:      'bg-emerald-400',
  }
  return (
    <span className={styles[severity]}>
      <span className={clsx('w-1.5 h-1.5 rounded-full inline-block', dots[severity],
        severity === 'CRITICAL' ? 'animate-pulse' : '')} />
      {severity}
    </span>
  )
}

// ─── Threat Status Badge ─────────────────────────────
export function ThreatStatusBadge({ status }: { status: ThreatStatus }) {
  const styles: Record<ThreatStatus, string> = {
    DETECTED:       'status-detected',
    INVESTIGATING:  'status-investigating',
    RESOLVED:       'status-resolved',
    FALSE_POSITIVE: 'status-false_positive',
  }
  const labels: Record<ThreatStatus, string> = {
    DETECTED:       'Detected',
    INVESTIGATING:  'Investigating',
    RESOLVED:       'Resolved',
    FALSE_POSITIVE: 'False Positive',
  }
  return <span className={styles[status]}>{labels[status]}</span>
}

// ─── Audit Status Badge ──────────────────────────────
export function AuditStatusBadge({ status }: { status: AuditStatus }) {
  const styles: Record<AuditStatus, string> = {
    SUCCESS: 'badge bg-emerald-500/15 text-emerald-300 border border-emerald-500/25',
    FAILURE: 'badge bg-red-500/15 text-red-300 border border-red-500/25',
    BLOCKED: 'badge bg-orange-500/15 text-orange-300 border border-orange-500/25',
  }
  return <span className={styles[status]}>{status}</span>
}

// ─── Role Badge ──────────────────────────────────────
export function RoleBadge({ role }: { role: string }) {
  const clean = role.replace('ROLE_', '')
  const styles: Record<string, string> = {
    ADMIN:            'badge bg-violet-500/15 text-violet-300 border border-violet-500/25',
    SECURITY_ANALYST: 'badge bg-blue-500/15 text-blue-300 border border-blue-500/25',
    AUDITOR:          'badge bg-teal-500/15 text-teal-300 border border-teal-500/25',
    EMPLOYEE:         'badge bg-slate-500/15 text-slate-400 border border-slate-500/25',
  }
  return <span className={styles[clean] ?? 'badge bg-slate-500/15 text-slate-400 border border-slate-500/25'}>{clean}</span>
}

// ─── Threat Type Label ───────────────────────────────
export function ThreatTypeLabel({ type }: { type: ThreatType }) {
  const labels: Record<ThreatType, string> = {
    SQL_INJECTION:       'SQL Injection',
    XSS:                 'XSS',
    BRUTE_FORCE:         'Brute Force',
    CREDENTIAL_STUFFING: 'Credential Stuffing',
    DATA_EXFILTRATION:   'Data Exfiltration',
    SUSPICIOUS_ACTIVITY: 'Suspicious Activity',
    PATH_TRAVERSAL:      'Path Traversal',
    COMMAND_INJECTION:   'Command Injection',
  }
  const colors: Record<ThreatType, string> = {
    SQL_INJECTION:       'badge bg-red-500/15 text-red-300 border border-red-500/25',
    XSS:                 'badge bg-orange-500/15 text-orange-300 border border-orange-500/25',
    BRUTE_FORCE:         'badge bg-yellow-500/15 text-yellow-300 border border-yellow-500/25',
    CREDENTIAL_STUFFING: 'badge bg-pink-500/15 text-pink-300 border border-pink-500/25',
    DATA_EXFILTRATION:   'badge bg-purple-500/15 text-purple-300 border border-purple-500/25',
    SUSPICIOUS_ACTIVITY: 'badge bg-slate-500/15 text-slate-300 border border-slate-500/25',
    PATH_TRAVERSAL:      'badge bg-cyan-500/15 text-cyan-300 border border-cyan-500/25',
    COMMAND_INJECTION:   'badge bg-rose-500/15 text-rose-300 border border-rose-500/25',
  }
  return <span className={colors[type]}>{labels[type]}</span>
}

// ─── Risk Score Badge ────────────────────────────────
export function RiskScoreBadge({ score }: { score: number }) {
  const color =
    score >= 75 ? 'bg-red-500/15 text-red-300 border-red-500/25' :
    score >= 50 ? 'bg-orange-500/15 text-orange-300 border-orange-500/25' :
    score >= 25 ? 'bg-amber-500/15 text-amber-300 border-amber-500/25' :
    'bg-emerald-500/15 text-emerald-300 border-emerald-500/25'
  return (
    <span className={clsx('badge border', color)}>
      {score}
    </span>
  )
}

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Search, X, AlertTriangle, Clock, Code, FileWarning, Shield, ExternalLink } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Layout } from '@/components/layout/Layout';
import { PageHeader } from '@/components/ui/PageHeader';
import { SeverityBadge, ThreatTypeLabel, ThreatStatusBadge } from '@/components/ui/Badge';
import { Pagination, EmptyState } from '@/components/ui/Shared';
import { threatApi } from '@/api/threat.api';
import { formatDistanceToNow, format } from 'date-fns';
import toast from 'react-hot-toast';
import type { ThreatEvent, ThreatStatus } from '@/types';

// Static mappings for MITRE, OWASP, and Recommended Actions
const MITRE_MAPPING: Record<string, string> = {
  SQL_INJECTION: 'T1190 – Exploit Public-Facing Application',
  XSS: 'T1059.007 – JavaScript',
  BRUTE_FORCE: 'T1110 – Brute Force',
  CREDENTIAL_STUFFING: 'T1110.004 – Credential Stuffing',
  DATA_EXFILTRATION: 'T1041 – Exfiltration Over C2Channel',
  SUSPICIOUS_ACTIVITY: 'T1078 – Valid Accounts',
  PATH_TRAVERSAL: 'T1083 – File and Directory Discovery',
  COMMAND_INJECTION: 'T1059 – Command and Scripting Interpreter',
};

const OWASP_MAPPING: Record<string, string> = {
  SQL_INJECTION: 'A03:2021 – Injection',
  XSS: 'A03:2021 – Injection',
  BRUTE_FORCE: 'A07:2021 – Identification and Authentication Failures',
  CREDENTIAL_STUFFING: 'A07:2021 – Identification and Authentication Failures',
  DATA_EXFILTRATION: 'A01:2021 – Broken Access Control',
  PATH_TRAVERSAL: 'A01:2021 – Broken Access Control',
  COMMAND_INJECTION: 'A03:2021 – Injection',
  SUSPICIOUS_ACTIVITY: 'A02:2021 – Cryptographic Failures',
};

const RECOMMENDED_ACTIONS: Record<string, string[]> = {
  SQL_INJECTION: [
    'Enable prepared statements / parameterized queries immediately.',
    'Sanitize input patterns in application routing layers.',
    'Inspect database activity logs for administrative commands.',
  ],
  XSS: [
    'Enforce Content Security Policy (CSP) headers.',
    'HTML-encode all dynamic user-provided outputs.',
    'Enable HttpOnly flags on cookie assets.',
  ],
  BRUTE_FORCE: [
    'Temporarily block or rate-limit the attacking source IP.',
    'Check user account lock state in User Management.',
    'Inspect audit events for similar lock/login sequences.',
  ],
  CREDENTIAL_STUFFING: [
    'Enable adaptive multi-factor authentication (MFA).',
    'Review identity database for compromised credentials.',
    'Block malicious bot traffic via WAF rule adjustments.',
  ],
  DATA_EXFILTRATION: [
    'Terminate active session token and force user logout.',
    'Restrict egress traffic on target resource endpoints.',
    'Verify data sensitivity classifications.',
  ],
  PATH_TRAVERSAL: [
    'Enforce strict input path normalization rules.',
    'Check filesystem access control list (ACL) rules.',
    'Audit local resource inclusions in application code.',
  ],
  COMMAND_INJECTION: [
    'Avoid system shell operations in server context.',
    'Filter arguments using whitelist regex blocks.',
    'Verify shell command permission parameters.',
  ],
  SUSPICIOUS_ACTIVITY: [
    'Audit recent log events for flagged user accounts.',
    'Verify authenticity of operations with account owner.',
    'Promote threat incident status for investigation.',
  ],
};

export function ThreatsPage() {
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [selected, setSelected] = useState<ThreatEvent | null>(null);
  const [drawerStatus, setDrawerStatus] = useState<ThreatStatus | ''>('');
  const [statusNote, setStatusNote] = useState('');
  const qc = useQueryClient();

  const filters = {
    sourceIp: search,
    severity: severityFilter,
    status: statusFilter,
  };

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['threats', page, filters],
    queryFn: () => threatApi.getThreats({ ...filters, page, size: 20 }),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, status, notes }: { id: string; status: ThreatStatus; notes?: string }) =>
      threatApi.updateStatus(id, status, notes),
    onSuccess: () => {
      toast.success('Incident status updated successfully');
      setSelected(null);
      setDrawerStatus('');
      setStatusNote('');
      qc.invalidateQueries({ queryKey: ['threats'] });
    },
  });

  const openDrawer = (threat: ThreatEvent) => {
    setSelected(threat);
    setDrawerStatus(threat.status);
    setStatusNote(threat.notes ?? '');
  };

  const closeDrawer = () => {
    setSelected(null);
    setDrawerStatus('');
    setStatusNote('');
  };

  const handleExport = () => {
    if (!data?.content || data.content.length === 0) {
      toast.error('No threat events available to export');
      return;
    }

    const headers = [
      'ID',
      'Threat Type',
      'Severity',
      'Source IP',
      'Target Resource',
      'Target Method',
      'Status',
      'Detection Rule',
      'Created At',
      'Notes'
    ];

    const rows = data.content.map((t) => [
      t.id,
      t.threatType,
      t.severity,
      t.sourceIp ?? '',
      t.targetResource ?? '',
      t.targetMethod ?? '',
      t.status,
      t.detectionRule ?? '',
      t.createdAt,
      t.notes ?? ''
    ]);

    const metadata = [
      '# SYVORA',
      '# AI-Powered Zero Trust Security Platform',
      '# Security Incident Report',
      '# Confidential',
      '# Generated by Syvora AI',
      `# Generated At: ${new Date().toISOString()}`,
      ''
    ].join('\n');

    const csvContent = metadata + [
      headers.join(','),
      ...rows.map(row => row.map(val => `"${val.replace(/"/g, '""')}"`).join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `syvora_threat_report_${Date.now()}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast.success('Security incident report exported successfully');
  };

  const TABLE_HEADERS = ['Type', 'Severity', 'Source IP', 'Target', 'Method', 'Status', 'Detection Rule', 'Time'];

  return (
    <Layout onRefresh={refetch} isRefreshing={isLoading}>
      <PageHeader
        title="Threat Center"
        description="Comprehensive console for threat monitoring, analysis, and containment"
        icon={<Shield className="w-5 h-5" />}
        onRefresh={refetch}
        isRefreshing={isLoading}
        onExport={handleExport}
      />

      {/* ─── Toolbar ──────────────────────────────── */}
      <div className="sentinel-toolbar">
        <div className="relative max-w-xs flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#64748B]" />
          <input
            type="text"
            placeholder="Search by attacker IP…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
            className="sentinel-input pl-9"
          />
        </div>

        <select
          className="sentinel-input w-auto min-w-[140px]"
          value={severityFilter}
          onChange={(e) => {
            setSeverityFilter(e.target.value);
            setPage(0);
          }}
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>

        <select
          className="sentinel-input w-auto min-w-[160px]"
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(0);
          }}
        >
          <option value="">All Statuses</option>
          <option value="DETECTED">Detected</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="RESOLVED">Resolved</option>
          <option value="FALSE_POSITIVE">False Positive</option>
        </select>

        {(search || severityFilter || statusFilter) && (
          <button
            onClick={() => {
              setSearch('');
              setSeverityFilter('');
              setStatusFilter('');
              setPage(0);
            }}
            className="sentinel-btn-ghost text-xs py-1.5"
          >
            Clear Filters
          </button>
        )}

        <div className="ml-auto">
          <span className="text-xs text-[#64748B] font-medium">
            {data?.totalElements ?? 0} active incidents
          </span>
        </div>
      </div>

      {/* ─── Table ────────────────────────────────── */}
      <div className="sentinel-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="sentinel-table">
            <thead className="sentinel-thead">
              <tr>
                {TABLE_HEADERS.map((h) => (
                  <th key={h} className="sentinel-th">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading && Array.from({ length: 8 }).map((_, i) => (
                <tr key={i}>
                  {Array.from({ length: 8 }).map((_, j) => (
                    <td key={j} className="sentinel-td">
                      <div className="skeleton h-4 rounded w-16" />
                    </td>
                  ))}
                </tr>
              ))}
              {!isLoading && !data?.content?.length && (
                <tr>
                  <td colSpan={8}>
                    <EmptyState
                      message="No Critical Threats Detected"
                      description="Your environment is currently secure. Protected by Syvora."
                      icon={<AlertTriangle className="w-6 h-6" />}
                    />
                  </td>
                </tr>
              )}
              {data?.content?.map((t) => (
                <tr
                  key={t.id}
                  onClick={() => openDrawer(t)}
                  className="sentinel-tr-clickable"
                >
                  <td className="sentinel-td"><ThreatTypeLabel type={t.threatType} /></td>
                  <td className="sentinel-td"><SeverityBadge severity={t.severity} /></td>
                  <td className="sentinel-td font-mono text-xs text-[#94A3B8]">{t.sourceIp ?? '—'}</td>
                  <td className="sentinel-td text-xs text-[#94A3B8] max-w-[180px] truncate">{t.targetResource ?? '—'}</td>
                  <td className="sentinel-td text-xs text-[#94A3B8]">{t.targetMethod ?? '—'}</td>
                  <td className="sentinel-td"><ThreatStatusBadge status={t.status} /></td>
                  <td className="sentinel-td font-mono text-xs text-[#64748B] max-w-[140px] truncate">{t.detectionRule ?? '—'}</td>
                  <td className="sentinel-td text-xs text-[#64748B] whitespace-nowrap font-medium">
                    {formatDistanceToNow(new Date(t.createdAt), { addSuffix: true })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {data && data.totalPages > 1 && (
          <Pagination
            page={data.page}
            totalPages={data.totalPages}
            totalElements={data.totalElements}
            size={data.size}
            onPageChange={setPage}
          />
        )}
      </div>

      {/* ─── Side Drawer ──────────────────────────── */}
      <AnimatePresence>
        {selected && (
          <>
            {/* Overlay */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
              className="fixed inset-0 bg-black/60 z-40"
              onClick={closeDrawer}
            />

            {/* Drawer */}
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ duration: 0.22, ease: 'easeOut' }}
              className="fixed right-0 top-0 h-full w-[500px] max-w-full bg-[#171B22] border-l border-[#2D3642] z-50 flex flex-col"
            >
              {/* Drawer Header */}
              <div className="flex items-center justify-between p-5 border-b border-[#2D3642]">
                <div className="flex items-center gap-3">
                  <ThreatTypeLabel type={selected.threatType} />
                  <SeverityBadge severity={selected.severity} />
                </div>
                <button
                  onClick={closeDrawer}
                  className="sentinel-btn-icon"
                  title="Close panel"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Drawer Body */}
              <div className="flex-1 overflow-y-auto p-5 space-y-6">
                {/* Incident Overview Details */}
                <div>
                  <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-3">Incident Overview</h3>
                  <div className="space-y-3">
                    {[
                      { label: 'Detection Rule', value: selected.detectionRule },
                      { label: 'Source IP Address', value: selected.sourceIp, mono: true },
                      { label: 'Target Endpoint', value: selected.targetResource },
                      { label: 'HTTP Method', value: selected.targetMethod },
                      { label: 'User Context', value: selected.userEmail },
                    ].map(({ label, value, mono }) => (
                      <div key={label} className="flex justify-between items-start gap-4">
                        <span className="text-xs text-[#64748B] font-medium">{label}</span>
                        <span className={`text-xs text-[#F8FAFC] text-right break-all max-w-[60%] ${mono ? 'font-mono' : ''}`}>
                          {value ?? '—'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* MITRE & OWASP Framework Mappings */}
                <div className="border-t border-[#2D3642] pt-4">
                  <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-3">Framework Reference</h3>
                  <div className="space-y-2.5">
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-[#64748B] font-medium">MITRE ATT&CK Mapping</span>
                      <span className="sentinel-badge bg-[#1F2530] border-[#2D3642] text-[#F8FAFC]">
                        {MITRE_MAPPING[selected.threatType] ?? 'T1059 – Command execution'}
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-[#64748B] font-medium">OWASP Top 10 Reference</span>
                      <span className="sentinel-badge bg-[#1F2530] border-[#2D3642] text-[#F8FAFC]">
                        {OWASP_MAPPING[selected.threatType] ?? 'A01:2021 – Access Control'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Recommended Mitigation Steps */}
                <div className="border-t border-[#2D3642] pt-4">
                  <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-3">Recommended Actions</h3>
                  <ul className="space-y-2">
                    {(RECOMMENDED_ACTIONS[selected.threatType] ?? RECOMMENDED_ACTIONS.SUSPICIOUS_ACTIVITY).map((action, i) => (
                      <li key={i} className="text-xs text-[#94A3B8] flex items-start gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#16A34A] mt-1.5 shrink-0" />
                        {action}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Attack Payload Code Block */}
                {selected.attackPayload && (
                  <div className="border-t border-[#2D3642] pt-4">
                    <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-3 flex items-center gap-1.5">
                      <Code className="w-3.5 h-3.5 text-[#64748B]" />
                      Attack Payload
                    </h3>
                    <pre className="sentinel-code text-[#DC2626]/85 max-h-40">
                      {selected.attackPayload}
                    </pre>
                  </div>
                )}

                {/* Status Triage Management */}
                <div className="border-t border-[#2D3642] pt-4">
                  <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-3 flex items-center gap-1.5">
                    <FileWarning className="w-3.5 h-3.5 text-[#64748B]" />
                    Triage & Mitigation
                  </h3>
                  <div className="space-y-3">
                    <div>
                      <label className="sentinel-label">Triage Status</label>
                      <select
                        className="sentinel-input bg-[#1F2530]"
                        value={drawerStatus}
                        onChange={(e) => setDrawerStatus(e.target.value as ThreatStatus)}
                      >
                        <option value="DETECTED">Detected</option>
                        <option value="INVESTIGATING">Investigating</option>
                        <option value="RESOLVED">Resolved</option>
                        <option value="FALSE_POSITIVE">False Positive</option>
                      </select>
                    </div>

                    <div>
                      <label className="sentinel-label">Investigation Notes</label>
                      <textarea
                        value={statusNote}
                        onChange={(e) => setStatusNote(e.target.value)}
                        rows={3}
                        placeholder="Add investigation logs, firewall block rules applied, user contact validation details..."
                        className="sentinel-input bg-[#1F2530]"
                      />
                    </div>

                    <button
                      onClick={() =>
                        drawerStatus && updateMutation.mutate({
                          id: selected.id,
                          status: drawerStatus as ThreatStatus,
                          notes: statusNote || undefined,
                        })
                      }
                      disabled={updateMutation.isPending || !drawerStatus}
                      className="sentinel-btn-primary w-full justify-center py-2"
                    >
                      {updateMutation.isPending ? 'Applying changes…' : 'Update Threat Status'}
                    </button>
                  </div>
                </div>

                {/* Event Audit History */}
                <div className="border-t border-[#2D3642] pt-4">
                  <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-3 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-[#64748B]" />
                    Audit Logs
                  </h3>
                  <div className="space-y-2.5">
                    {[
                      { label: 'Event Detected', value: selected.createdAt },
                      { label: 'Last Evaluated', value: selected.updatedAt },
                      ...(selected.resolvedAt ? [{ label: 'Resolved Time', value: selected.resolvedAt }] : []),
                    ].map(({ label, value }) => (
                      <div key={label} className="flex justify-between text-xs">
                        <span className="text-[#64748B] font-medium">{label}</span>
                        <span className="text-[#94A3B8]">
                          {format(new Date(value), 'MMM dd, yyyy HH:mm:ss')}
                        </span>
                      </div>
                    ))}
                    {selected.resolvedBy && (
                      <div className="flex justify-between text-xs">
                        <span className="text-[#64748B] font-medium">Analyst Signature</span>
                        <span className="text-[#94A3B8] font-mono">{selected.resolvedBy}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </Layout>
  );
}

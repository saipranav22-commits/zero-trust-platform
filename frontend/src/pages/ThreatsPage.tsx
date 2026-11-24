import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Search, X, AlertTriangle, Clock, Code, FileWarning, Shield, ExternalLink, Sparkles, Send, UserCheck, CheckCircle2, RotateCcw, ListFilter } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Layout } from '@/components/layout/Layout';
import { PageHeader } from '@/components/ui/PageHeader';
import { SeverityBadge, ThreatTypeLabel, ThreatStatusBadge, IncidentStatusBadge } from '@/components/ui/Badge';
import { Pagination, EmptyState } from '@/components/ui/Shared';
import { threatApi, incidentApi, aiApi } from '@/api/threat.api';
import { formatDistanceToNow, format } from 'date-fns';
import toast from 'react-hot-toast';
import type { ThreatEvent, ThreatStatus, Incident, IncidentStatus } from '@/types';

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
  const [activeTab, setActiveTab] = useState<'threats' | 'incidents'>('threats');
  const qc = useQueryClient();

  // ─── Threat Events State ─────────────────────────────────
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [selected, setSelected] = useState<ThreatEvent | null>(null);
  const [drawerStatus, setDrawerStatus] = useState<ThreatStatus | ''>('');
  const [statusNote, setStatusNote] = useState('');

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
      toast.success('Threat status updated successfully');
      setSelected(null);
      setDrawerStatus('');
      setStatusNote('');
      qc.invalidateQueries({ queryKey: ['threats'] });
    },
  });

  // ─── Incidents State ─────────────────────────────────────
  const [incPage, setIncPage] = useState(0);
  const [incSearch, setIncSearch] = useState('');
  const [incSeverityFilter, setIncSeverityFilter] = useState('');
  const [incStatusFilter, setIncStatusFilter] = useState('');
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [incidentActionNotes, setIncidentActionNotes] = useState('');
  const [assigneeInput, setAssigneeInput] = useState('');
  const [newNoteInput, setNewNoteInput] = useState('');
  const [aiExplanation, setAiExplanation] = useState<string | null>(null);
  const [analyzingAi, setAnalyzingAi] = useState(false);

  const incFilters = {
    search: incSearch,
    severity: incSeverityFilter,
    status: incStatusFilter,
  };

  const { data: incData, isLoading: incLoading, refetch: incRefetch } = useQuery({
    queryKey: ['incidents', incPage, incFilters],
    queryFn: () => incidentApi.getIncidents({ ...incFilters, page: incPage, size: 20 }),
    enabled: activeTab === 'incidents',
  });

  const incStatusMutation = useMutation({
    mutationFn: ({ id, status, notes }: { id: string; status: string; notes?: string }) =>
      incidentApi.updateStatus(id, status, notes),
    onSuccess: (updated) => {
      toast.success(`Incident transitioned to ${updated.status}`);
      setSelectedIncident(updated);
      setIncidentActionNotes('');
      qc.invalidateQueries({ queryKey: ['incidents'] });
    },
    onError: (err: any) => {
      toast.error(err?.response?.data?.message || 'Invalid incident state transition');
    },
  });

  const incAssignMutation = useMutation({
    mutationFn: ({ id, assignedTo }: { id: string; assignedTo: string }) =>
      incidentApi.assign(id, assignedTo, 'Assigned via Incident Management Console'),
    onSuccess: (updated) => {
      toast.success(`Assigned to ${updated.assignedTo}`);
      setSelectedIncident(updated);
      setAssigneeInput('');
      qc.invalidateQueries({ queryKey: ['incidents'] });
    },
  });

  const incNoteMutation = useMutation({
    mutationFn: ({ id, notes }: { id: string; notes: string }) =>
      incidentApi.addNote(id, notes),
    onSuccess: (updated) => {
      toast.success('Investigation note recorded in timeline');
      setSelectedIncident(updated);
      setNewNoteInput('');
      qc.invalidateQueries({ queryKey: ['incidents'] });
    },
  });

  const runAiAnalysis = async (incident: Incident) => {
    setAnalyzingAi(true);
    setAiExplanation(null);
    try {
      const res = await aiApi.explainIncident(incident);
      setAiExplanation(res.explanation);
      toast.success('AI SOC analysis & mitigation plan generated');
    } catch {
      toast.error('Failed to obtain AI analysis');
    } finally {
      setAnalyzingAi(false);
    }
  };

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

  const openIncidentDrawer = (inc: Incident) => {
    setSelectedIncident(inc);
    setIncidentActionNotes('');
    setAssigneeInput(inc.assignedTo || '');
    setNewNoteInput('');
    setAiExplanation(null);
  };

  const closeIncidentDrawer = () => {
    setSelectedIncident(null);
    setIncidentActionNotes('');
    setAiExplanation(null);
  };

  const handleExport = () => {
    if (!data?.content || data.content.length === 0) {
      toast.error('No threat events available to export');
      return;
    }

    const headers = [
      'ID', 'Threat Type', 'Severity', 'Source IP', 'Target Resource',
      'Target Method', 'Status', 'Detection Rule', 'Created At', 'Notes'
    ];

    const rows = data.content.map((t) => [
      t.id, t.threatType, t.severity, t.sourceIp ?? '', t.targetResource ?? '',
      t.targetMethod ?? '', t.status, t.detectionRule ?? '', t.createdAt, t.notes ?? ''
    ]);

    const metadata = [
      '# SYVORA', '# AI-Powered Zero Trust Security Platform',
      '# Security Incident Report', '# Confidential',
      '# Generated by Syvora AI', `# Generated At: ${new Date().toISOString()}`, ''
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
    toast.success('Security report exported successfully');
  };

  const TABLE_HEADERS = ['Type', 'Severity', 'Source IP', 'Target', 'Method', 'Status', 'Detection Rule', 'Time'];
  const INCIDENT_HEADERS = ['Incident #', 'Title', 'Severity', 'Status', 'Correlation ID', 'Target', 'Assigned To', 'Created'];

  return (
    <Layout onRefresh={activeTab === 'threats' ? refetch : incRefetch} isRefreshing={isLoading || incLoading}>
      <PageHeader
        title="Threat & Incident Command Center"
        description="Real-time threat inspection, automated incident triage, and tamper-evident lifecycle containment"
        icon={<Shield className="w-5 h-5" />}
        onRefresh={activeTab === 'threats' ? refetch : incRefetch}
        isRefreshing={isLoading || incLoading}
        onExport={handleExport}
      />

      {/* ─── Mode Selector Tabs ──────────────────────────────── */}
      <div className="flex items-center gap-2 mb-4 border-b border-[#232936] pb-2">
        <button
          onClick={() => setActiveTab('threats')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === 'threats'
              ? 'bg-[#3B82F6]/15 text-[#38BDF8] border border-[#38BDF8]/30 shadow-sm'
              : 'text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#1E293B]'
          }`}
        >
          <Shield className="w-4 h-4" />
          Threat Detection Events
          <span className="ml-1.5 px-2 py-0.5 rounded-full text-[10px] bg-[#1E2533] text-[#94A3B8]">
            {data?.totalElements ?? 0}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('incidents')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
            activeTab === 'incidents'
              ? 'bg-[#3B82F6]/15 text-[#38BDF8] border border-[#38BDF8]/30 shadow-sm'
              : 'text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#1E293B]'
          }`}
        >
          <ListFilter className="w-4 h-4" />
          Security Incidents (Phase 5)
          <span className="ml-1.5 px-2 py-0.5 rounded-full text-[10px] bg-[#1E2533] text-[#94A3B8]">
            {incData?.totalElements ?? 0}
          </span>
        </button>
      </div>

      {activeTab === 'threats' ? (
        <>
          {/* ─── Threat Toolbar ──────────────────────────────── */}
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
                {data?.totalElements ?? 0} active events
              </span>
            </div>
          </div>

          {/* ─── Threat Table ────────────────────────────────── */}
          <div className="sentinel-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="sentinel-table">
                <thead className="sentinel-thead">
                  <tr>
                    {TABLE_HEADERS.map((h) => (
                      <th key={h} className="sentinel-th">{h}</th>
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
              <div className="p-4 border-t border-[#2D3642]">
                <Pagination
                  page={page}
                  totalPages={data.totalPages}
                  totalElements={data.totalElements}
                  size={20}
                  onPageChange={setPage}
                />
              </div>
            )}
          </div>
        </>
      ) : (
        <>
          {/* ─── Incidents Toolbar ───────────────────────────── */}
          <div className="sentinel-toolbar">
            <div className="relative max-w-xs flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#64748B]" />
              <input
                type="text"
                placeholder="Search incidents by title, ID, IP…"
                value={incSearch}
                onChange={(e) => {
                  setIncSearch(e.target.value);
                  setIncPage(0);
                }}
                className="sentinel-input pl-9"
              />
            </div>

            <select
              className="sentinel-input w-auto min-w-[140px]"
              value={incSeverityFilter}
              onChange={(e) => {
                setIncSeverityFilter(e.target.value);
                setIncPage(0);
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
              value={incStatusFilter}
              onChange={(e) => {
                setIncStatusFilter(e.target.value);
                setIncPage(0);
              }}
            >
              <option value="">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="RESOLVED">Resolved</option>
            </select>

            {(incSearch || incSeverityFilter || incStatusFilter) && (
              <button
                onClick={() => {
                  setIncSearch('');
                  setIncSeverityFilter('');
                  setIncStatusFilter('');
                  setIncPage(0);
                }}
                className="sentinel-btn-ghost text-xs py-1.5"
              >
                Clear Filters
              </button>
            )}

            <div className="ml-auto">
              <span className="text-xs text-[#64748B] font-medium">
                {incData?.totalElements ?? 0} incidents tracked
              </span>
            </div>
          </div>

          {/* ─── Incidents Table ─────────────────────────────── */}
          <div className="sentinel-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="sentinel-table">
                <thead className="sentinel-thead">
                  <tr>
                    {INCIDENT_HEADERS.map((h) => (
                      <th key={h} className="sentinel-th">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {incLoading && Array.from({ length: 6 }).map((_, i) => (
                    <tr key={i}>
                      {Array.from({ length: 8 }).map((_, j) => (
                        <td key={j} className="sentinel-td">
                          <div className="skeleton h-4 rounded w-16" />
                        </td>
                      ))}
                    </tr>
                  ))}
                  {!incLoading && !incData?.content?.length && (
                    <tr>
                      <td colSpan={8}>
                        <EmptyState
                          message="No Security Incidents Found"
                          description="Qualifying threats (Critical/High) automatically promote to managed incidents."
                          icon={<Shield className="w-6 h-6" />}
                        />
                      </td>
                    </tr>
                  )}
                  {incData?.content?.map((inc: Incident) => (
                    <tr
                      key={inc.id}
                      onClick={() => openIncidentDrawer(inc)}
                      className="sentinel-tr-clickable"
                    >
                      <td className="sentinel-td font-mono text-xs text-[#38BDF8] font-bold">
                        {inc.incidentNumber}
                      </td>
                      <td className="sentinel-td text-xs text-[#F8FAFC] font-semibold max-w-[220px] truncate">
                        {inc.title}
                      </td>
                      <td className="sentinel-td"><SeverityBadge severity={inc.severity} /></td>
                      <td className="sentinel-td"><IncidentStatusBadge status={inc.status} /></td>
                      <td className="sentinel-td font-mono text-[11px] text-[#64748B]">
                        {inc.correlationId ? `${inc.correlationId.slice(0, 10)}…` : '—'}
                      </td>
                      <td className="sentinel-td text-xs text-[#94A3B8] max-w-[150px] truncate">
                        {inc.targetResource ?? '—'}
                      </td>
                      <td className="sentinel-td text-xs text-[#E2E8F0]">
                        {inc.assignedTo ? (
                          <span className="flex items-center gap-1.5 font-medium text-[#38BDF8]">
                            <UserCheck className="w-3 h-3" />
                            {inc.assignedTo}
                          </span>
                        ) : (
                          <span className="text-[#64748B] italic">Unassigned</span>
                        )}
                      </td>
                      <td className="sentinel-td text-xs text-[#64748B] whitespace-nowrap font-medium">
                        {formatDistanceToNow(new Date(inc.createdAt), { addSuffix: true })}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {incData && incData.totalPages > 1 && (
              <div className="p-4 border-t border-[#2D3642]">
                <Pagination
                  page={incPage}
                  totalPages={incData.totalPages}
                  totalElements={incData.totalElements}
                  size={20}
                  onPageChange={setIncPage}
                />
              </div>
            )}
          </div>
        </>
      )}

      {/* ─── Threat Drawer ─────────────────────────────────── */}
      <AnimatePresence>
        {selected && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={closeDrawer}
              className="sentinel-drawer-overlay"
            />
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 28, stiffness: 300 }}
              className="sentinel-drawer"
            >
              <div className="flex items-center justify-between p-6 border-b border-[#2D3642]">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-xl bg-[#DC2626]/10 border border-[#DC2626]/20 flex items-center justify-center">
                    <AlertTriangle className="w-4 h-4 text-[#DC2626]" />
                  </div>
                  <div>
                    <h2 className="text-sm font-semibold text-[#F8FAFC]">Threat Analysis</h2>
                    <p className="text-xs text-[#64748B] font-mono mt-0.5">{selected.id}</p>
                  </div>
                </div>
                <button onClick={closeDrawer} className="p-1.5 rounded-lg text-[#64748B] hover:text-[#F8FAFC] hover:bg-[#1F2530] transition-colors">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-6 space-y-6">
                <div>
                  <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-3">Classification</h3>
                  <div className="space-y-2.5">
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-[#64748B] font-medium">Threat Pattern</span>
                      <ThreatTypeLabel type={selected.threatType} />
                    </div>
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-[#64748B] font-medium">Assigned Severity</span>
                      <SeverityBadge severity={selected.severity} />
                    </div>
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-[#64748B] font-medium">Lifecycle Status</span>
                      <ThreatStatusBadge status={selected.status} />
                    </div>
                  </div>
                </div>

                <div className="border-t border-[#2D3642] pt-4">
                  <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-3">Target Details</h3>
                  <div className="space-y-2.5 font-mono text-xs">
                    <div className="flex justify-between">
                      <span className="text-[#64748B]">Origin IP</span>
                      <span className="text-[#94A3B8]">{selected.sourceIp ?? '—'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#64748B]">HTTP Method</span>
                      <span className="text-[#94A3B8]">{selected.targetMethod ?? '—'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#64748B]">Endpoint Path</span>
                      <span className="text-[#94A3B8] break-all max-w-[200px] text-right">{selected.targetResource ?? '—'}</span>
                    </div>
                    {selected.correlationId && (
                      <div className="flex justify-between">
                        <span className="text-[#64748B]">Correlation ID</span>
                        <span className="text-[#38BDF8]">{selected.correlationId}</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="border-t border-[#2D3642] pt-4">
                  <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-3">Triage & Status</h3>
                  <div className="space-y-3">
                    <div>
                      <label className="sentinel-label">Status</label>
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
                      <label className="sentinel-label">Notes</label>
                      <textarea
                        value={statusNote}
                        onChange={(e) => setStatusNote(e.target.value)}
                        rows={3}
                        placeholder="Add investigation logs, firewall block rules applied..."
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
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      {/* ─── Incident Drawer (Phase 5) ────────────────────── */}
      <AnimatePresence>
        {selectedIncident && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={closeIncidentDrawer}
              className="sentinel-drawer-overlay"
            />
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 28, stiffness: 300 }}
              className="sentinel-drawer max-w-lg"
            >
              <div className="flex items-center justify-between p-6 border-b border-[#2D3642]">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-xl bg-[#3B82F6]/10 border border-[#38BDF8]/20 flex items-center justify-center">
                    <Shield className="w-4 h-4 text-[#38BDF8]" />
                  </div>
                  <div>
                    <h2 className="text-sm font-semibold text-[#F8FAFC]">
                      {selectedIncident.incidentNumber}
                    </h2>
                    <p className="text-xs text-[#94A3B8] max-w-[280px] truncate">{selectedIncident.title}</p>
                  </div>
                </div>
                <button onClick={closeIncidentDrawer} className="p-1.5 rounded-lg text-[#64748B] hover:text-[#F8FAFC] hover:bg-[#1F2530] transition-colors">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-6 space-y-6 overflow-y-auto max-h-[calc(100vh-100px)]">
                {/* Status & Severity Badges */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={selectedIncident.severity} />
                    <IncidentStatusBadge status={selectedIncident.status} />
                  </div>
                  <span className="text-[11px] font-mono text-[#64748B]">
                    Created {format(new Date(selectedIncident.createdAt), 'MMM dd, HH:mm')}
                  </span>
                </div>

                {/* Metadata */}
                <div className="bg-[#11141B] border border-[#232936] rounded-xl p-4 space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-[#64748B]">Category</span>
                    <span className="text-[#F8FAFC] font-semibold">{selectedIncident.category}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#64748B]">Attacker IP</span>
                    <span className="font-mono text-[#94A3B8]">{selectedIncident.sourceIp || '—'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#64748B]">Target Resource</span>
                    <span className="font-mono text-[#94A3B8]">{selectedIncident.targetResource || '—'}</span>
                  </div>
                  {selectedIncident.correlationId && (
                    <div className="flex justify-between">
                      <span className="text-[#64748B]">Correlation ID</span>
                      <span className="font-mono text-[#38BDF8]">{selectedIncident.correlationId}</span>
                    </div>
                  )}
                  <div className="flex justify-between">
                    <span className="text-[#64748B]">Assigned Analyst</span>
                    <span className="text-[#38BDF8] font-medium">{selectedIncident.assignedTo || 'Unassigned'}</span>
                  </div>
                </div>

                {/* State Transition Actions */}
                <div className="border-t border-[#2D3642] pt-4">
                  <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-3">
                    Lifecycle Actions (Current: {selectedIncident.status})
                  </h3>

                  <div className="space-y-3">
                    {selectedIncident.status === 'OPEN' && (
                      <div className="grid grid-cols-2 gap-2">
                        <button
                          onClick={() => incStatusMutation.mutate({ id: selectedIncident.id, status: 'ACKNOWLEDGED' })}
                          disabled={incStatusMutation.isPending}
                          className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-[#3B82F6]/10 text-[#38BDF8] border border-[#38BDF8]/30 hover:bg-[#3B82F6]/20 text-xs font-semibold"
                        >
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Acknowledge
                        </button>
                        <button
                          onClick={() => incStatusMutation.mutate({ id: selectedIncident.id, status: 'INVESTIGATING' })}
                          disabled={incStatusMutation.isPending}
                          className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-[#D97706]/10 text-[#F59E0B] border border-[#F59E0B]/30 hover:bg-[#D97706]/20 text-xs font-semibold"
                        >
                          <Shield className="w-3.5 h-3.5" />
                          Investigate
                        </button>
                      </div>
                    )}

                    {selectedIncident.status === 'ACKNOWLEDGED' && (
                      <button
                        onClick={() => incStatusMutation.mutate({ id: selectedIncident.id, status: 'INVESTIGATING' })}
                        disabled={incStatusMutation.isPending}
                        className="w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-[#D97706]/10 text-[#F59E0B] border border-[#F59E0B]/30 hover:bg-[#D97706]/20 text-xs font-semibold"
                      >
                        <Shield className="w-3.5 h-3.5" />
                        Begin Investigation
                      </button>
                    )}

                    {selectedIncident.status === 'INVESTIGATING' && (
                      <div className="space-y-2">
                        <textarea
                          value={incidentActionNotes}
                          onChange={(e) => setIncidentActionNotes(e.target.value)}
                          placeholder="Required resolution notes (mitigation applied, root cause verified)…"
                          className="sentinel-input bg-[#1F2530]"
                          rows={2}
                        />
                        <button
                          onClick={() => incStatusMutation.mutate({
                            id: selectedIncident.id,
                            status: 'RESOLVED',
                            notes: incidentActionNotes
                          })}
                          disabled={incStatusMutation.isPending || !incidentActionNotes.trim()}
                          className="w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-[#16A34A]/10 text-[#22C55E] border border-[#22C55E]/30 hover:bg-[#16A34A]/20 text-xs font-semibold disabled:opacity-50"
                        >
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Resolve Incident
                        </button>
                      </div>
                    )}

                    {selectedIncident.status === 'RESOLVED' && (
                      <div className="space-y-2">
                        <div className="p-3 bg-[#16A34A]/10 border border-[#16A34A]/20 rounded-lg text-xs text-[#22C55E]">
                          <p className="font-semibold">Incident Resolved</p>
                          <p className="mt-1 text-[#86EFAC]">{selectedIncident.resolutionNotes || 'No notes provided'}</p>
                        </div>
                        <textarea
                          value={incidentActionNotes}
                          onChange={(e) => setIncidentActionNotes(e.target.value)}
                          placeholder="Required reopening justification…"
                          className="sentinel-input bg-[#1F2530]"
                          rows={2}
                        />
                        <button
                          onClick={() => incStatusMutation.mutate({
                            id: selectedIncident.id,
                            status: 'OPEN',
                            notes: incidentActionNotes
                          })}
                          disabled={incStatusMutation.isPending || !incidentActionNotes.trim()}
                          className="w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-[#DC2626]/10 text-[#EF4444] border border-[#EF4444]/30 hover:bg-[#DC2626]/20 text-xs font-semibold disabled:opacity-50"
                        >
                          <RotateCcw className="w-3.5 h-3.5" />
                          Documented Reopen Incident
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* Assign Analyst */}
                <div className="border-t border-[#2D3642] pt-4">
                  <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-2">Assign Analyst</h3>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      placeholder="Analyst email or identifier…"
                      value={assigneeInput}
                      onChange={(e) => setAssigneeInput(e.target.value)}
                      className="sentinel-input bg-[#1F2530] text-xs"
                    />
                    <button
                      onClick={() => assigneeInput.trim() && incAssignMutation.mutate({
                        id: selectedIncident.id,
                        assignedTo: assigneeInput.trim()
                      })}
                      disabled={incAssignMutation.isPending || !assigneeInput.trim()}
                      className="px-3 py-1.5 rounded-lg bg-[#1E293B] text-xs font-medium text-[#F8FAFC] border border-[#334155] hover:bg-[#334155] disabled:opacity-50"
                    >
                      Assign
                    </button>
                  </div>
                </div>

                {/* Add Investigation Note */}
                <div className="border-t border-[#2D3642] pt-4">
                  <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-2">Record Investigation Note</h3>
                  <div className="flex gap-2">
                    <textarea
                      rows={2}
                      placeholder="Add forensic observations, IP block confirmations…"
                      value={newNoteInput}
                      onChange={(e) => setNewNoteInput(e.target.value)}
                      className="sentinel-input bg-[#1F2530] text-xs flex-1"
                    />
                    <button
                      onClick={() => newNoteInput.trim() && incNoteMutation.mutate({
                        id: selectedIncident.id,
                        notes: newNoteInput.trim()
                      })}
                      disabled={incNoteMutation.isPending || !newNoteInput.trim()}
                      className="px-3 py-1.5 rounded-lg bg-[#3B82F6] text-xs font-medium text-white hover:bg-[#2563EB] disabled:opacity-50 self-end"
                    >
                      <Send className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Gemini AI Incident Analysis */}
                <div className="border-t border-[#2D3642] pt-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5 text-[#38BDF8]" />
                      AI SOC Containment Assistant
                    </h3>
                    <button
                      onClick={() => runAiAnalysis(selectedIncident)}
                      disabled={analyzingAi}
                      className="flex items-center gap-1 text-[11px] font-semibold text-[#38BDF8] hover:underline disabled:opacity-50"
                    >
                      {analyzingAi ? 'Analyzing…' : 'Generate Mitigation Plan'}
                    </button>
                  </div>

                  {aiExplanation && (
                    <div className="p-3 bg-[#0F172A] border border-[#1E293B] rounded-xl text-xs text-[#CBD5E1] whitespace-pre-wrap font-sans leading-relaxed">
                      {aiExplanation}
                    </div>
                  )}
                </div>

                {/* Historical Timeline */}
                <div className="border-t border-[#2D3642] pt-4">
                  <h3 className="text-xs font-semibold text-[#64748B] uppercase tracking-wider mb-3 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-[#64748B]" />
                    Incident Historical Timeline
                  </h3>

                  <div className="space-y-3 relative before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#232936]">
                    {selectedIncident.timeline?.map((entry) => (
                      <div key={entry.id} className="relative flex items-start gap-3 pl-6">
                        <span className="absolute left-1 top-1 w-2.5 h-2.5 rounded-full bg-[#38BDF8] border-2 border-[#0F172A]" />
                        <div className="flex-1">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-semibold text-[#F8FAFC]">{entry.action}</span>
                            <span className="text-[10px] text-[#64748B]">
                              {format(new Date(entry.createdAt), 'MM/dd HH:mm:ss')}
                            </span>
                          </div>
                          <p className="text-[11px] text-[#94A3B8] mt-0.5">
                            By <span className="font-mono text-[#CBD5E1]">{entry.performedBy}</span>
                          </p>
                          {entry.notes && (
                            <p className="text-xs text-[#E2E8F0] bg-[#11141B] border border-[#1E293B] rounded-lg p-2 mt-1.5">
                              {entry.notes}
                            </p>
                          )}
                        </div>
                      </div>
                    ))}
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

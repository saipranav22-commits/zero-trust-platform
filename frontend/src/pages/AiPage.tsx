import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Brain, ShieldAlert, FileBarChart, Send, Sparkles, Copy, Clock, MessageSquare } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import ReactMarkdown from 'react-markdown';
import clsx from 'clsx';
import { Layout } from '@/components/layout/Layout';
import { PageHeader } from '@/components/ui/PageHeader';
import { aiApi } from '@/api/threat.api';
import type { ThreatType, Severity } from '@/types';
import toast from 'react-hot-toast';

const tabs = [
  { id: 'general', label: 'General Query', icon: Brain },
  { id: 'threat', label: 'Threat Analysis', icon: ShieldAlert },
  { id: 'report', label: 'Posture Report', icon: FileBarChart },
] as const;

type TabId = (typeof tabs)[number]['id'];

const severityOptions = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
const threatTypeOptions = [
  'SQL_INJECTION',
  'XSS',
  'BRUTE_FORCE',
  'CREDENTIAL_STUFFING',
  'DATA_EXFILTRATION',
  'SUSPICIOUS_ACTIVITY',
  'PATH_TRAVERSAL',
  'COMMAND_INJECTION',
] as const;

const SUGGESTED = [
  {
    cat: "Security Overview",
    qs: ["What happened today?", "Show today's security summary", "Show active threats", "Show blocked attacks", "Show security score"]
  },
  {
    cat: "Threat Analysis",
    qs: ["Explain this SQL Injection attack", "Explain this XSS attempt", "Why was this request blocked?", "Show attack timeline", "Which attack is the most dangerous?"]
  },
  {
    cat: "Risk Analysis",
    qs: ["Who are the highest-risk users?", "Why is this user considered high risk?", "Show suspicious login behavior", "Explain risk score calculation"]
  },
  {
    cat: "Audit Logs",
    qs: ["Show today's audit events", "Explain this audit log", "Show related events", "Find unusual activity"]
  },
  {
    cat: "Database Protection",
    qs: ["Show encrypted table access", "Which users accessed sensitive records?", "Detect abnormal database activity", "Show recent protected records"]
  },
  {
    cat: "Access Control",
    qs: ["Why was access denied?", "Show failed login attempts", "Show MFA failures", "Explain authorization decision"]
  },
  {
    cat: "Threat Intelligence",
    qs: ["Predict future attacks", "Show MITRE ATT&CK mapping", "Show OWASP attack categories", "Generate attack summary"]
  },
  {
    cat: "Incident Reports",
    qs: ["Generate executive summary", "Generate incident report", "Suggest mitigation steps", "Explain business impact"]
  },
  {
    cat: "Compliance",
    qs: ["Show compliance violations", "Explain policy failures", "Generate compliance report"]
  },
  {
    cat: "System Health",
    qs: ["Show Kafka status", "Show Redis status", "Show AI service health", "Show ML service health", "Show overall platform health"]
  },
];

export function AiPage() {
  const [activeTab, setActiveTab] = useState<TabId>('general');
  const [chatQuestion, setChatQuestion] = useState('');
  const [threatForm, setThreatForm] = useState<{
    threatType: ThreatType;
    severity: Severity;
    sourceIp: string;
    attackPayload: string;
    detectionRule: string;
    targetResource: string;
  }>({
    threatType: 'SQL_INJECTION',
    severity: 'HIGH',
    sourceIp: '',
    attackPayload: '',
    detectionRule: '',
    targetResource: '',
  });
  const [reportForm, setReportForm] = useState({
    totalThreats: '',
    criticalThreats: '',
    failedLogins: '',
    securityScore: '',
  });
  const [result, setResult] = useState<string | null>(null);
  const [resultType, setResultType] = useState<string>('');
  
  // Local state for recent queries tracker
  const [recentInsights, setRecentInsights] = useState<Array<{ q: string; a: string; time: string }>>([]);

  const addRecentInsight = (q: string, a: string) => {
    const snippet = a.replace(/[*#`_\-]/g, '').slice(0, 70) + '...';
    setRecentInsights((prev) => [
      { q, a: snippet, time: new Date().toLocaleTimeString() },
      ...prev.slice(0, 2),
    ]);
  };

  const chatMutation = useMutation({
    mutationFn: (question: string) => aiApi.chat(question),
    onSuccess: (data: any) => {
      const ans = data.answer || data.response || data.message || JSON.stringify(data);
      setResult(ans);
      setResultType('chat');
      addRecentInsight(chatQuestion, ans);
    },
  });

  const explainMutation = useMutation({
    mutationFn: (payload: typeof threatForm) => aiApi.explainThreat(payload),
    onSuccess: (data: any) => {
      const ans = data.explanation || data.response || JSON.stringify(data);
      setResult(ans);
      setResultType('threat');
      addRecentInsight(`Explain ${threatForm.threatType}`, ans);
    },
  });

  const reportMutation = useMutation({
    mutationFn: (payload: Record<string, number>) => aiApi.generateReport(payload),
    onSuccess: (data: any) => {
      const ans = data.report || data.response || JSON.stringify(data);
      setResult(ans);
      setResultType('report');
      addRecentInsight('Generate Posture Report', ans);
    },
  });

  const isLoading =
    chatMutation.isPending || explainMutation.isPending || reportMutation.isPending;

  const handleSubmit = () => {
    // Inject formatting constraints to enforce the requested SOC reporting structure
    const formatConstraint = "\n\n[INSTRUCTION: Format the output as a professional cybersecurity response from Syvora AI. Ensure the response strictly includes these sections: Executive Summary, Threat Classification, Confidence Score, Root Cause, Technical Analysis, Business Impact, Affected Resources, MITRE ATT&CK Mapping, OWASP Reference, Recommended Actions, Related Incidents, References]";

    if (activeTab === 'general') {
      if (!chatQuestion.trim()) return;
      chatMutation.mutate(chatQuestion + formatConstraint);
    } else if (activeTab === 'threat') {
      explainMutation.mutate({
        ...threatForm,
        attackPayload: threatForm.attackPayload + formatConstraint,
      });
    } else {
      reportMutation.mutate({
        totalThreats: Number(reportForm.totalThreats) || 0,
        criticalThreats: Number(reportForm.criticalThreats) || 0,
        failedLogins: Number(reportForm.failedLogins) || 0,
        securityScore: Number(reportForm.securityScore) || 0,
      });
    }
  };

  const updateThreatForm = (field: string, value: string) =>
    setThreatForm((prev) => ({ ...prev, [field]: value }));

  const updateReportForm = (field: string, value: string) =>
    setReportForm((prev) => ({ ...prev, [field]: value }));

  const copyToClipboard = () => {
    if (result) {
      navigator.clipboard.writeText(result);
      toast.success('Copied analysis to clipboard');
    }
  };

  return (
    <Layout onRefresh={handleSubmit} isRefreshing={isLoading}>
      <PageHeader
        title="Syvora AI"
        description="Enterprise Security Copilot"
        icon={<Brain className="w-5 h-5" />}
      />

      <div className="grid grid-cols-12 gap-6">
        {/* LEFT COLUMN: Suggested Questions */}
        <div className="col-span-12 lg:col-span-3 space-y-4 max-h-[80vh] overflow-y-auto pr-1">
          <div className="sentinel-card p-4 space-y-4">
            <h2 className="text-xs font-semibold text-[#F8FAFC] flex items-center gap-2 uppercase tracking-wider">
              <Sparkles className="w-3.5 h-3.5 text-[#16A34A]" />
              Suggested Queries
            </h2>
            <div className="space-y-4">
              {SUGGESTED.map((grp) => (
                <div key={grp.cat} className="space-y-1.5">
                  <p className="text-[10px] font-semibold text-[#475569] uppercase tracking-wider">{grp.cat}</p>
                  <div className="flex flex-col gap-1">
                    {grp.qs.map((q) => (
                      <button
                        key={q}
                        onClick={() => {
                          setActiveTab('general');
                          setChatQuestion(q);
                        }}
                        className="text-left text-xs text-[#64748B] hover:text-[#F8FAFC] hover:bg-[#1F2530] rounded p-2 transition-colors duration-150 truncate block"
                        title={q}
                      >
                        {q}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* CENTER COLUMN: Query Panel */}
        <div className="col-span-12 lg:col-span-5">
          <div className="sentinel-card p-5 space-y-4">
            <h2 className="text-sm font-semibold text-[#F8FAFC] flex items-center gap-2">
              <Brain className="w-4 h-4 text-[#16A34A]" />
              Syvora AI Panel
            </h2>
            <p className="text-xs text-[#64748B]">
              Ask questions about incidents, threats, users, access control, audit logs, compliance, and database activity.
            </p>

            {/* Tab Selector */}
            <div className="flex gap-1 p-1 bg-[#0E1117] rounded-lg border border-[#2D3642]">
              {tabs.map((tab) => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={clsx(
                      'flex-1 flex items-center justify-center gap-1.5 px-2 py-2 rounded-md text-xs font-medium transition-colors duration-150',
                      activeTab === tab.id
                        ? 'bg-[#16A34A]/10 text-[#16A34A] border border-[#16A34A]/25'
                        : 'text-[#64748B] hover:text-[#94A3B8]'
                    )}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    <span className="hidden xl:inline">{tab.label}</span>
                  </button>
                );
              })}
            </div>

            {/* Tab Content */}
            <div className="space-y-4">
              {activeTab === 'general' && (
                <div className="space-y-1.5">
                  <label className="sentinel-label">Security Copilot Chat</label>
                  <textarea
                    value={chatQuestion}
                    onChange={(e) => setChatQuestion(e.target.value)}
                    placeholder="Ask Syvora AI about vulnerabilities, attacks, patterns, or system metrics..."
                    rows={6}
                    className="sentinel-input w-full resize-none text-sm"
                  />
                </div>
              )}

              {activeTab === 'threat' && (
                <div className="space-y-3">
                  <div>
                    <label className="sentinel-label">Threat Type</label>
                    <select
                      value={threatForm.threatType}
                      onChange={(e) => updateThreatForm('threatType', e.target.value)}
                      className="sentinel-input w-full text-sm bg-[#1F2530]"
                    >
                      {threatTypeOptions.map((t) => (
                        <option key={t} value={t}>
                          {t.replace(/_/g, ' ')}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="sentinel-label">Severity Level</label>
                    <select
                      value={threatForm.severity}
                      onChange={(e) => updateThreatForm('severity', e.target.value)}
                      className="sentinel-input w-full text-sm bg-[#1F2530]"
                    >
                      {severityOptions.map((s) => (
                        <option key={s} value={s}>
                          {s}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="sentinel-label">Source Attacking IP</label>
                    <input
                      type="text"
                      value={threatForm.sourceIp}
                      onChange={(e) => updateThreatForm('sourceIp', e.target.value)}
                      placeholder="e.g. 192.168.1.100"
                      className="sentinel-input w-full text-sm"
                    />
                  </div>
                  <div>
                    <label className="sentinel-label">Attack Payload</label>
                    <textarea
                      value={threatForm.attackPayload}
                      onChange={(e) => updateThreatForm('attackPayload', e.target.value)}
                      placeholder="Paste query logs or suspicious request parameters..."
                      rows={3}
                      className="sentinel-input w-full resize-none text-sm"
                    />
                  </div>
                  <div>
                    <label className="sentinel-label">Detection Rule Triggered</label>
                    <input
                      type="text"
                      value={threatForm.detectionRule}
                      onChange={(e) => updateThreatForm('detectionRule', e.target.value)}
                      placeholder="e.g. SQL_OR_TAUTOLOGY"
                      className="sentinel-input w-full text-sm"
                    />
                  </div>
                  <div>
                    <label className="sentinel-label">Target Endpoint Resource</label>
                    <input
                      type="text"
                      value={threatForm.targetResource}
                      onChange={(e) => updateThreatForm('targetResource', e.target.value)}
                      placeholder="e.g. /api/auth/login"
                      className="sentinel-input w-full text-sm"
                    />
                  </div>
                </div>
              )}

              {activeTab === 'report' && (
                <div className="space-y-3">
                  <div>
                    <label className="sentinel-label">Total Threats Detected (24h)</label>
                    <input
                      type="number"
                      value={reportForm.totalThreats}
                      onChange={(e) => updateReportForm('totalThreats', e.target.value)}
                      placeholder="0"
                      className="sentinel-input w-full text-sm"
                    />
                  </div>
                  <div>
                    <label className="sentinel-label">Critical Incidents</label>
                    <input
                      type="number"
                      value={reportForm.criticalThreats}
                      onChange={(e) => updateReportForm('criticalThreats', e.target.value)}
                      placeholder="0"
                      className="sentinel-input w-full text-sm"
                    />
                  </div>
                  <div>
                    <label className="sentinel-label">Failed Logins Logged</label>
                    <input
                      type="number"
                      value={reportForm.failedLogins}
                      onChange={(e) => updateReportForm('failedLogins', e.target.value)}
                      placeholder="0"
                      className="sentinel-input w-full text-sm"
                    />
                  </div>
                  <div>
                    <label className="sentinel-label">Overall Posture Security Score</label>
                    <input
                      type="number"
                      value={reportForm.securityScore}
                      onChange={(e) => updateReportForm('securityScore', e.target.value)}
                      placeholder="0-100"
                      className="sentinel-input w-full text-sm"
                    />
                  </div>
                </div>
              )}

              <button
                onClick={handleSubmit}
                disabled={isLoading}
                className="sentinel-btn-primary w-full flex items-center justify-center gap-2 text-sm py-2.5"
              >
                {isLoading ? (
                  <>
                    <svg className="animate-spin w-4 h-4 text-white" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Send className="w-4 h-4" />
                    Submit Triage Query
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: Results Display Panel */}
        <div className="col-span-12 lg:col-span-4 flex flex-col gap-6">
          <div className="sentinel-card p-5 flex-1 min-h-[500px] flex flex-col">
            <div className="flex items-center justify-between mb-4 border-b border-[#2D3642] pb-3 shrink-0">
              <h2 className="text-sm font-semibold text-[#F8FAFC] flex items-center gap-2">
                <Brain className="w-4 h-4 text-[#16A34A]" />
                Analysis Results
              </h2>

              {result && (
                <div className="flex gap-2">
                  <span className="sentinel-badge bg-[#16A34A]/10 border-[#16A34A]/25 text-[#16A34A] text-[10px] tracking-wider uppercase font-semibold">
                    Syvora AI
                  </span>
                  <button
                    onClick={copyToClipboard}
                    className="p-1 rounded bg-[#1F2530] border border-[#2D3642] text-[#64748B] hover:text-[#94A3B8] transition-colors"
                    title="Copy response"
                  >
                    <Copy className="w-3 h-3" />
                  </button>
                </div>
              )}
            </div>

            <div className="flex-1 overflow-y-auto pr-1">
              <AnimatePresence mode="wait">
                {isLoading ? (
                  <motion.div
                    key="loading"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.15 }}
                    className="space-y-3"
                  >
                    <div className="skeleton h-4 w-3/4 rounded" />
                    <div className="skeleton h-4 w-full rounded" />
                    <div className="skeleton h-4 w-5/6 rounded" />
                    <div className="skeleton h-20 w-full rounded-lg mt-4" />
                    <div className="skeleton h-4 w-2/3 rounded" />
                    <div className="skeleton h-4 w-4/5 rounded" />
                  </motion.div>
                ) : result ? (
                  <motion.div
                    key="result"
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -8 }}
                    transition={{ duration: 0.2 }}
                    className="sentinel-prose"
                  >
                    <ReactMarkdown
                      components={{
                        blockquote: ({ children }) => (
                          <blockquote className="border-l-2 border-[#16A34A] pl-3 text-[#94A3B8] text-xs italic mb-3">
                            {children}
                          </blockquote>
                        ),
                        code: ({ className, children }) => {
                          const isInline = !className;
                          return isInline ? (
                            <code className="sentinel-inline-code">
                              {children}
                            </code>
                          ) : (
                            <code className="font-mono text-xs text-[#94A3B8]">{children}</code>
                          );
                        },
                      }}
                    >
                      {result}
                    </ReactMarkdown>
                  </motion.div>
                ) : (
                  <motion.div
                    key="empty"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.2 }}
                    className="flex flex-col items-center justify-center py-24 text-center h-full"
                  >
                    <div className="w-12 h-12 rounded-xl bg-[#1F2530] border border-[#2D3642] flex items-center justify-center mb-4 text-[#64748B]">
                      <Sparkles className="w-6 h-6" />
                    </div>
                    <p className="text-sm font-semibold text-[#94A3B8] mb-1">Syvora AI Copilot Idle</p>
                    <p className="text-xs text-[#64748B] max-w-xs">
                      Submit a threat analysis, posture report parameters, or query query to start investigation.
                    </p>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>

          {/* Recent Insights Tracker */}
          {recentInsights.length > 0 && (
            <div className="sentinel-card p-4 space-y-3 shrink-0">
              <h3 className="text-xs font-semibold text-[#64748B] flex items-center gap-1.5 uppercase tracking-wider">
                <Clock className="w-3.5 h-3.5" />
                Recent Insights
              </h3>
              <div className="space-y-2">
                {recentInsights.map((insight, index) => (
                  <div
                    key={index}
                    className="bg-[#1F2530] border border-[#2D3642] rounded-lg p-2.5 flex items-start gap-2.5 animate-fade-in"
                  >
                    <MessageSquare className="w-3.5 h-3.5 text-[#16A34A] shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-semibold text-[#94A3B8] truncate">{insight.q}</p>
                      <p className="text-[11px] text-[#64748B] mt-0.5 truncate">{insight.a}</p>
                      <p className="text-[9px] text-[#475569] mt-1 font-mono">{insight.time}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}

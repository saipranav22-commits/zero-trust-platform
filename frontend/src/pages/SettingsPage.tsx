import { Shield, Key, Database, Cpu, Settings, Sparkles } from 'lucide-react';
import { Layout } from '@/components/layout/Layout';
import { PageHeader } from '@/components/ui/PageHeader';
import { RoleBadge } from '@/components/ui/Badge';
import { useAuthStore } from '@/store/auth.store';

const securityFeatures = [
  {
    title: 'JWT Authentication',
    description: 'HS256 cryptographic algorithm, 15-minute access token expiry duration',
    active: true,
  },
  {
    title: 'Refresh Token Rotation',
    description: '7-day reuse detection token window with rotation invalidation',
    active: true,
  },
  {
    title: 'Brute Force Protection',
    description: 'Immediate account lockout triggers after 5 unsuccessful login iterations',
    active: true,
  },
  {
    title: 'Audit Chain Cryptography',
    description: 'SHA-256 integrity blockchain logs linked using previous log hashes',
    active: true,
  },
  {
    title: 'Threat Detection Rules Engine',
    description: 'Heuristic pattern detection triggers real-time telemetry containment alerts',
    active: true,
  },
  {
    title: 'AI Security Assistant',
    description: 'LLM security copilot capabilities driven by Gemini context models',
    active: true,
  },
];

const techStack = [
  { label: 'Core Engine Core', value: 'Spring Boot 3.3.2 • Java 21' },
  { label: 'Security Relational Database', value: 'PostgreSQL + Flyway Migration System' },
  { label: 'Access Token Configuration', value: 'JWT Signature Verification + RBAC Filter Claims' },
  { label: 'Client Presentation Framework', value: 'React 18 + TypeScript + Vite Bundler' },
  { label: 'Heuristics AI Pipeline', value: 'Google Gemini (Provider Agnostic Fallback Engine)' },
  { label: 'Containment Infrastructure', value: 'Docker Compose Container Orchestration' },
];

export function SettingsPage() {
  const { user } = useAuthStore();

  const accountRows = [
    { label: 'Administrator Profile', value: user ? `${user.firstName} ${user.lastName}` : '—' },
    { label: 'Corporate Email', value: user?.email ?? '—' },
    {
      label: 'Unique Profile ID',
      value: user?.id ?? '—',
      mono: true,
    },
    {
      label: 'Granted Credentials',
      value: user?.roles ?? [],
      isRoles: true,
    },
  ];

  return (
    <Layout>
      <PageHeader
        title="Platform Settings"
        description="Review security enforcement configurations, account settings, and engine details"
        icon={<Settings className="w-5 h-5" />}
      />

      <div className="max-w-3xl space-y-6">
        {/* Card 0: Syvora Security Engine */}
        <div className="sentinel-card p-5">
          <h2 className="text-sm font-semibold text-[#F8FAFC] flex items-center gap-2 mb-4">
            <Cpu className="w-4 h-4 text-[#16A34A]" />
            Syvora Core Engine
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-[#1F2530] border border-[#2D3642] p-3 rounded-lg flex items-center justify-between">
              <div>
                <p className="text-xs text-[#64748B] font-medium">Engine Status</p>
                <p className="text-sm font-semibold text-[#F8FAFC] mt-0.5">Fully Operational</p>
              </div>
              <span className="w-2.5 h-2.5 rounded-full bg-[#16A34A] live-dot" />
            </div>
            <div className="bg-[#1F2530] border border-[#2D3642] p-3 rounded-lg">
              <p className="text-xs text-[#64748B] font-medium">Software Version</p>
              <p className="text-sm font-bold text-[#16A34A] mt-0.5 font-mono">v1.0-ENTERPRISE</p>
            </div>
          </div>
        </div>

        {/* Card 1: Account Information */}
        <div className="sentinel-card p-5">
          <h2 className="text-sm font-semibold text-[#F8FAFC] flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-[#16A34A]" />
            Account Information
          </h2>
          <div className="space-y-0">
            {accountRows.map((row, index) => (
              <div
                key={row.label}
                className={`flex items-center justify-between py-3 ${
                  index < accountRows.length - 1 ? 'border-b border-[#2D3642]' : ''
                }`}
              >
                <span className="text-sm text-[#64748B] font-medium">{row.label}</span>
                {row.isRoles ? (
                  <div className="flex flex-wrap gap-1 justify-end">
                    {(row.value as string[]).length > 0 ? (
                      (row.value as string[]).map((role) => (
                        <RoleBadge key={role} role={role} />
                      ))
                    ) : (
                      <span className="text-sm text-[#F8FAFC] font-medium">—</span>
                    )}
                  </div>
                ) : (
                  <span
                    className={`text-sm text-[#F8FAFC] font-medium ${row.mono ? 'font-mono text-xs' : ''}`}
                  >
                    {row.value as string}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Card 1.5: Syvora AI Copilot Health Status */}
        <div className="sentinel-card p-5">
          <h2 className="text-sm font-semibold text-[#F8FAFC] flex items-center gap-2 mb-4">
            <Sparkles className="w-4 h-4 text-[#16A34A]" />
            Syvora AI Service Status
          </h2>
          <div className="space-y-3">
            <div className="flex justify-between items-center text-xs">
              <span className="text-[#64748B] font-medium">Syvora AI Model</span>
              <span className="sentinel-badge bg-[#16A34A]/10 border-[#16A34A]/25 text-[#16A34A]">Gemini-1.5-Flash</span>
            </div>
            <div className="flex justify-between items-center text-xs">
              <span className="text-[#64748B] font-medium">RAG Fallback Engine</span>
              <span className="sentinel-badge bg-[#16A34A]/10 border-[#16A34A]/25 text-[#16A34A]">Operational</span>
            </div>
          </div>
        </div>

        {/* Card 2: Security Configuration */}
        <div className="sentinel-card p-5">
          <h2 className="text-sm font-semibold text-[#F8FAFC] flex items-center gap-2 mb-4">
            <Key className="w-4 h-4 text-[#16A34A]" />
            Active Platform Policies
          </h2>
          <div className="space-y-0">
            {securityFeatures.map((feature, index) => (
              <div
                key={feature.title}
                className={`flex items-center justify-between py-3 ${
                  index < securityFeatures.length - 1 ? 'border-b border-[#2D3642]' : ''
                }`}
              >
                <div>
                  <p className="text-sm font-medium text-[#F8FAFC]">{feature.title}</p>
                  <p className="text-xs text-[#64748B] mt-0.5">{feature.description}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0 ml-4">
                  <div
                    className={`w-2 h-2 rounded-full ${
                      feature.active ? 'bg-[#16A34A]' : 'bg-[#D97706]'
                    }`}
                  />
                  <span className="text-xs font-semibold text-[#64748B] uppercase tracking-wider">
                    {feature.active ? 'Enforced' : 'Configure'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Card 3: Platform Stack */}
        <div className="sentinel-card p-5">
          <h2 className="text-sm font-semibold text-[#F8FAFC] flex items-center gap-2 mb-4">
            <Database className="w-4 h-4 text-[#16A34A]" />
            Technology Architecture Profile
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {techStack.map((item) => (
              <div
                key={item.label}
                className="bg-[#1F2530] rounded-lg p-3 border border-[#2D3642]"
              >
                <p className="text-xs text-[#64748B] font-semibold">{item.label}</p>
                <p className="text-xs text-[#F8FAFC] mt-1 font-medium">{item.value}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Layout>
  );
}

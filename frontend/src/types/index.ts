// ─── Auth Types ──────────────────────────────────────
export interface User {
  id: string
  email: string
  firstName: string
  lastName: string
  roles: string[]
  isActive: boolean
  isLocked: boolean
  failedLoginAttempts: number
  lastLoginAt?: string
  lastLoginIp?: string
  createdAt: string
}

export interface AuthResponse {
  accessToken: string
  refreshToken: string
  tokenType: string
  expiresIn: number
  user: {
    id: string
    email: string
    firstName: string
    lastName: string
    roles: string[]
  }
}

export interface LoginRequest {
  email: string
  password: string
}

export interface RegisterRequest {
  email: string
  password: string
  firstName: string
  lastName: string
}

// ─── Threat Types ─────────────────────────────────────
export type ThreatType =
  | 'SQL_INJECTION'
  | 'XSS'
  | 'BRUTE_FORCE'
  | 'CREDENTIAL_STUFFING'
  | 'DATA_EXFILTRATION'
  | 'SUSPICIOUS_ACTIVITY'
  | 'PATH_TRAVERSAL'
  | 'COMMAND_INJECTION'

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type ThreatStatus = 'DETECTED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE'

export interface ThreatEvent {
  id: string
  userId?: string
  userEmail?: string
  threatType: ThreatType
  severity: Severity
  sourceIp?: string
  targetResource?: string
  targetMethod?: string
  attackPayload?: string
  detectionRule?: string
  status: ThreatStatus
  resolvedBy?: string
  resolvedAt?: string
  notes?: string
  createdAt: string
  updatedAt: string
}

// ─── Audit Types ──────────────────────────────────────
export type AuditStatus = 'SUCCESS' | 'FAILURE' | 'BLOCKED'

export interface AuditLog {
  id: string
  userId?: string
  userEmail?: string
  action: string
  resourceType?: string
  resourceId?: string
  sourceIp?: string
  userAgent?: string
  status: AuditStatus
  riskScore: number
  details?: string
  previousHash?: string
  currentHash?: string
  createdAt: string
}

// ─── Dashboard Types ──────────────────────────────────
export interface DashboardOverview {
  totalThreatsLast24h: number
  activeThreats: number
  criticalThreatsLast24h: number
  highThreatsLast24h: number
  failedLoginsLast24h: number
  totalAuditLogsLast24h: number
  totalActiveUsers: number
  securityScore: number
  recentThreats: ThreatEvent[]
}

export interface ThreatAnalytics {
  days: number
  byType: Record<string, number>
  bySeverity: Record<string, number>
  timeline: Array<{ date: string; count: number }>
  topIps: Array<{ ip: string; count: number }>
}

export interface UserActivityAnalytics {
  totalActions: number
  failedActions: number
  failureRate: number
  byAction: Record<string, number>
  activityTimeline: Array<{ date: string; count: number }>
  recentActivity: AuditLog[]
}

// ─── Common Types ─────────────────────────────────────
export interface ApiResponse<T> {
  success: boolean
  message: string
  data: T
  traceId: string
  timestamp: string
}

export interface PageResponse<T> {
  content: T[]
  page: number
  size: number
  totalElements: number
  totalPages: number
  first: boolean
  last: boolean
}

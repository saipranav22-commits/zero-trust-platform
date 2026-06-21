import api from './axios.config'
import type { ApiResponse, ThreatEvent, PageResponse } from '@/types'

export const threatApi = {
  getThreats: async (params: {
    threatType?: string; severity?: string; status?: string
    sourceIp?: string; from?: string; to?: string; page?: number; size?: number
  }): Promise<PageResponse<ThreatEvent>> => {
    const res = await api.get<ApiResponse<PageResponse<ThreatEvent>>>('/threats', { params })
    return res.data.data
  },

  getThreatById: async (id: string): Promise<ThreatEvent> => {
    const res = await api.get<ApiResponse<ThreatEvent>>(`/threats/${id}`)
    return res.data.data
  },

  getRecent: async (): Promise<ThreatEvent[]> => {
    const res = await api.get<ApiResponse<ThreatEvent[]>>('/threats/recent')
    return res.data.data
  },

  getStatistics: async (days = 30): Promise<Record<string, unknown>> => {
    const res = await api.get<ApiResponse<Record<string, unknown>>>('/threats/statistics', { params: { days } })
    return res.data.data
  },

  updateStatus: async (id: string, status: string, notes?: string): Promise<ThreatEvent> => {
    const res = await api.put<ApiResponse<ThreatEvent>>(`/threats/${id}/status`, { status, notes })
    return res.data.data
  },

  analyzeInput: async (input: string, targetPath?: string): Promise<{ threatDetected: boolean; event?: ThreatEvent }> => {
    const res = await api.post<ApiResponse<{ threatDetected: boolean; event?: ThreatEvent }>>('/threats/analyze', {
      input, targetPath: targetPath || '/test', method: 'POST'
    })
    return res.data.data
  },
}

export const auditApi = {
  getLogs: async (params: {
    userId?: string; action?: string; status?: string
    from?: string; to?: string; page?: number; size?: number
  }) => {
    const res = await api.get<ApiResponse<PageResponse<import('@/types').AuditLog>>>('/audit/logs', { params })
    return res.data.data
  },

  getRecent: async () => {
    const res = await api.get<ApiResponse<import('@/types').AuditLog[]>>('/audit/logs/recent')
    return res.data.data
  },

  getUserHistory: async (userId: string, page = 0, size = 20) => {
    const res = await api.get<ApiResponse<PageResponse<import('@/types').AuditLog>>>(
      `/audit/users/${userId}/history`, { params: { page, size } }
    )
    return res.data.data
  },

  verifyIntegrity: async (id: string): Promise<{ integrityValid: boolean; message: string }> => {
    const res = await api.get<ApiResponse<{ integrityValid: boolean; message: string }>>(
      `/audit/logs/${id}/verify`
    )
    return res.data.data
  },
}

export const aiApi = {
  chat: async (question: string): Promise<{ question: string; answer: string }> => {
    const res = await api.post<ApiResponse<{ question: string; answer: string }>>('/ai/chat', { question })
    return res.data.data
  },

  explainThreat: async (threat: Partial<ThreatEvent>): Promise<{ threatType: string; explanation: string }> => {
    const res = await api.post<ApiResponse<{ threatType: string; explanation: string }>>('/ai/explain-threat', {
      threatType: threat.threatType,
      severity: threat.severity,
      sourceIp: threat.sourceIp,
      attackPayload: threat.attackPayload,
      detectionRule: threat.detectionRule,
      targetResource: threat.targetResource,
    })
    return res.data.data
  },

  generateReport: async (metrics: Record<string, unknown>): Promise<{ report: string; generatedAt: string }> => {
    const res = await api.post<ApiResponse<{ report: string; generatedAt: string }>>('/ai/generate-report', metrics)
    return res.data.data
  },
}

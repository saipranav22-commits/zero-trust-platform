import api from './axios.config'
import type { ApiResponse, DashboardOverview, ThreatAnalytics, UserActivityAnalytics } from '@/types'

export const dashboardApi = {
  getOverview: async (): Promise<DashboardOverview> => {
    const res = await api.get<ApiResponse<DashboardOverview>>('/dashboard/overview')
    return res.data.data
  },

  getThreatAnalytics: async (days = 30): Promise<ThreatAnalytics> => {
    const res = await api.get<ApiResponse<ThreatAnalytics>>('/dashboard/threat-analytics', { params: { days } })
    return res.data.data
  },

  getUserActivity: async (days = 30): Promise<UserActivityAnalytics> => {
    const res = await api.get<ApiResponse<UserActivityAnalytics>>('/dashboard/user-activity', { params: { days } })
    return res.data.data
  },
}

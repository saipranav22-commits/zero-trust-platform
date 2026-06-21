import api from './axios.config'
import type { ApiResponse, AuthResponse, User, LoginRequest, RegisterRequest, PageResponse } from '@/types'

export const authApi = {
  login: async (data: LoginRequest): Promise<AuthResponse> => {
    const res = await api.post<ApiResponse<AuthResponse>>('/auth/login', data)
    return res.data.data
  },

  register: async (data: RegisterRequest): Promise<AuthResponse> => {
    const res = await api.post<ApiResponse<AuthResponse>>('/auth/register', data)
    return res.data.data
  },

  logout: async (refreshToken: string): Promise<void> => {
    await api.post('/auth/logout', { refreshToken })
  },

  refresh: async (refreshToken: string): Promise<AuthResponse> => {
    const res = await api.post<ApiResponse<AuthResponse>>('/auth/refresh', { refreshToken })
    return res.data.data
  },

  me: async (): Promise<{ email: string; roles: string[]; userId: string }> => {
    const res = await api.get<ApiResponse<{ email: string; roles: string[]; userId: string }>>('/auth/me')
    return res.data.data
  },
}

export const userApi = {
  getUsers: async (params: { email?: string; isActive?: boolean; page?: number; size?: number }):
    Promise<PageResponse<User>> => {
    const res = await api.get<ApiResponse<PageResponse<User>>>('/users', { params })
    return res.data.data
  },

  getUserById: async (id: string): Promise<User> => {
    const res = await api.get<ApiResponse<User>>(`/users/${id}`)
    return res.data.data
  },

  updateUser: async (id: string, data: Partial<User>): Promise<User> => {
    const res = await api.put<ApiResponse<User>>(`/users/${id}`, data)
    return res.data.data
  },

  updateRoles: async (id: string, roles: string[]): Promise<User> => {
    const res = await api.put<ApiResponse<User>>(`/users/${id}/roles`, { roles })
    return res.data.data
  },

  unlockUser: async (id: string): Promise<User> => {
    const res = await api.post<ApiResponse<User>>(`/users/${id}/unlock`)
    return res.data.data
  },

  deactivateUser: async (id: string): Promise<void> => {
    await api.delete(`/users/${id}`)
  },
}

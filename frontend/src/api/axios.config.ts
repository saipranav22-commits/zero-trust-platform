import axios, { AxiosError, AxiosInstance } from 'axios'
import { useAuthStore } from '@/store/auth.store'
import toast from 'react-hot-toast'

const api: AxiosInstance = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

// ─── Request Interceptor: Attach Bearer Token ──────────
api.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().accessToken
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// ─── Response Interceptor: Handle 401 / Refresh ────────
let isRefreshing = false
let failedQueue: Array<{ resolve: (v: string) => void; reject: (e: unknown) => void }> = []

const processQueue = (error: unknown, token: string | null = null) => {
  failedQueue.forEach(({ resolve, reject }) => {
    error ? reject(error) : resolve(token!)
  })
  failedQueue = []
}

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as typeof error.config & { _retry?: boolean }

    // Handle 401 — try token refresh
    if (error.response?.status === 401 && !originalRequest?._retry) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject })
        }).then((token) => {
          originalRequest!.headers!.Authorization = `Bearer ${token}`
          return api(originalRequest!)
        })
      }

      originalRequest!._retry = true
      isRefreshing = true

      const { refreshToken, setTokens, logout } = useAuthStore.getState()

      if (!refreshToken) {
        logout()
        window.location.href = '/login'
        return Promise.reject(error)
      }

      try {
        const response = await axios.post('/api/auth/refresh', { refreshToken })
        const { accessToken: newAccess, refreshToken: newRefresh } = response.data.data
        setTokens(newAccess, newRefresh)
        processQueue(null, newAccess)
        originalRequest!.headers!.Authorization = `Bearer ${newAccess}`
        return api(originalRequest!)
      } catch (refreshError) {
        processQueue(refreshError, null)
        logout()
        window.location.href = '/login'
        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }

    // Handle 429 rate limiting
    if (error.response?.status === 429) {
      toast.error('Too many requests. Please slow down.')
    }

    // Handle 403 forbidden
    if (error.response?.status === 403) {
      toast.error('Access denied. Insufficient permissions.')
    }

    return Promise.reject(error)
  }
)

export default api

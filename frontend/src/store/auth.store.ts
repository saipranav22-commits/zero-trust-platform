import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import type { AuthResponse } from '@/types'

interface AuthState {
  accessToken: string | null
  refreshToken: string | null
  user: AuthResponse['user'] | null
  isAuthenticated: boolean

  login: (response: AuthResponse) => void
  logout: () => void
  setTokens: (access: string, refresh: string) => void
  hasRole: (role: string) => boolean
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      accessToken: null,
      refreshToken: null,
      user: null,
      isAuthenticated: false,

      login: (response) =>
        set({
          accessToken: response.accessToken,
          refreshToken: response.refreshToken,
          user: response.user,
          isAuthenticated: true,
        }),

      logout: () =>
        set({
          accessToken: null,
          refreshToken: null,
          user: null,
          isAuthenticated: false,
        }),

      setTokens: (access, refresh) =>
        set({ accessToken: access, refreshToken: refresh }),

      hasRole: (role) => {
        const user = get().user
        if (!user) return false
        return user.roles.some((r) => r === role || r === `ROLE_${role}`)
      },
    }),
    {
      name: 'zt-auth',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        accessToken:     state.accessToken,
        refreshToken:    state.refreshToken,
        user:            state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
)

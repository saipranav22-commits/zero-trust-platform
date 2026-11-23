import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from 'react-hot-toast'
import { ProtectedRoute, AdminRoute } from '@/components/layout/ProtectedRoute'
import { LoginPage }    from '@/pages/LoginPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { ThreatsPage }  from '@/pages/ThreatsPage'
import { AuditPage }    from '@/pages/AuditPage'
import { ActivityPage } from '@/pages/ActivityPage'
import { AiPage }       from '@/pages/AiPage'
import { UsersPage }    from '@/pages/UsersPage'
import { SettingsPage } from '@/pages/SettingsPage'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { SecurityAlertsPage } from '@/pages/SecurityAlertsPage'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#1F2530',
              color: '#F8FAFC',
              border: '1px solid #2D3642',
              borderRadius: '10px',
              fontSize: '13px',
              fontFamily: 'Inter, IBM Plex Sans, sans-serif',
              boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
            },
            success: { iconTheme: { primary: '#16A34A', secondary: '#1F2530' } },
            error:   { iconTheme: { primary: '#DC2626', secondary: '#1F2530' } },
          }}
        />

        <Routes>
          {/* Public */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<Navigate to="/dashboard" replace />} />

          {/* Protected */}
          <Route element={<ProtectedRoute />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/threats"   element={<ThreatsPage />} />
            <Route path="/audit"     element={<AuditPage />} />
            <Route path="/activity"  element={<ActivityPage />} />
            <Route path="/ai"        element={<AiPage />} />
            <Route path="/settings"  element={<SettingsPage />} />
            <Route path="/alerts"    element={<SecurityAlertsPage />} />
          </Route>

          {/* Admin only */}
          <Route element={<AdminRoute />}>
            <Route path="/users" element={<UsersPage />} />
          </Route>

          {/* 404 */}
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

import { Sidebar } from './Sidebar'
import { Header } from './Header'

interface LayoutProps {
  children: React.ReactNode
  title: string
  subtitle?: string
  onRefresh?: () => void
  isRefreshing?: boolean
}

export function Layout({ children, title, subtitle, onRefresh, isRefreshing }: LayoutProps) {
  return (
    <div className="flex h-screen bg-surface-900 overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col ml-64 overflow-hidden">
        <Header title={title} subtitle={subtitle} onRefresh={onRefresh} isRefreshing={isRefreshing} />
        <main className="flex-1 overflow-y-auto p-6 bg-grid-pattern">
          <div className="max-w-screen-2xl mx-auto animate-in">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}

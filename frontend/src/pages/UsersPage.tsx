import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Users, Lock, Unlock, UserX, Check } from 'lucide-react'
import { Layout } from '@/components/layout/Layout'
import { RoleBadge } from '@/components/ui/Badge'
import { Pagination, EmptyState } from '@/components/ui/Shared'
import { userApi } from '@/api/auth.api'
import { format } from 'date-fns'
import toast from 'react-hot-toast'
import type { User } from '@/types'

export function UsersPage() {
  const [page, setPage] = useState(0)
  const [search, setSearch] = useState('')
  const qc = useQueryClient()

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['users', page, search],
    queryFn: () => userApi.getUsers({ email: search, page, size: 20 }),
  })

  const unlockMutation = useMutation({
    mutationFn: (id: string) => userApi.unlockUser(id),
    onSuccess: () => { toast.success('User unlocked'); qc.invalidateQueries({ queryKey: ['users'] }) },
  })

  const deactivateMutation = useMutation({
    mutationFn: (id: string) => userApi.deactivateUser(id),
    onSuccess: () => { toast.success('User deactivated'); qc.invalidateQueries({ queryKey: ['users'] }) },
  })

  return (
    <Layout title="User Management" subtitle="Manage users, roles, and account access" onRefresh={refetch} isRefreshing={isLoading}>

      {/* Search */}
      <div className="card p-4 mb-4 flex items-center gap-3">
        <Users className="w-4 h-4 text-slate-500" />
        <input type="text" placeholder="Search by email…" value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(0) }}
          className="input-dark flex-1 max-w-xs" />
        <span className="text-xs text-slate-500 ml-auto">
          {data?.totalElements ?? 0} users found
        </span>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-slate-700/50">
              <tr>
                {['User', 'Roles', 'Status', 'Failed Logins', 'Last Login', 'Joined', 'Actions'].map((h) => (
                  <th key={h} className="text-left py-3 px-4 text-xs font-semibold text-slate-500 uppercase tracking-wide whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading && Array.from({ length: 8 }).map((_, i) => (
                <tr key={i} className="border-b border-slate-700/20">
                  {Array.from({ length: 7 }).map((_, j) => (
                    <td key={j} className="py-4 px-4"><div className="skeleton h-4 rounded w-20" /></td>
                  ))}
                </tr>
              ))}
              {!isLoading && !data?.content?.length && (
                <tr><td colSpan={7}>
                  <EmptyState message="No users found" icon={<Users className="w-6 h-6" />} />
                </td></tr>
              )}
              {data?.content?.map((user: User) => (
                <tr key={user.id} className="border-b border-slate-700/20 hover:bg-surface-700/30 transition-colors group">
                  <td className="py-4 px-4">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-brand-500/60 to-violet-600/60 flex items-center justify-center text-xs font-bold text-white shrink-0">
                        {user.firstName?.[0]}{user.lastName?.[0]}
                      </div>
                      <div>
                        <p className="text-sm text-slate-200 font-medium">{user.firstName} {user.lastName}</p>
                        <p className="text-xs text-slate-500">{user.email}</p>
                      </div>
                    </div>
                  </td>
                  <td className="py-4 px-4">
                    <div className="flex flex-wrap gap-1">
                      {user.roles?.map((r: string) => <RoleBadge key={r} role={r} />)}
                    </div>
                  </td>
                  <td className="py-4 px-4">
                    {user.isLocked ? (
                      <span className="badge bg-red-500/15 text-red-300 border border-red-500/25">
                        <Lock className="w-3 h-3" /> Locked
                      </span>
                    ) : user.isActive ? (
                      <span className="badge bg-emerald-500/15 text-emerald-300 border border-emerald-500/25">
                        <Check className="w-3 h-3" /> Active
                      </span>
                    ) : (
                      <span className="badge bg-slate-500/15 text-slate-400 border border-slate-500/25">Inactive</span>
                    )}
                  </td>
                  <td className="py-4 px-4">
                    <span className={`font-mono text-sm ${user.failedLoginAttempts > 3 ? 'text-orange-400' : 'text-slate-400'}`}>
                      {user.failedLoginAttempts}
                    </span>
                  </td>
                  <td className="py-4 px-4 text-xs text-slate-500">
                    {user.lastLoginAt ? format(new Date(user.lastLoginAt), 'MM/dd HH:mm') : '—'}
                  </td>
                  <td className="py-4 px-4 text-xs text-slate-500">
                    {format(new Date(user.createdAt), 'MM/dd/yyyy')}
                  </td>
                  <td className="py-4 px-4">
                    <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      {user.isLocked && (
                        <button onClick={() => unlockMutation.mutate(user.id)} title="Unlock account"
                          className="p-1.5 rounded-md text-slate-500 hover:text-emerald-400 hover:bg-emerald-500/10 transition-all">
                          <Unlock className="w-3.5 h-3.5" />
                        </button>
                      )}
                      {user.isActive && (
                        <button onClick={() => deactivateMutation.mutate(user.id)} title="Deactivate user"
                          className="p-1.5 rounded-md text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-all">
                          <UserX className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {data && data.totalPages > 1 && (
          <Pagination page={data.page} totalPages={data.totalPages}
            totalElements={data.totalElements} size={data.size} onPageChange={setPage} />
        )}
      </div>
    </Layout>
  )
}

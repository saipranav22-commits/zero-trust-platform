import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import { Users, Unlock, UserX, AlertCircle, RefreshCw, Search } from 'lucide-react';
import toast from 'react-hot-toast';
import clsx from 'clsx';
import { Layout } from '@/components/layout/Layout';
import { PageHeader } from '@/components/ui/PageHeader';
import { RoleBadge } from '@/components/ui/Badge';
import { Pagination, EmptyState } from '@/components/ui/Shared';
import { userApi } from '@/api/auth.api';
import type { User } from '@/types';

export function UsersPage() {
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const pageSize = 20;
  const queryClient = useQueryClient();

  const {
    data,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['users', page, search],
    queryFn: () => userApi.getUsers({ page, size: pageSize, email: search }),
  });

  const unlockMutation = useMutation({
    mutationFn: (userId: string) => userApi.unlockUser(userId),
    onSuccess: () => {
      toast.success('User account unlocked successfully');
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
    onError: () => {
      toast.error('Failed to unlock user');
    },
  });

  const deactivateMutation = useMutation({
    mutationFn: (userId: string) => userApi.deactivateUser(userId),
    onSuccess: () => {
      toast.success('User account deactivated successfully');
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
    onError: () => {
      toast.error('Failed to deactivate user');
    },
  });

  const users: User[] = data?.content ?? [];
  const totalCount = data?.totalElements ?? 0;
  const totalPages = data?.totalPages ?? 0;

  if (isError) {
    return (
      <Layout>
        <div className="flex flex-col items-center justify-center py-20">
          <div className="w-12 h-12 rounded-xl bg-[#1F2530] border border-[#2D3642] flex items-center justify-center mb-4">
            <AlertCircle className="w-6 h-6 text-[#DC2626]" />
          </div>
          <p className="text-sm font-semibold text-[#F8FAFC] mb-1">Failed to load users</p>
          <p className="text-xs text-[#64748B] mb-4">
            {(error as Error)?.message ?? 'An unexpected error occurred'}
          </p>
          <button
            onClick={() => refetch()}
            className="sentinel-btn-secondary flex items-center gap-2 text-sm"
          >
            <RefreshCw className="w-4 h-4" />
            Retry
          </button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout onRefresh={refetch} isRefreshing={isLoading}>
      <PageHeader
        title="User Management"
        description="Configure client identities, assign security profiles, and manage system lockout statuses"
        icon={<Users className="w-5 h-5" />}
        onRefresh={refetch}
        isRefreshing={isLoading}
      />

      <div className="space-y-6">
        {/* Toolbar */}
        <div className="sentinel-toolbar">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#64748B]" />
            <input
              type="text"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(0);
              }}
              placeholder="Search users by email address…"
              className="sentinel-input pl-9 w-72 text-sm"
            />
          </div>
          <div className="flex items-center gap-2 text-sm text-[#64748B] font-medium ml-auto">
            <Users className="w-4 h-4" />
            <span>{totalCount} registered users</span>
          </div>
        </div>

        {/* Table */}
        <div className="sentinel-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="sentinel-table">
              <thead className="sentinel-thead">
                <tr>
                  <th className="sentinel-th">User</th>
                  <th className="sentinel-th">Security Roles</th>
                  <th className="sentinel-th">Account Status</th>
                  <th className="sentinel-th">Failed Logins</th>
                  <th className="sentinel-th">Last Login Timestamp</th>
                  <th className="sentinel-th">Date Joined</th>
                  <th className="sentinel-th text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading
                  ? Array.from({ length: 5 }).map((_, i) => (
                      <tr key={i}>
                        {Array.from({ length: 7 }).map((_, j) => (
                          <td key={j} className="sentinel-td">
                            <div className="skeleton h-4 w-20 rounded" />
                          </td>
                        ))}
                      </tr>
                    ))
                  : users.map((user) => (
                      <tr key={user.id} className="sentinel-tr group">
                        {/* User Identity */}
                        <td className="sentinel-td">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-lg bg-[#16A34A]/10 border border-[#16A34A]/25 text-[#16A34A] flex items-center justify-center text-xs font-semibold">
                              {user.firstName?.[0]?.toUpperCase()}{user.lastName?.[0]?.toUpperCase()}
                            </div>
                            <div>
                              <p className="text-sm text-[#F8FAFC] font-semibold">
                                {user.fullName || `${user.firstName} ${user.lastName}`}
                              </p>
                              <p className="text-xs text-[#64748B]">{user.email}</p>
                            </div>
                          </div>
                        </td>
                        {/* Security Roles */}
                        <td className="sentinel-td">
                          <div className="flex flex-wrap gap-1">
                            {(user.roleNames ?? user.roles?.map(r => r.name) ?? []).map((role: string) => (
                              <RoleBadge key={role} role={role} />
                            ))}
                          </div>
                        </td>
                        {/* Account Status */}
                        <td className="sentinel-td">
                          <div className="flex items-center gap-2">
                            <div
                              className={clsx(
                                'w-2 h-2 rounded-full',
                                user.locked || user.accountCurrentlyLocked ? 'bg-[#DC2626]' : user.active ? 'bg-[#16A34A]' : 'bg-[#64748B]'
                              )}
                            />
                            <span className="text-xs font-medium text-[#94A3B8]">
                              {user.locked || user.accountCurrentlyLocked ? 'Locked' : user.active ? 'Active' : 'Inactive'}
                            </span>
                          </div>
                        </td>
                        {/* Failed Logins */}
                        <td className="sentinel-td">
                          <span
                            className={clsx(
                              'text-xs font-semibold font-mono',
                              (user.failedLoginAttempts ?? 0) > 3 ? 'text-[#D97706]' : 'text-[#94A3B8]'
                            )}
                          >
                            {user.failedLoginAttempts ?? 0}
                          </span>
                        </td>
                        {/* Last Login */}
                        <td className="sentinel-td text-xs text-[#94A3B8] font-medium">
                          {user.lastLoginAt
                            ? format(new Date(user.lastLoginAt), 'MMM d, yyyy HH:mm')
                            : '—'}
                        </td>
                        {/* Joined */}
                        <td className="sentinel-td text-xs text-[#64748B] font-medium">
                          {user.createdAt
                            ? format(new Date(user.createdAt), 'MMM d, yyyy')
                            : '—'}
                        </td>
                        {/* Action buttons */}
                        <td className="sentinel-td text-right">
                          <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity duration-150">
                            {(user.locked || user.accountCurrentlyLocked) && (
                              <button
                                onClick={() => unlockMutation.mutate(user.id)}
                                disabled={unlockMutation.isPending}
                                className="sentinel-btn-ghost p-1.5 text-[#94A3B8] hover:text-[#16A34A]"
                                title="Unlock Account"
                              >
                                <Unlock className="w-4 h-4" />
                              </button>
                            )}
                            {user.active && (
                              <button
                                onClick={() => deactivateMutation.mutate(user.id)}
                                disabled={deactivateMutation.isPending}
                                className="sentinel-btn-ghost p-1.5 text-[#94A3B8] hover:text-[#DC2626]"
                                title="Deactivate Account"
                              >
                                <UserX className="w-4 h-4" />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
              </tbody>
            </table>
          </div>

          {!isLoading && users.length === 0 && (
            <EmptyState
              icon={<Users className="w-6 h-6" />}
              message={search ? 'No users found matching query' : 'No registered users in system database'}
              description="System has no configured client profiles."
            />
          )}

          {totalPages > 1 && (
            <Pagination
              page={page}
              totalPages={totalPages}
              totalElements={totalCount}
              size={pageSize}
              onPageChange={setPage}
            />
          )}
        </div>
      </div>
    </Layout>
  );
}

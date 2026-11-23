import api from './axios.config';
import type { ApiResponse, PageResponse } from '@/types';
import type { Notification, NotificationFilters } from '@/types/notification';

export const notificationApi = {
  /** Get paginated notifications with optional filters */
  getNotifications: async (
    filters: NotificationFilters = {},
    page = 0,
    size = 20
  ): Promise<PageResponse<Notification>> => {
    const params: Record<string, string | number | boolean | undefined> = {
      page,
      size,
      sort: 'createdAt,desc',
      ...filters,
    };
    // Remove undefined params
    Object.keys(params).forEach((k) => params[k] === undefined && delete params[k]);
    const res = await api.get<ApiResponse<PageResponse<Notification>>>('/notifications', { params });
    return res.data.data;
  },

  /** Get unread count */
  getUnreadCount: async (): Promise<number> => {
    const res = await api.get<ApiResponse<{ unreadCount: number }>>('/notifications/unread-count');
    return res.data.data.unreadCount;
  },

  /** Get single notification */
  getNotification: async (id: string): Promise<Notification> => {
    const res = await api.get<ApiResponse<Notification>>(`/notifications/${id}`);
    return res.data.data;
  },

  /** Mark single notification as read */
  markAsRead: async (id: string): Promise<Notification> => {
    const res = await api.patch<ApiResponse<Notification>>(`/notifications/${id}/read`);
    return res.data.data;
  },

  /** Mark all notifications as read */
  markAllAsRead: async (): Promise<void> => {
    await api.patch('/notifications/read-all');
  },

  /** Delete a notification */
  deleteNotification: async (id: string): Promise<void> => {
    await api.delete(`/notifications/${id}`);
  },

  /** Request a short-lived single-use SSE stream ticket */
  getStreamTicket: async (): Promise<string> => {
    const res = await api.post<ApiResponse<{ ticket: string }>>('/notifications/stream-ticket');
    return res.data.data.ticket;
  },
};

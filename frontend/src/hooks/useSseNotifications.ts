import { useEffect, useRef, useCallback } from 'react';
import toast from 'react-hot-toast';
import { notificationApi } from '@/api/notification.api';
import type { Notification } from '@/types/notification';

interface UseSseNotificationsOptions {
  onNotification: (n: Notification) => void;
  token?: string | null;
}

/**
 * Subscribes to the backend SSE stream at /api/notifications/stream.
 *
 * Security architecture:
 * Browser EventSource does not support custom headers (such as Authorization: Bearer).
 * Rather than leaking long-lived tokens in query parameters, we request a short-lived (30s)
 * single-use ticket via authenticated POST /api/notifications/stream-ticket.
 *
 * Uses relative path '/api/notifications/stream' so it automatically adapts to
 * Vite proxy during development and Nginx reverse proxy in production without
 * hardcoded ports or hostnames.
 */
export function useSseNotifications({ onNotification, token }: UseSseNotificationsOptions) {
  const esRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectDelayRef = useRef(3000);
  const mountedRef = useRef(true);

  const connect = useCallback(async () => {
    if (!token || !mountedRef.current) return;

    try {
      // 1. Obtain a single-use short-lived stream ticket
      const ticket = await notificationApi.getStreamTicket();
      if (!mountedRef.current) return;

      // 2. Connect using configured API endpoint with ticket param
      const apiBase = import.meta.env.VITE_API_URL || '/api';
      const url = `${apiBase}/notifications/stream?ticket=${encodeURIComponent(ticket)}`;
      const es = new EventSource(url, { withCredentials: false });
      esRef.current = es;

      es.addEventListener('connection', () => {
        reconnectDelayRef.current = 3000; // reset backoff on successful connect
      });

      es.addEventListener('notification', (e: MessageEvent) => {
        try {
          const notification: Notification = JSON.parse(e.data);
          onNotification(notification);
          // Show a toast based on severity
          const toastMsg = `🔔 ${notification.title}`;
          if (notification.severity === 'CRITICAL') {
            toast.error(toastMsg, { duration: 6000 });
          } else if (notification.severity === 'HIGH') {
            toast(toastMsg, { icon: '⚠️', duration: 5000 });
          } else {
            toast(toastMsg, { icon: '🛡️', duration: 4000 });
          }
        } catch {
          // malformed SSE payload — ignore
        }
      });

      es.onerror = () => {
        es.close();
        esRef.current = null;
        if (mountedRef.current) {
          // Exponential backoff capped at 30s
          reconnectDelayRef.current = Math.min(reconnectDelayRef.current * 2, 30000);
          reconnectTimerRef.current = setTimeout(connect, reconnectDelayRef.current);
        }
      };
    } catch {
      // Failed to acquire ticket or SSE connect error — retry with backoff
      if (mountedRef.current) {
        reconnectDelayRef.current = Math.min(reconnectDelayRef.current * 2, 30000);
        reconnectTimerRef.current = setTimeout(connect, reconnectDelayRef.current);
      }
    }
  }, [token, onNotification]);

  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
    };
  }, [connect]);
}

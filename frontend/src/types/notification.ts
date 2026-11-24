// ─── Notification Types ──────────────────────────────────────

export type NotificationSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type NotificationCategory =
  | 'THREAT_DETECTION'
  | 'AUTHENTICATION'
  | 'AI_REPORT'
  | 'AUDIT'
  | 'DATABASE'
  | 'POLICY'
  | 'SYSTEM';
export type NotificationIconType = 'CRITICAL' | 'HIGH' | 'THREAT' | 'LOGIN' | 'AI' | 'AUDIT' | 'DATABASE' | 'POLICY';

export interface Notification {
  id: string;
  title: string;
  description: string;
  severity: NotificationSeverity;
  category: NotificationCategory;
  isRead: boolean;
  relatedIncidentId?: string;
  relatedThreatId?: string;
  relatedUserId?: string;
  actionUrl?: string;
  createdBy?: string;
  iconType?: NotificationIconType;
  createdAt: string;
}

export interface NotificationFilters {
  search?: string;
  severity?: string;
  category?: string;
  isRead?: boolean;
  start?: string;
  end?: string;
}

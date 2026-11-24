-- Notification Center Table
CREATE TABLE IF NOT EXISTS notifications (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title               VARCHAR(255) NOT NULL,
    description         TEXT NOT NULL,
    severity            VARCHAR(50)  NOT NULL,
    category            VARCHAR(100) NOT NULL,
    is_read             BOOLEAN NOT NULL DEFAULT FALSE,
    related_incident_id UUID,
    related_threat_id   UUID,
    related_user_id     UUID,
    action_url          VARCHAR(255),
    created_by          VARCHAR(100),
    icon_type           VARCHAR(50),
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications (is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_severity ON notifications (severity);
CREATE INDEX IF NOT EXISTS idx_notifications_category ON notifications (category);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications (created_at DESC);

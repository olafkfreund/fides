ALTER TABLE integration_events ADD COLUMN IF NOT EXISTS deliveries_scheduled BOOLEAN NOT NULL DEFAULT false;

-- System outbox state, drained across organizations like integration_events.
CREATE TABLE IF NOT EXISTS integration_event_deliveries (
    event_id UUID NOT NULL REFERENCES integration_events(id) ON DELETE CASCADE,
    sink TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'dead')),
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    lease_token UUID,
    last_error TEXT,
    PRIMARY KEY (event_id, sink)
);

CREATE INDEX IF NOT EXISTS idx_event_deliveries_due
    ON integration_event_deliveries(next_attempt_at)
    WHERE status = 'pending';

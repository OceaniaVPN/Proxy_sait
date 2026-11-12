-- Store each endpoint's latest TCP result in its existing queue row.
-- This lets a probe update one D1 row instead of writing to both status and queue tables.
ALTER TABLE proxy_probe_queue ADD COLUMN status TEXT CHECK (status IN ('online', 'offline'));
ALTER TABLE proxy_probe_queue ADD COLUMN latency_ms INTEGER;

-- Preserve the status data already collected by earlier deployments.
UPDATE proxy_probe_queue
SET
  status = (SELECT c.status FROM proxy_status_cache c
            WHERE c.server = proxy_probe_queue.server AND c.port = proxy_probe_queue.port),
  latency_ms = (SELECT c.latency_ms FROM proxy_status_cache c
                WHERE c.server = proxy_probe_queue.server AND c.port = proxy_probe_queue.port)
WHERE EXISTS (
  SELECT 1 FROM proxy_status_cache c
  WHERE c.server = proxy_probe_queue.server AND c.port = proxy_probe_queue.port
);

CREATE INDEX IF NOT EXISTS proxy_probe_queue_status_checked_idx
  ON proxy_probe_queue(status, checked_at);

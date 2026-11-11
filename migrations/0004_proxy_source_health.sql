CREATE TABLE IF NOT EXISTS proxy_source_health (
  source TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok', 'error')),
  http_status INTEGER,
  bytes INTEGER NOT NULL DEFAULT 0,
  parsed_count INTEGER NOT NULL DEFAULT 0,
  checked_count INTEGER NOT NULL DEFAULT 0,
  online_count INTEGER NOT NULL DEFAULT 0,
  offline_count INTEGER NOT NULL DEFAULT 0,
  checked_at TEXT NOT NULL,
  error TEXT
);

CREATE INDEX IF NOT EXISTS proxy_source_health_checked_idx
  ON proxy_source_health(checked_at);

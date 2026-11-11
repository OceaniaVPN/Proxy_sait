-- Per-link Telegram protocol health results (each secret is checked independently).
CREATE TABLE IF NOT EXISTS proxy_mtproto_status (
  link_key TEXT PRIMARY KEY,
  server TEXT NOT NULL,
  port INTEGER NOT NULL,
  status TEXT NOT NULL,
  latency_ms INTEGER,
  checked_at TEXT NOT NULL,
  error_code TEXT,
  checker TEXT NOT NULL DEFAULT 'mtproxy-checker',
  dc INTEGER
);

CREATE INDEX IF NOT EXISTS proxy_mtproto_status_checked_idx
  ON proxy_mtproto_status(checked_at);

CREATE INDEX IF NOT EXISTS proxy_mtproto_status_state_idx
  ON proxy_mtproto_status(status, checked_at);

CREATE TABLE IF NOT EXISTS proxy_mtproto_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  checked_at TEXT,
  attempted_at TEXT,
  source_count INTEGER NOT NULL DEFAULT 0,
  discovered_links INTEGER NOT NULL DEFAULT 0,
  checked_count INTEGER NOT NULL DEFAULT 0,
  working_count INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  checker TEXT NOT NULL DEFAULT 'mtproxy-checker'
);

CREATE TABLE IF NOT EXISTS proxy_status_cache (
  server TEXT NOT NULL,
  port INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('online', 'offline')),
  latency_ms INTEGER,
  checked_at TEXT NOT NULL,
  PRIMARY KEY (server, port)
);

CREATE TABLE IF NOT EXISTS proxy_status_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  feed_hash TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  target_count INTEGER NOT NULL DEFAULT 0
);

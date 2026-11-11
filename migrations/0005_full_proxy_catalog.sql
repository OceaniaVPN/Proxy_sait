-- Full link catalog and incremental endpoint-check queue.
-- proxy_links remains as a compatibility table for older API consumers.
CREATE TABLE IF NOT EXISTS proxy_catalog_links (
  link_id TEXT PRIMARY KEY,
  server TEXT NOT NULL,
  port INTEGER NOT NULL,
  proxy_url TEXT NOT NULL,
  source TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS proxy_catalog_links_endpoint_idx
  ON proxy_catalog_links(server, port);

CREATE INDEX IF NOT EXISTS proxy_catalog_links_source_idx
  ON proxy_catalog_links(source);

CREATE INDEX IF NOT EXISTS proxy_catalog_links_last_seen_idx
  ON proxy_catalog_links(last_seen_at);

CREATE TABLE IF NOT EXISTS proxy_probe_queue (
  server TEXT NOT NULL,
  port INTEGER NOT NULL,
  queued_at TEXT NOT NULL,
  checked_at TEXT,
  next_check_at TEXT NOT NULL,
  PRIMARY KEY (server, port)
);

CREATE INDEX IF NOT EXISTS proxy_probe_queue_due_idx
  ON proxy_probe_queue(next_check_at, queued_at);

CREATE TABLE IF NOT EXISTS proxy_catalog_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  sources_checked_at TEXT,
  source_hash TEXT,
  source_count INTEGER NOT NULL DEFAULT 0,
  parsed_link_count INTEGER NOT NULL DEFAULT 0,
  endpoint_count INTEGER NOT NULL DEFAULT 0
);

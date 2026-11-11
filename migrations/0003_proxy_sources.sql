CREATE TABLE IF NOT EXISTS proxy_links (
  server TEXT NOT NULL,
  port INTEGER NOT NULL,
  proxy_url TEXT NOT NULL,
  source TEXT NOT NULL,
  PRIMARY KEY (server, port)
);

CREATE INDEX IF NOT EXISTS proxy_links_source_idx ON proxy_links(source);

CREATE TABLE IF NOT EXISTS proxy_refresh_lock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  started_at TEXT NOT NULL
);

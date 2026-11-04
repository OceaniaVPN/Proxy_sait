CREATE TABLE IF NOT EXISTS site_settings (
  setting_key TEXT PRIMARY KEY NOT NULL,
  setting_value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT OR IGNORE INTO site_settings (setting_key, setting_value)
VALUES ('season', 'autumn');

CREATE TABLE IF NOT EXISTS admin_login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_hash TEXT NOT NULL,
  attempted_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_login_attempts_ip_time
ON admin_login_attempts (ip_hash, attempted_at);

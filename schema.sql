CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  form_name TEXT NOT NULL,
  name TEXT,
  email TEXT,
  phone TEXT,
  city TEXT,
  service TEXT,
  message TEXT,
  source TEXT,
  device TEXT,
  location TEXT,
  ip TEXT,
  referer TEXT,
  status TEXT DEFAULT 'new',
  notes TEXT,
  raw_data TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_form_name ON submissions(form_name);
CREATE INDEX IF NOT EXISTS idx_status ON submissions(status);
CREATE INDEX IF NOT EXISTS idx_created_at ON submissions(created_at);
CREATE INDEX IF NOT EXISTS idx_email ON submissions(email);
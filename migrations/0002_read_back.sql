-- Read-back flow: after the face check a check is 'answered' (the answerer now sees the words),
-- and it only becomes 'passed' once the sender confirms the words were read back to them.
-- SQLite can't change a CHECK constraint in place, so the table is rebuilt.
CREATE TABLE checks_new (
  id TEXT PRIMARY KEY,
  from_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'answered', 'passed', 'declined', 'expired', 'failed')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  answered_at INTEGER,
  answered_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  confirmed_at INTEGER,
  key_type TEXT,
  receipt TEXT
);

INSERT INTO checks_new (id, from_user_id, to_user_id, code, status, created_at, expires_at, answered_at, answered_by, key_type, receipt)
  SELECT id, from_user_id, to_user_id, code, status, created_at, expires_at, answered_at, answered_by, key_type, receipt FROM checks;

DROP TABLE checks;
ALTER TABLE checks_new RENAME TO checks;
CREATE INDEX checks_from ON checks(from_user_id, created_at);
CREATE INDEX checks_to ON checks(to_user_id, status, expires_at);

-- Accounts. A handle is the only public identifier; no names, emails or photos are stored.
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  handle TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  last_check_at INTEGER,
  checks_passed INTEGER NOT NULL DEFAULT 0,
  challenge_policy TEXT NOT NULL DEFAULT 'anyone' CHECK (challenge_policy IN ('anyone', 'contacts', 'nobody'))
);

-- Handles of deleted accounts are never handed out again, so nobody can take over a known handle.
CREATE TABLE retired_handles (
  handle TEXT PRIMARY KEY,
  retired_at INTEGER NOT NULL
);

-- Passkeys. The private key never leaves the person's device; we keep only the public half.
CREATE TABLE credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  device_type TEXT NOT NULL,
  backed_up INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE INDEX credentials_user ON credentials(user_id);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  verified_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);

-- One-time passkey ceremonies. Each row is used once and then deleted.
CREATE TABLE ceremonies (
  id TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,
  challenge TEXT NOT NULL,
  user_id TEXT,
  handle TEXT,
  webauthn_user_id TEXT,
  ref TEXT,
  expires_at INTEGER NOT NULL
);

-- Human checks ("prove it" challenges).
CREATE TABLE checks (
  id TEXT PRIMARY KEY,
  from_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'passed', 'declined', 'expired', 'failed')),
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  answered_at INTEGER,
  answered_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  key_type TEXT,
  receipt TEXT
);
CREATE INDEX checks_from ON checks(from_user_id, created_at);
CREATE INDEX checks_to ON checks(to_user_id, status, expires_at);

CREATE TABLE contacts (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  contact_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, contact_id)
);

CREATE TABLE blocks (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, blocked_id)
);

CREATE TABLE push_subscriptions (
  endpoint TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX push_user ON push_subscriptions(user_id);

-- Sliding-window rate limits.
CREATE TABLE rate_events (
  key TEXT NOT NULL,
  at INTEGER NOT NULL
);
CREATE INDEX rate_key ON rate_events(key, at);

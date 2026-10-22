-- URLCheck online unlock codes (Option B). Plaintext codes are NEVER stored.
CREATE TABLE IF NOT EXISTS unlock_codes (
  code_id        TEXT PRIMARY KEY,          -- uuid
  code_hash      TEXT NOT NULL UNIQUE,      -- hex HMAC-SHA256(pepper, normalizedCode)
  origin         TEXT NOT NULL,             -- scheme://host[:port], lowercase
  ticket         TEXT NOT NULL,             -- e.g. TK-15345 (mandatory)
  reason         TEXT,
  issuer_email   TEXT NOT NULL,             -- from Cloudflare Access JWT
  created_at     INTEGER NOT NULL,          -- epoch ms
  expires_at     INTEGER NOT NULL,          -- redeem window end (created + 15 min)
  grant_ttl_s    INTEGER NOT NULL,          -- unlock duration on the device after redeem
  redeemed_at    INTEGER,
  redeemed_device TEXT,
  redeemed_label  TEXT,
  redeemed_ip     TEXT,
  revoked_at     INTEGER,
  revoked_by     TEXT
);
CREATE INDEX IF NOT EXISTS idx_codes_created ON unlock_codes(created_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  at          INTEGER NOT NULL,
  event       TEXT NOT NULL,   -- issued | redeemed | redeem_failed | revoked | rate_limited
  code_id     TEXT,
  ticket      TEXT,
  origin      TEXT,
  actor       TEXT,            -- issuer/revoker email, or device id for redeem events
  device_id   TEXT,
  device_label TEXT,
  ip          TEXT,
  ext_version TEXT,
  detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_code ON audit_log(code_id);

CREATE TABLE IF NOT EXISTS redeem_failures (
  bucket  TEXT NOT NULL,       -- "ip:<ip>" or "dev:<deviceId>"
  at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fail_bucket ON redeem_failures(bucket, at);

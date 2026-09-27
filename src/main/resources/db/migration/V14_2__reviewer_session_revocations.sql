-- Keep only a one-way digest of the server-issued session identifier. The signed
-- cookie and CSRF token must never be stored in the revocation record.
CREATE TABLE reviewer_session_revocations (
    session_digest sha256_digest PRIMARY KEY,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT now()
);

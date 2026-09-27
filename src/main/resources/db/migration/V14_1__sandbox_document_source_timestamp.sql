-- Historical documents without a recorded source time must remain unknown.
-- Versioned fixture producers supply created_at explicitly; migration time is not source evidence.
ALTER TABLE sandbox_documents ADD COLUMN created_at timestamptz;

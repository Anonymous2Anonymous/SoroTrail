ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS sequence BIGINT;
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS entry_hash TEXT NOT NULL DEFAULT '';

-- Create index on sequence for ordering and verification
CREATE INDEX IF NOT EXISTS idx_audit_records_sequence ON audit_records(sequence);

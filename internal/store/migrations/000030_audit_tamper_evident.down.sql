DROP INDEX IF EXISTS idx_audit_records_sequence;
ALTER TABLE audit_records DROP COLUMN IF EXISTS entry_hash;
ALTER TABLE audit_records DROP COLUMN IF EXISTS prev_hash;
ALTER TABLE audit_records DROP COLUMN IF EXISTS sequence;

-- +goose Up
CREATE TABLE audit_trail_records (
    id BIGSERIAL PRIMARY KEY,
    sequence BIGINT NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL,
    tenant_id TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_trail_tenant ON audit_trail_records(tenant_id);
CREATE INDEX idx_audit_trail_sequence ON audit_trail_records(sequence);

-- +goose Down
DROP TABLE IF EXISTS audit_trail_records;

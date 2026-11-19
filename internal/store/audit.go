package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// AuditRecord represents a tamper-evident audit trail entry stored in Postgres.
type AuditRecord struct {
	ID        int64           `json:"id"`
	Sequence  int64           `json:"sequence"`
	Timestamp time.Time       `json:"timestamp"`
	TenantID  *int64          `json:"tenant_id,omitempty"`
	Action    string          `json:"action"`
	Actor     string          `json:"actor"`
	Details   json.RawMessage `json:"details,omitempty"`
	PrevHash  string          `json:"prev_hash"`
	EntryHash string          `json:"entry_hash"`
}

// ComputeEntryHash produces a canonicalized SHA-256 hash for an audit entry.
func ComputeEntryHash(sequence int64, timestamp time.Time, tenantID *int64, action, actor string, details json.RawMessage, prevHash string) (string, error) {
	rawDetails := []byte("null")
	if len(details) > 0 {
		var compact bytesBuffer
		_ = json.Compact(&compact, details)
		rawDetails = compact.Bytes()
	if len(rawDetails) == 0 {
		rawDetails = details
	}
	}

	canonicalMap := map[string]any{
		"sequence":  sequence,
		"timestamp": timestamp.UTC().Format(time.RFC3339Nano),
		"action":    action,
		"actor":     actor,
		"prev_hash": prevHash,
	}
	if tenantID != nil {
		canonicalMap["tenant_id"] = *tenantID
	}
	data, err := json.Marshal(canonicalMap)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	h.Write(data)
	h.Write([]byte("|"))
	h.Write(rawDetails)
	return hex.EncodeToString(h.Sum(nil)), nil
}

type bytesBuffer struct {
	buf []byte
}

func (b *bytesBuffer) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *bytesBuffer) Bytes() []byte {
	return b.buf
}

// AppendRecord inserts a new audit record into Postgres with hash chaining.
func (db *Postgres) AppendRecord(ctx context.Context, action, actor string, tenantID *int64, details json.RawMessage) (*AuditRecord, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var prevHash string
	var nextSeq int64 = 1

	row := tx.QueryRow(ctx, `SELECT entry_hash, sequence FROM audit_records ORDER BY sequence DESC LIMIT 1 FOR UPDATE`)
	var dbPrev *string
	var dbSeq *int64
	err = row.Scan(&dbPrev, &dbSeq)
	if err == nil {
		keys := dbPrev
		if keys != nil {
			prevHash = *keys
		}
		if dbSeq != nil {
			nextSeq = *dbSeq + 1
		}
	}

	ts := time.Now().UTC()
	h, err := ComputeEntryHash(nextSeq, ts, tenantID, action, actor, details, prevHash)
	if err != nil {
		return nil, err
	}

	var id int64
	query := `INSERT INTO audit_records (sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`
	err = tx.QueryRow(ctx, query, nextSeq, ts, tenantID, action, actor, details, prevHash, h).Scan(&id)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &AuditRecord{
		ID:        id,
		Sequence:  nextSeq,
		Timestamp: ts,
		TenantID:  tenantID,
		Action:    action,
		Actor:     actor,
		Details:   details,
		PrevHash:  prevHash,
		EntryHash: h,
	}, nil
}

// ListRecords retrieves audit records ordered by sequence with optional limit for bounding.
func (db *Postgres) ListRecords(ctx context.Context, limit int) ([]AuditRecord, error) {
	query := `SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM audit_records ORDER BY sequence ASC`
	if limit > 0 {
		query = fmt.Sprintf(`SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM (SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM audit_records ORDER BY sequence DESC LIMIT %d) sub ORDER BY sequence ASC`, limit)
	}
	rows, err := db.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []AuditRecord
	for rows.Next() {
		var r AuditRecord
		var rawDetails []byte
		err := rows.Scan(&r.ID, &r.Sequence, &r.Timestamp, &r.TenantID, &r.Action, &r.Actor, &rawDetails, &r.PrevHash, &r.EntryHash)
		if err != nil {
			return nil, err
		}
		r.Details = json.RawMessage(rawDetails)
		records = append(records, r)
	}
	return records, rows.Err()
}

// ListTenantRecords retrieves audit records restricted to a specific tenant ID to guarantee isolation.
func (db *Postgres) ListTenantRecords(ctx context.Context, tenantID int64, limit int) ([]AuditRecord, error) {
	query := `SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM audit_records WHERE tenant_id = $1 ORDER BY sequence ASC`
	if limit > 0 {
		query = fmt.Sprintf(`SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM (SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM audit_records WHERE tenant_id = $1 ORDER BY sequence DESC LIMIT %d) sub ORDER BY sequence ASC`, limit)
	}
	rows, err := db.Pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []AuditRecord
	for rows.Next() {
		var r AuditRecord
		var rawDetails []byte
		err := rows.Scan(&r.ID, &r.Sequence, &r.Timestamp, &r.TenantID, &r.Action, &r.Actor, &rawDetails, &r.PrevHash, &r.EntryHash)
		if err != nil {
			return nil, err
		}
		r.Details = json.RawMessage(rawDetails)
		records = append(records, r)
	}
	return records, rows.Err()
}

// LatestRecord returns the most recent audit record.
func (db *Postgres) LatestRecord(ctx context.Context) (*AuditRecord, error) {
	query := `SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM audit_records ORDER BY sequence DESC LIMIT 1`
	row := db.Pool.QueryRow(ctx, query)
	var r AuditRecord
	var rawDetails []byte
	err := row.Scan(&r.ID, &r.Sequence, &r.Timestamp, &r.TenantID, &r.Action, &r.Actor, &rawDetails, &r.PrevHash, &r.EntryHash)
	if err != nil {
		return nil, nil
	}
	r.Details = json.RawMessage(rawDetails)
	return &r, nil
}

// CheckpointBeforePrune returns the latest audit record prior to pruning retention boundary.
func (db *Postgres) CheckpointBeforePrune(ctx context.Context, before time.Time) (*AuditRecord, error) {
	query := `SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM audit_records WHERE timestamp < $1 ORDER BY sequence DESC LIMIT 1`
	row := db.Pool.QueryRow(ctx, query, before)
	var r AuditRecord
	var rawDetails []byte
	err := row.Scan(&r.ID, &r.Sequence, &r.Timestamp, &r.TenantID, &r.Action, &r.Actor, &rawDetails, &r.PrevHash, &r.EntryHash)
	if err != nil {
		return db.LatestRecord(ctx)
	}
	r.Details = json.RawMessage(rawDetails)
	return &r, nil
}

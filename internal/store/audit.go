package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sorotrail/sorotrail/internal/audit"
)

// AppendRecord inserts a new audit record into Postgres with hash chaining.
func (db *Postgres) AppendRecord(ctx context.Context, action, actor string, tenantID *int64, details json.RawMessage) (*audit.Record, error) {
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
		if dbPrev != nil {
			prevHash = *dbPrev
		}
		if dbSeq != nil {
			nextSeq = *dbSeq + 1
		}
	}

	ts := time.Now().UTC()
	h, err := audit.ComputeEntryHash(nextSeq, ts, tenantID, action, actor, details, prevHash)
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

	return &audit.Record{
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
func (db *Postgres) ListRecords(ctx context.Context, limit int) ([]audit.Record, error) {
	query := `SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM audit_records ORDER BY sequence ASC`
	if limit > 0 {
		query = fmt.Sprintf(`SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM (SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM audit_records ORDER BY sequence DESC LIMIT %d) sub ORDER BY sequence ASC`, limit)
	}
	rows, err := db.Pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []audit.Record
	for rows.Next() {
		var r audit.Record
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
func (db *Postgres) ListTenantRecords(ctx context.Context, tenantID int64, limit int) ([]audit.Record, error) {
	query := `SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM audit_records WHERE tenant_id = $1 ORDER BY sequence ASC`
	if limit > 0 {
		query = fmt.Sprintf(`SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM (SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM audit_records WHERE tenant_id = $1 ORDER BY sequence DESC LIMIT %d) sub ORDER BY sequence ASC`, limit)
	}
	rows, err := db.Pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []audit.Record
	for rows.Next() {
		var r audit.Record
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
func (db *Postgres) LatestRecord(ctx context.Context) (*audit.Record, error) {
	query := `SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM audit_records ORDER BY sequence DESC LIMIT 1`
	row := db.Pool.QueryRow(ctx, query)
	var r audit.Record
	var rawDetails []byte
	err := row.Scan(&r.ID, &r.Sequence, &r.Timestamp, &r.TenantID, &r.Action, &r.Actor, &rawDetails, &r.PrevHash, &r.EntryHash)
	if err != nil {
		return nil, nil
	}
	r.Details = json.RawMessage(rawDetails)
	return &r, nil
}

// CheckpointBeforePrune returns the latest audit record prior to pruning retention boundary.
func (db *Postgres) CheckpointBeforePrune(ctx context.Context, before time.Time) (*audit.Record, error) {
	query := `SELECT id, sequence, timestamp, tenant_id, action, actor, details, prev_hash, entry_hash FROM audit_records WHERE timestamp < $1 ORDER BY sequence DESC LIMIT 1`
	row := db.Pool.QueryRow(ctx, query, before)
	var r audit.Record
	var rawDetails []byte
	err := row.Scan(&r.ID, &r.Sequence, &r.Timestamp, &r.TenantID, &r.Action, &r.Actor, &rawDetails, &r.PrevHash, &r.EntryHash)
	if err != nil {
		return db.LatestRecord(ctx)
	}
	r.Details = json.RawMessage(rawDetails)
	return &r, nil
}

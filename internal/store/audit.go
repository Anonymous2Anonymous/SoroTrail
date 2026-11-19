package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

// AuditTrailRecord represents a single tamper-evident audit entry.
type AuditTrailRecord struct {
	ID           int64     `json:"id"`
	Sequence     int64     `json:"sequence"`
	Timestamp    time.Time `json:"timestamp"`
	TenantID     string    `json:"tenant_id"`
	Action       string    `json:"action"`
	Details      string    `json:"details"`
	PreviousHash string    `json:"previous_hash"`
	RecordHash   string    `json:"record_hash"`
}

// AppendAuditRecord appends a new audit record to the tamper-evident chain and emits an external checkpoint log.
func (s *Postgres) AppendAuditRecord(ctx context.Context, tenantID, action, details string) (AuditTrailRecord, error) {
	var lastSeq int64
	var lastHash string

	err := s.pool.QueryRow(ctx, `SELECT sequence, record_hash FROM audit_trail_records ORDER BY sequence DESC LIMIT 1`).Scan(&lastSeq, &lastHash)
	if err != nil && err != pgx.ErrNoRows {
		return AuditTrailRecord{}, fmt.Errorf("fetching last audit record: %w", err)
	}

	seq := lastSeq + 1
	ts := time.Now().UTC()

	canonical, err := canonicalizeAuditContent(seq, ts, tenantID, action, details, lastHash)
	if err != nil {
		return AuditTrailRecord{}, err
	}

	hashBytes := sha256.Sum256([]byte(canonical))
	recordHash := hex.EncodeToString(hashBytes[:])

	var id int64
	err = s.pool.QueryRow(ctx,
		`INSERT INTO audit_trail_records (sequence, timestamp, tenant_id, action, details, previous_hash, record_hash) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		seq, ts, tenantID, action, details, lastHash, recordHash,
	).Scan(&id)
	if err != nil {
		return AuditTrailRecord{}, fmt.Errorf("inserting audit record: %w", err)
	}

	// Publish external checkpoint log line for wholesale truncation detection
	slog.Info("audit checkpoint", "sequence", seq, "record_hash", recordHash, "timestamp", ts.Format(time.RFC3339Nano), "tenant_id", tenantID, "action", action)

	return AuditTrailRecord{
		ID:           id,
		Sequence:     seq,
		Timestamp:    ts,
		TenantID:     tenantID,
		Action:       action,
		Details:      details,
		PreviousHash: lastHash,
		RecordHash:   recordHash,
	}, nil
}

// VerifyAuditChain inspects audit trail records (bounded or full) and returns divergence or success.
func (s *Postgres) VerifyAuditChain(ctx context.Context, limit int) (int64, error) {
	query := `SELECT sequence, timestamp, tenant_id, action, details, previous_hash, record_hash FROM audit_trail_records ORDER BY sequence DESC`
	args := []any{}
	if limit > 0 {
		query += ` LIMIT $1`
		args = append(args, limit)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("querying audit trail records: %w", err)
	}
	defer rows.Close()

	var records []AuditTrailRecord
	for rows.Next() {
		var r AuditTrailRecord
		var ts time.Time
		err := rows.Scan(&r.Sequence, &ts, &r.TenantID, &r.Action, &r.Details, &r.PreviousHash, &r.RecordHash)
		if err != nil {
			return 0, fmt.Errorf("scanning audit record: %w", err)
		}
		r.Timestamp = ts
		records = append(records, r)
	}

	// Reverse to ASC order
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}

	if len(records) == 0 {
		return 0, nil
	}

	var expectedPrevHash string
	if len(records) > 0 {
		// If bounded, we need the actual previous hash of the first fetched record if it's not sequence 1
		if records[0].Sequence > 1 {
			var prevHash string
			err := s.pool.QueryRow(ctx, `SELECT record_hash FROM audit_trail_records WHERE sequence = $1`, records[0].Sequence-1).Scan(&prevHash)
			if err == nil {
				expectedPrevHash = prevHash
			}
		}
	}

	expectedSeq := records[0].Sequence
	for _, r := range records {
		if r.Sequence != expectedSeq {
			return r.Sequence, fmt.Errorf("sequence break: expected %d, got %d", expectedSeq, r.Sequence)
		}
		if r.PreviousHash != expectedPrevHash {
			return r.Sequence, fmt.Errorf("previous hash mismatch at sequence %d", r.Sequence)
		}

		canonical, err := canonicalizeAuditContent(r.Sequence, r.Timestamp, r.TenantID, r.Action, r.Details, r.PreviousHash)
		if err != nil {
			return r.Sequence, err
		}

		hashBytes := sha256.Sum256([]byte(canonical))
		computedHash := hex.EncodeToString(hashBytes[:])

		if computedHash != r.RecordHash {
			return r.Sequence, fmt.Errorf("record hash mismatch at sequence %d", r.Sequence)
		}

		expectedPrevHash = r.RecordHash
		expectedSeq++
	}

	return 0, nil
}

// QueryTenantAuditRecords queries audit records filtered by tenant ID for tenant-scoped visibility.
func (s *Postgres) QueryTenantAuditRecords(ctx context.Context, tenantID string, limit int) ([]AuditTrailRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, sequence, timestamp, tenant_id, action, details, previous_hash, record_hash FROM audit_trail_records WHERE tenant_id = $1 OR tenant_id = '' ORDER BY sequence DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("querying tenant audit records: %w", err)
	}
	defer rows.Close(),

	var out []AuditTrailRecord
	for rows.Next() {
		var r AuditTrailRecord
		var ts time.Time
		err := rows.Scan(&r.ID, &r.Sequence, &ts, &r.TenantID, &r.Action, &r.Details, &r.PreviousHash, &r.RecordHash)
		if err != nil {
			return nil, err
		}
		r.Timestamp = ts
		out = append(out, r)
	}
	return out, nil
}

// PruneAuditRecordsWithCheckpoint checkpoints the chain head and prunes audit records older than retention while preserving the checkpoint boundary.
func (s *Postgres) PruneAuditRecordsWithCheckpoint(ctx context.Context, retentionAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-retentionAge)
	var lastSeq int64
	var lastHash string
	err := s.pool.QueryRow(ctx, `SELECT sequence, record_hash FROM audit_trail_records WHERE timestamp <= $1 ORDER BY sequence DESC LIMIT 1`, cutoff).Scan(&lastSeq, &lastHash)
	if err == nil {
		slog.Info("audit retention checkpoint before prune", "checkpoint_sequence", lastSeq, "record_hash", lastHash, "cutoff", cutoff)
	}

	tag, err := s.pool.Exec(ctx, `DELETE FROM audit_trail_records WHERE timestamp < $1 AND sequence < (SELECT COALESCE(MAX(sequence), 0) FROM audit_trail_records)`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("pruning audit records: %w", err)
	}
	return tag.RowsAffected(), nil
}

func canonicalizeAuditContent(seq int64, ts time.Time, tenantID, action, details, prevHash string) (string, error) {
	obj := map[string]any{
		"sequence":      seq,
		"timestamp":     ts.UTC().Format(time.RFC3339Nano),
		"tenant_id":     tenantID,
		"action":        action,
		"details":       details,
		"previous_hash": prevHash,
	}
	bs, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(bs), nil
}

package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sorotrail/sorotrail/internal/store"
)

func TestAuditChainIntegrityAndVerification(t *testing.T) {
	dbURL := testDatabaseURL(t)
	if dbURL == "" {
		t.Skip("skipping database-backed test: DATABASE_URL not set")
	}

	ctx := context.Background()
	st, err := store.NewPostgres(ctx, dbURL)
	require.NoError(t, err)
	defer st.Close()

	// Clean up test table
	_, _ = st.Pool().Exec(ctx, "TRUNCATE TABLE audit_trail_records")

	// 1. Intact chain test
	r1, err := st.AppendAuditRecord(ctx, "tenant-a", "credential.create", "key_id=1")
	require.NoError(t, err)
	r2, err := st.AppendAuditRecord(ctx, "tenant-b", "tenant.update", "tier=enterprise")
	require.NoError(t, err)
	r3, err := st.AppendAuditRecord(ctx, "tenant-a", "spec.override", "contract=CA123")
	require.NoError(t, err)

	div, err := st.VerifyAuditChain(ctx, 0)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), div)

	// 2. Bounded verification test
	divBounded, err := st.VerifyAuditChain(ctx, 2)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), divBounded)

	// 3. Multi-tenant visibility test
	recordsA, err := st.QueryTenantAuditRecords(ctx, "tenant-a", 10)
	require.NoError(t, err);
	for _, rec := range recordsA {
		assert.True(t, rec.TenantID == "tenant-a" || rec.TenantID == "")
	}

	// 4. Altered record test
	_, err = st.Pool().Exec(ctx, "UPDATE audit_trail_records SET details = 'tampered' WHERE sequence = 2")
	require.NoError(t, err)

	div, err = st.VerifyAuditChain(ctx, 0)
	assert.Error(t, err)
	assert.Equal(t, r2.Sequence, div)

	// Restore r2 details for next checks
	_, _ = st.Pool().Exec(ctx, "UPDATE audit_trail_records SET details = $1 WHERE sequence = 2", r2.Details)

	// 5. Deleted record test
	_, err = st.Pool().Exec(ctx, "DELETE FROM audit_trail_records WHERE sequence = 2")
	require.NoError(t, err)

	div, err = st.VerifyAuditChain(ctx, 0)
	assert.Error(t, err)

	// Re-insert r2 to test truncation/retention
	_, _ = st.Pool().Exec(ctx, "TRUNCATE TABLE audit_trail_records")
	_, _ = st.AppendAuditRecord(ctx, "tenant-a", "credential.create", "key_id=1")

	// 6. Legitimate retention sweep test (checkpoint before prune)
	_, err = st.PruneAuditRecordsWithCheckpoint(ctx, 0)
	require.NoError(t, err)
	div, err = st.VerifyAuditChain(ctx, 0)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), div)
}

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
)

func runAuditVerify(args []string) error {
	fs := flag.NewFlagSet("audit-verify", flag.ExitOnError)
	var dbURL string
	fs.StringVar(&dbURL, "database-url", os.Getenv("DATABASE_URL"), "Database connection URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if dbURL != "" {
		_ = os.Setenv("DATABASE_URL", dbURL)
	}

	ctx := context.Background()
	storeInst, cleanup, err := openStore(ctx)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer cleanup()

	firstDivergence, err := storeInst.VerifyAuditChain(ctx)
	if err != nil {
		return fmt.Errorf("audit chain verification failed at sequence %d: %w", firstDivergence, err)
	}

	fmt.Println("audit trail chain verification: INTACT")
	return nil
}

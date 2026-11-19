package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/sorotrail/sorotrail/internal/audit"
)

func runAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	_ = fs.Parse(args)

	sub := fs.Arg(0)
	if sub == "" {
		sub = "verify"
	}

	switch sub {
	case "verify":
		ctx := context.Background()
		db, closeFn, err := openStore(ctx)
		if err != nil {
			return fmt.Errorf("failed to connect store for audit verification: %w", err)
		}
		defer closeFn()

		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		verifier := audit.NewVerifier(db, logger)
		div, err := verifier.VerifyChain(ctx)
		if err != nil {
			fmt.Printf("FAIL: audit chain broken at sequence %d: %v\n", div, err)
			os.Exit(1)
		}
		fmt.Println("OK: audit chain intact")
		return nil
	default:
		return fmt.Errorf("unknown audit subcommand: %s", sub)
	}
}

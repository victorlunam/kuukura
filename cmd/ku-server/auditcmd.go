package main

import (
	"context"
	"fmt"
)

// runAuditVerify recomputes the whole audit hash chain and prints the number of rows and the head hash. Store the
// head somewhere the database's operator cannot edit: the chain alone shows edits and deletions in the middle, only
// a remembered head shows that the newest rows were cut off. It fails (exit 1) if the chain is broken.
func runAuditVerify(args []string) error {
	if err := noArgs("audit verify", args); err != nil {
		return err
	}
	return withApp(func(ctx context.Context, a *app) error {
		head, err := a.log.VerifyHead(ctx)
		if err != nil {
			return fmt.Errorf("the audit log does not verify: %w", err)
		}
		fmt.Printf("OK: audit log verified, %d rows, head %x\n", head.Rows, head.Hash)
		return nil
	})
}

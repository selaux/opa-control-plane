package database

import (
	"context"
	"database/sql"
	"fmt"
)

type Principal struct {
	Id        string
	Role      string
	CreatedAt string
}

func (db *Database) UpsertPrincipal(ctx context.Context, principal Principal) error {

	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := db.UpsertPrincipalTx(ctx, tx, principal); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit txn for principal %q: %w", principal.Id, err)
	}

	return nil
}

func (db *Database) UpsertPrincipalTx(ctx context.Context, tx *sql.Tx, principal Principal) error {
	if err := db.upsert(ctx, tx, "principals", []string{"id", "role"}, []string{"id"}, principal.Id, principal.Role); err != nil {
		return fmt.Errorf("failed to insert principal: %w", err)
	}

	return nil
}

func (db *Database) GetPrincipalId(ctx context.Context, apiKey string) (string, error) {

	query := `
		SELECT principals.id FROM principals JOIN tokens ON tokens.name = principals.id WHERE tokens.api_key = ?
	`

	row := db.db.QueryRowContext(ctx, query, apiKey)
	var principalId string
	if err := row.Scan(&principalId); err != nil {
		return "", err
	}
	return principalId, nil
}

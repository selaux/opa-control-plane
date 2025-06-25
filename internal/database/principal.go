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

func UpsertPrincipal(ctx context.Context, db *Database, principal Principal) error {

	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := UpsertPrincipalTx(ctx, tx, principal); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit txn for principal %q: %w", principal.Id, err)
	}

	return nil
}

func UpsertPrincipalTx(ctx context.Context, tx *sql.Tx, principal Principal) error {
	query := `
	INSERT OR REPLACE INTO principals (id, role)
	VALUES ($1, $2)
`
	_, err := tx.ExecContext(ctx, query, principal.Id, principal.Role)
	if err != nil {
		return fmt.Errorf("failed to insert principal: %w", err)
	}
	return nil
}

func GetPrincipalId(ctx context.Context, db *Database, apiKey string) (string, error) {

	query := `
		SELECT principals.id FROM principals JOIN tokens ON tokens.id = principals.id WHERE tokens.api_key = ?
	`

	row := db.db.QueryRowContext(ctx, query, apiKey)
	var principalId string
	if err := row.Scan(&principalId); err != nil {
		return "", err
	}
	return principalId, nil
}

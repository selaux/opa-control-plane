package database

import (
	"context"
	"fmt"
)

type Principal struct {
	Id        string
	Role      string
	CreatedAt string
}

func InsertPrincipal(ctx context.Context, db *Database, principal Principal) error {
	query := `
        INSERT INTO principals (id, role)
        VALUES ($1, $2)
    `
	_, err := db.db.ExecContext(ctx, query, principal.Id, principal.Role)
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

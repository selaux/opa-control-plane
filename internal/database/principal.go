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

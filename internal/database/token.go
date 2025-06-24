package database

import (
	"context"
	"fmt"

	"github.com/tsandall/lighthouse/internal/config"
)

func InsertToken(ctx context.Context, db *Database, token *config.Token) error {
	if _, err := db.db.Exec(`INSERT OR REPLACE INTO tokens (id, api_key) VALUES (?, ?)`, token.Name, token.APIKey); err != nil {
		return err
	}
	if len(token.Scopes) != 1 {
		return fmt.Errorf("multiple scopes are not supported but were found on token %q", token.Name)
	}
	return InsertPrincipal(ctx, db, Principal{Id: token.Name, Role: token.Scopes[0].Role})
}

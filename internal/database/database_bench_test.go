package database_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/styrainc/lighthouse/internal/config"
	"github.com/styrainc/lighthouse/internal/database"
)

func BenchmarkPaginationFinalPageLatency(b *testing.B) {

	sizes := []int64{100, 1000, 10000}
	const limit = 50

	for _, n := range sizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {

			ctx := context.Background()
			var db database.Database
			err := db.InitDB(ctx, filepath.Join(b.TempDir()+b.Name(), "data"))
			if err != nil {
				b.Fatal(err)
			}

			if err := db.UpsertPrincipal(ctx, database.Principal{Id: "admin", Role: "administrator"}); err != nil {
				b.Fatal(err)
			}

			for i := range n {
				if err := db.UpsertSource(ctx, "admin", &config.Source{Name: "source" + fmt.Sprint(i)}); err != nil {
					b.Fatal(err)
				}
			}

			// NOTE(tsandall): this is only for test callers. Callers must treat cursor as opaque.
			cursor := base64.URLEncoding.EncodeToString([]byte(strconv.FormatInt(n-(limit-1), 10)))

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				result, next, err := db.ListSources(ctx, "admin", database.ListOptions{Limit: limit, Cursor: cursor})
				if err != nil {
					b.Fatal(err)
				}
				if next != "" {
					b.Fatal("expected no more pages but got", next)
				}
				if len(result) != limit-1 {
					b.Fatal("expected", limit-1, "but got", len(result))
				}
			}
		})
	}

}

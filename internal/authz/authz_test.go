package authz

import (
	"context"
	"fmt"
	"testing"
)

// TODO(tsandall): add integration test
func testPartial(t *testing.T) {
	result, err := Partial(context.Background(), Access{Principal: "bob", Resource: "sources", Permission: "sources.view"}, map[string]sqlColumnRef{"input.id": {Table: "sources", Column: "id"}})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(result.SQL())
}

package config_test

import (
	"bytes"
	"testing"

	"github.com/tsandall/lighthouse/internal/config"
)

func TestRootValidateAndInjectDefaults(t *testing.T) {
	cases := []struct {
		name string
		root string
		errs []string
	}{
		{
			name: "valid config",
			root: `{systems: {foo: {git: {repo: https://example.com/repo.git}}}}`,
		},
		{
			name: "missing secret value",
			root: `{systems: {foo: {git: {repo: https://example.com/repo.git}}}, secrets: {bar: {}}}`,
			errs: []string{
				`secret "bar" is missing a value`,
			},
		},
		{
			name: "bad system secret reference",
			root: `{systems: {foo: {git: {repo: https://example.com/repo.git, credentials: {http: missing_secret_name}}}}, secrets: {bar: {value: x1234}}}`,
			errs: []string{`system "foo" git http credential refers to secret "missing_secret_name" that is invalid or undefined`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, warnings, err := config.Parse(bytes.NewReader([]byte(tc.root)))
			if err != nil {
				t.Fatal(err)
			}
			if len(warnings) != len(tc.errs) {
				t.Fatalf("expected: %v\n\ngot: %v", tc.errs, warnings)
			}
			for i := range warnings {
				if warnings[i].Error() != tc.errs[i] {
					t.Fatalf("expected: %v\n\ngot: %v", tc.errs, warnings)
				}
			}
		})
	}
}

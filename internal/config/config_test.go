package config_test

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/tsandall/lighthouse/internal/config"
	"gopkg.in/yaml.v3"
)

func TestParseSecretResolve(t *testing.T) {

	result, err := config.Parse(bytes.NewReader([]byte(`{
		systems: {
			foo: {
				git: {
					repo: https://example.com/repo.git,
					credentials: secret1
				}
			}
		},
		secrets: {
			secret1: {
				username: bob,
				password: '${LIGHTHOUSE_PASSWORD}'
			}
		}
	}`)))

	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("LIGHTHOUSE_PASSWORD", "passw0rd")

	secret, err := result.Systems["foo"].Git.Credentials.Resolve()
	if err != nil {
		t.Fatal(err)
	}

	exp := map[string]interface{}{
		"username": "bob",
		"password": "passw0rd",
	}

	value, _ := secret.Get(context.Background())

	if !reflect.DeepEqual(value, exp) {
		t.Fatalf("expected: %v\n\ngot: %v", exp, value)
	}

}

func TestFilesMarshallingRoundtrip(t *testing.T) {

	f := config.Files{
		"foo.rego": "package x\np := 7",
	}

	bs, err := yaml.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}

	f2 := config.Files{}

	if err := yaml.Unmarshal(bs, &f2); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(f, f2) {
		t.Fatalf("exp: %v\n\ngot: %v", f, f2)
	}

}

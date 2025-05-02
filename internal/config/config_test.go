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
				},
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

	cfg, err := config.Parse(bytes.NewBufferString(`{
		systems: {
			foo: {
				files: {
					"foo.rego": "cGFja2FnZSBmb28=",
				}
			}
		}
	}`))

	if err != nil {
		t.Fatal(err)
	}

	if cfg.Systems["foo"].Files["foo.rego"] != "package foo" {
		t.Fatalf("expected file to be 'package foo' but got:\n%v", cfg.Systems["foo"].Files["foo.rego"])
	}

	bs, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cfg2, err := config.Parse(bytes.NewBuffer(bs))
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.Systems["foo"].Equal(cfg2.Systems["foo"]) {
		t.Fatal("expected systems to be equal")
	}

}

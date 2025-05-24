package cmd

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestMerge(t *testing.T) {

	bs := []byte(`[
		{
			"keep0": 0,
			"overwrite1": 0,
			"merge": {
				"keep0": 0,
				"overwrite2": 0,
				"merge1": {
					"keep0": 0,
					"overwrite1": 0
				}
			}
		},
		{
			"overwrite1": 1,
			"keep1": 1,
			"merge": {
				"keep1": 1,
				"overwrite2": 1,
				"merge1": {
					"overwrite1": 1
				}
			}
		},
		{
			"merge": {
				"overwrite2": 2,
				"keep2": 2
			},
			"keep2": 2
		}
	]`)
	var docs []map[string]interface{}
	if err := json.Unmarshal(bs, &docs); err != nil {
		t.Fatal(err)
	}

	result := merge(docs)

	bs2 := []byte(`{
		"keep0": 0,
		"overwrite1": 1,
		"merge": {
			"keep0": 0,
			"overwrite2": 2,
			"merge1": {
				"keep0": 0,
				"overwrite1": 1
			},
			"keep2": 2,
			"keep1": 1
		},
		"keep2": 2,
		"keep1": 1
	}`)

	var exp map[string]interface{}
	if err := json.Unmarshal(bs2, &exp); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(result, exp) {
		t.Fatalf("expected %v but got %v", exp, result)
	}
}

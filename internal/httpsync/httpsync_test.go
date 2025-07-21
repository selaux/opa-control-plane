package httpsync

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"
)

func TestHTTPDataSynchronizer(t *testing.T) {
	contents := `{"key": "value"}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(contents))
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	file := path.Join(t.TempDir(), "foo/test.json")
	synchronizer := New(file, ts.URL, nil, nil)
	err := synchronizer.Execute(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("expected no error while reading file, got: %v", err)
	}

	if !bytes.Equal(data, []byte(contents)) {
		t.Fatal("downloaded data does not match expected contents")
	}
}

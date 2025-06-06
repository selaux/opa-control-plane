package server

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestServer(t *testing.T) {
	router := mux.NewRouter()
	database := newMockDatabase()
	New().WithDatabase(database).WithRouter(router).Init()
	s := httptest.NewServer(router)
	defer s.Close()

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		statusCode int
		result     string
	}{
		{
			name:       "GET",
			method:     "GET",
			path:       "/v1/bundles/system1/foo",
			body:       "",
			statusCode: 200,
			result:     "{}\n",
		},
		{
			name:       "PUT",
			method:     "PUT",
			path:       "/v1/bundles/system1/foo",
			body:       `{"key": "value"}`,
			statusCode: 200,
			result:     "{}\n",
		},
		{
			name:       "GET after PUT",
			method:     "GET",
			path:       "/v1/bundles/system1/foo",
			body:       "",
			statusCode: 200,
			result: `{"result":{"key":"value"}}
`,
		},
		{
			name:       "POST",
			method:     "POST",
			path:       "/v1/bundles/system1/foo",
			body:       `{"key": "value2"}`,
			statusCode: 200,
			result:     "{}\n",
		},
		{
			name:       "GET after POST",
			method:     "GET",
			path:       "/v1/bundles/system1/foo",
			body:       "",
			statusCode: 200,
			result: `{"result":{"key":"value2"}}
`,
		},
		{
			name:       "DELETE",
			method:     "DELETE",
			path:       "/v1/bundles/system1/foo",
			body:       "",
			statusCode: 200,
			result:     "{}\n",
		},
		{
			name:       "GET after DELETE",
			method:     "GET",
			path:       "/v1/bundles/system1/foo",
			body:       "",
			statusCode: 200,
			result:     "{}\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var body []byte
			switch test.method {
			case "PUT", "POST":
				if test.body != "" {
					body = []byte(test.body)
				}
			}
			req := httptest.NewRequest(test.method, s.URL+test.path, bytes.NewBuffer(body))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != test.statusCode {
				t.Errorf("expected status %d, got %d", test.statusCode, w.Code)
			}

			if w.Body.String() != test.result {
				t.Errorf("expected body %q, got %q", test.result, w.Body.String())
			}
		})
	}
}

type mockDatabase struct {
	data map[key]interface{}
}

func newMockDatabase() *mockDatabase {
	return &mockDatabase{
		data: make(map[key]interface{}),
	}
}

type key struct {
	bundleId string
	path     string
}

func (m *mockDatabase) BundlesDataGet(ctx context.Context, bundleId, path string) (interface{}, bool, error) {
	if data, ok := m.data[key{bundleId, path}]; ok {
		return data, true, nil
	}
	return nil, false, nil
}

func (m *mockDatabase) BundlesDataPut(ctx context.Context, bundleId, path string, data interface{}) error {
	m.data[key{bundleId, path}] = data
	return nil
}

func (m *mockDatabase) BundlesDataDelete(ctx context.Context, bundleId, path string) error {
	delete(m.data, key{bundleId, path})
	return nil
}

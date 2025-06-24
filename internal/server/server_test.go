package server

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/database"
)

func TestServer(t *testing.T) {
	router := mux.NewRouter()
	var db database.Database

	ctx := context.Background()
	if err := db.InitDB(context.Background(), t.TempDir()); err != nil {
		t.Fatal(err)
	}

	if err := database.InsertToken(ctx, &db, &config.Token{Name: "admin", APIKey: "testapikey", Scopes: []config.Scope{{Role: "administrator"}}}); err != nil {
		t.Fatal(err)
	}

	New().WithDatabase(&db).WithRouter(router).Init()
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
			path:       "/v1/sources/system1/foo",
			body:       "",
			statusCode: 200,
			result:     "{}\n",
		},
		{
			name:       "PUT",
			method:     "PUT",
			path:       "/v1/sources/system1/foo",
			body:       `{"key": "value"}`,
			statusCode: 200,
			result:     "{}\n",
		},
		{
			name:       "GET after PUT",
			method:     "GET",
			path:       "/v1/sources/system1/foo",
			body:       "",
			statusCode: 200,
			result: `{"result":{"key":"value"}}
`,
		},
		{
			name:       "POST",
			method:     "POST",
			path:       "/v1/sources/system1/foo",
			body:       `{"key": "value2"}`,
			statusCode: 200,
			result:     "{}\n",
		},
		{
			name:       "GET after POST",
			method:     "GET",
			path:       "/v1/sources/system1/foo",
			body:       "",
			statusCode: 200,
			result: `{"result":{"key":"value2"}}
`,
		},
		{
			name:       "DELETE",
			method:     "DELETE",
			path:       "/v1/sources/system1/foo",
			body:       "",
			statusCode: 200,
			result:     "{}\n",
		},
		{
			name:       "GET after DELETE",
			method:     "GET",
			path:       "/v1/sources/system1/foo",
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
			req.Header.Add("authorization", "Bearer testapikey")
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

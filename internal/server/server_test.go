package server

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/database"
	"github.com/tsandall/lighthouse/internal/server/types"
)

func TestServerSourcesData(t *testing.T) {
	ctx := context.Background()
	db := initTestDB(ctx, t)
	ts := initTestServer(t, db)
	defer ts.Close()

	if err := database.UpsertPrincipal(ctx, db, database.Principal{Id: "internaladmin", Role: "administrator"}); err != nil {
		t.Fatal(err)
	}

	const adminKey = "test-admin-apikey"

	if err := db.UpsertToken(ctx, "internaladmin", &config.Token{Name: "admin", APIKey: adminKey, Scopes: []config.Scope{{Role: "administrator"}}}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		apikey     string
		statusCode int
		result     string
	}{
		{
			name:       "Create source",
			method:     "PUT",
			path:       "/v1/sources/system1",
			body:       `{}`,
			apikey:     adminKey,
			statusCode: 200,
			result:     "{}\n",
		},
		{
			name:       "GET",
			method:     "GET",
			path:       "/v1/sources/system1/foo",
			body:       "",
			apikey:     adminKey,
			statusCode: 200,
			result:     "{}\n",
		},
		{
			name:       "PUT",
			method:     "PUT",
			path:       "/v1/sources/system1/foo",
			body:       `{"key": "value"}`,
			apikey:     adminKey,
			statusCode: 200,
			result:     "{}\n",
		},
		{
			name:       "GET after PUT",
			method:     "GET",
			path:       "/v1/sources/system1/foo",
			body:       "",
			apikey:     adminKey,
			statusCode: 200,
			result: `{"result":{"key":"value"}}
`,
		},
		{
			name:       "POST",
			method:     "POST",
			path:       "/v1/sources/system1/foo",
			body:       `{"key": "value2"}`,
			apikey:     adminKey,
			statusCode: 200,
			result:     "{}\n",
		},
		{
			name:       "GET after POST",
			method:     "GET",
			path:       "/v1/sources/system1/foo",
			body:       "",
			apikey:     adminKey,
			statusCode: 200,
			result: `{"result":{"key":"value2"}}
`,
		},
		{
			name:       "DELETE",
			method:     "DELETE",
			path:       "/v1/sources/system1/foo",
			body:       "",
			apikey:     adminKey,
			statusCode: 200,
			result:     "{}\n",
		},
		{
			name:       "GET after DELETE",
			method:     "GET",
			path:       "/v1/sources/system1/foo",
			body:       "",
			apikey:     adminKey,
			statusCode: 200,
			result:     "{}\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tr := ts.Request(test.method, test.path, test.body, test.apikey).ExpectStatus(test.statusCode)

			if tr.Body().String() != test.result {
				t.Fatalf("expected body %q, got %q", test.result, tr.Body().String())
			}
		})
	}
}

func TestServerSourceOwners(t *testing.T) {
	ctx := context.Background()

	db := initTestDB(ctx, t)
	ts := initTestServer(t, db)
	defer ts.Close()

	if err := database.UpsertPrincipal(ctx, db, database.Principal{Id: "internal", Role: "administrator"}); err != nil {
		t.Fatal(err)
	}

	const ownerKey = "test-owner-key"
	const ownerKey2 = "test-owner-key2"

	if err := db.UpsertToken(ctx, "internal", &config.Token{Name: "testowner", APIKey: ownerKey, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
		t.Fatal(err)
	}

	if err := db.UpsertToken(ctx, "internal", &config.Token{Name: "testowner2", APIKey: ownerKey2, Scopes: []config.Scope{{Role: "owner"}}}); err != nil {
		t.Fatal(err)
	}

	ts.Request("PUT", "/v1/sources/testsrc", "{}", ownerKey).ExpectStatus(200)

	var ownerList types.SourcesListResponseV1
	ts.Request("GET", "/v1/sources", "", ownerKey).ExpectStatus(200).ExpectBody(&ownerList)
	if len(ownerList.Result) != 1 {
		t.Fatal("expected exactly one source")
	}

	// TODO(tsandall): check details

	var ownerList2 types.SourcesListResponseV1
	ts.Request("GET", "/v1/sources", "", ownerKey2).ExpectStatus(200).ExpectBody(&ownerList2)
	if len(ownerList2.Result) != 0 {
		t.Fatal("did not expect to see source")
	}

	ts.Request("PUT", "/v1/sources/testsrc", "{}", ownerKey2).ExpectStatus(403)
	ts.Request("PUT", "/v1/sources/testsrc", "{}", ownerKey).ExpectStatus(200)
}

func initTestDB(ctx context.Context, t *testing.T) *database.Database {
	t.Helper()
	var db database.Database
	if err := db.InitDB(ctx, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	return &db
}

type testServer struct {
	t      *testing.T
	srv    *Server
	router *mux.Router
	s      *httptest.Server
}

func initTestServer(t *testing.T, db *database.Database) *testServer {
	var ts testServer
	ts.t = t
	ts.router = mux.NewRouter()
	ts.srv = New().WithDatabase(db).WithRouter(ts.router)
	ts.srv.Init()
	ts.s = httptest.NewServer(ts.router)
	return &ts
}

func (ts *testServer) Close() {
	ts.s.Close()
}

func (ts *testServer) Request(method, path string, body string, apikey string) *testResponse {
	var buf io.Reader
	if body != "" {
		buf = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(method, ts.s.URL+path, buf)
	if apikey != "" {
		req.Header.Add("authorization", "Bearer "+apikey)
	}
	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)
	return &testResponse{ts: ts, w: w}
}

type testResponse struct {
	ts *testServer
	w  *httptest.ResponseRecorder
}

func (tr *testResponse) Body() *bytes.Buffer {
	return tr.w.Body
}

func (tr *testResponse) ExpectStatus(code int) *testResponse {
	tr.ts.t.Helper()
	if tr.w.Code != code {
		tr.ts.t.Fatalf("expected status %v but got %v", code, tr.w.Code)
	}
	return tr
}

func (tr *testResponse) ExpectBody(x interface{}) *testResponse {
	tr.ts.t.Helper()
	if err := newJSONDecoder(tr.w.Body).Decode(x); err != nil {
		tr.ts.t.Fatal(err)
	}
	return tr
}

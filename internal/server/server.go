package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/gorilla/mux"
	"github.com/open-policy-agent/opa/server/writer"
	"github.com/tsandall/lighthouse/internal/server/types"
)

type Server struct {
	router   *mux.Router
	database Database
}

type Database interface {
	LibrariesDataGet(ctx context.Context, libraryId, path string) (data interface{}, ok bool, err error)
	LibrariesDataPut(ctx context.Context, libraryId, path string, data interface{}) error
	LibrariesDataDelete(ctx context.Context, libraryId, path string) error
}

func New() *Server {
	return &Server{}
}

func (s *Server) Init() *Server {
	if s.router == nil {
		s.router = mux.NewRouter()
	}

	s.router.Handle("/v1/libraries/{library:.+}/{path:.+}", http.HandlerFunc(s.v1LibrariesDataGet)).Methods(http.MethodGet)
	s.router.Handle("/v1/libraries/{library:.+}/{path:.+}", http.HandlerFunc(s.v1LibrariesDataPut)).Methods(http.MethodPost, http.MethodPut)
	s.router.Handle("/v1/libraries/{library:.+}/{path:.+}", http.HandlerFunc(s.v1LibrariesDataDelete)).Methods(http.MethodDelete)

	return s
}

func (s *Server) WithRouter(router *mux.Router) *Server {
	s.router = router
	return s
}

func (s *Server) WithDatabase(db Database) *Server {
	s.database = db
	return s
}

func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.router)
}

// v1LibrariesDataGet handles GET requests to retrieve data from a library.
func (s *Server) v1LibrariesDataGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	libraryId, err := url.PathUnescape(vars["library"])
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	data, ok, err := s.database.LibrariesDataGet(ctx, libraryId, path.Join(vars["path"], "data.json"))
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.LibrariesGetDataResponseV1{}

	if ok {
		resp.Result = &data
	}

	JSONOK(w, resp, pretty(r))
}

// v1LibrariesDataPut handles PUT and POST requests to upload data to a library.
func (s *Server) v1LibrariesDataPut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	libraryId, err := url.PathUnescape(vars["library"])
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	var value interface{}
	if err := newJSONDecoder(r.Body).Decode(&value); err != nil {
		writer.ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	err = s.database.LibrariesDataPut(ctx, libraryId, path.Join(vars["path"], "data.json"), value)
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.LibrariesPutDataResponseV1{}
	JSONOK(w, resp, pretty(r))
}

// v1LibrariesDataDelete handles DELETE requests to remove data from a library.
func (s *Server) v1LibrariesDataDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)

	libraryId, err := url.PathUnescape(vars["library"])
	if err != nil {
		ErrorString(w, http.StatusBadRequest, types.CodeInvalidParameter, err)
		return
	}

	err = s.database.LibrariesDataDelete(ctx, libraryId, path.Join(vars["path"], "data.json"))
	if err != nil {
		errorAuto(w, err)
		return
	}

	resp := types.LibrariesDeleteDataResponseV1{}
	JSONOK(w, resp, pretty(r))
}

func errorAuto(w http.ResponseWriter, err error) {
	switch {
	default:
		ErrorString(w, http.StatusInternalServerError, types.CodeInternal, err)
	}
}

func ErrorString(w http.ResponseWriter, status int, code string, err error) {
	Error(w, status, types.NewErrorV1(code, err.Error()))
}

func Error(w http.ResponseWriter, status int, err *types.ErrorV1) {
	headers := w.Header()
	headers.Add("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(err.Bytes(), byte('\n')))
}

func JSON(w http.ResponseWriter, code int, v interface{}, pretty bool) {
	enc := json.NewEncoder(w)
	if pretty {
		enc.SetIndent("", "  ")
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)

	if err := enc.Encode(v); err != nil {
		errorAuto(w, err)
	}
}

func JSONOK(w http.ResponseWriter, v interface{}, pretty bool) {
	JSON(w, http.StatusOK, v, pretty)
}

func getBoolParam(url *url.URL, name string, ifEmpty bool) bool {
	p, ok := url.Query()[name]
	if !ok {
		return false
	}

	if len(p) == 1 && p[0] == "" {
		return ifEmpty
	}

	for _, x := range p {
		if strings.ToLower(x) == "true" {
			return true
		}
	}

	return false
}

func pretty(r *http.Request) bool {
	return getBoolParam(r.URL, types.ParamPrettyV1, true)
}

func newJSONDecoder(r io.Reader) *json.Decoder {
	decoder := json.NewDecoder(r)
	decoder.UseNumber()
	return decoder
}

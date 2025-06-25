package types

import (
	"encoding/json"

	"github.com/tsandall/lighthouse/internal/config"
)

const (
	CodeInternal         = "internal_error"
	CodeInvalidParameter = "invalid_parameter"
)

const (
	ParamPrettyV1 = "pretty"
)

type SourcesGetDataResponseV1 struct {
	Result *interface{} `json:"result,omitempty"`
}

type SourcesListResponseV1 struct {
	Result []*config.Source `json:"result,omitempty"`
}

type SourcesPutResponseV1 struct{}

type SourcesDeleteDataResponseV1 struct{}

type SourcesPutDataResponseV1 struct{}

type ErrorV1 struct {
	Code    string  `json:"code"`
	Message string  `json:"message"`
	Errors  []error `json:"errors,omitempty"`
}

func NewErrorV1(code, f string) *ErrorV1 {
	return &ErrorV1{
		Code:    code,
		Message: f,
	}
}

func (e *ErrorV1) Bytes() []byte {
	bs, _ := json.MarshalIndent(e, "", "  ")
	return bs
}

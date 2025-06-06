package types

import (
	"encoding/json"
)

const (
	CodeInternal         = "internal_error"
	CodeInvalidParameter = "invalid_parameter"
)

const (
	ParamPrettyV1 = "pretty"
)

type BundlesGetDataResponseV1 struct {
	Result *interface{} `json:"result,omitempty"`
}

type BundlesDeleteDataResponseV1 struct{}
type BundlesPutDataResponseV1 struct{}

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

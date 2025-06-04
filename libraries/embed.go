package libraries

import (
	"embed"

	_ "github.com/open-policy-agent/opa/cmd" // for running library tests
)

//go:embed *
var FS embed.FS

package database

import "fmt"

var ErrNotFound = fmt.Errorf("not found")
var ErrNotAuthorized = fmt.Errorf("not authorized")

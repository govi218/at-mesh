package server

import (
	_ "embed"
)

//go:embed templates/authorize.html
var authorizePageHTML string

//go:embed templates/error.html
var errorPageHTML string

//go:embed templates/success.html
var successPageHTML string

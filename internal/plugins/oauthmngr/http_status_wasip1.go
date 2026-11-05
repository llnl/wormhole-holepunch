//go:build wasip1

package oauthmngr

// Envoy's WASI runtime cannot load net/http's filesystem-related imports.
const (
	statusFound               = 302
	statusBadRequest          = 400
	statusUnauthorized        = 401
	statusForbidden           = 403
	statusNotFound            = 404
	statusMethodNotAllowed    = 405
	statusInternalServerError = 500
	statusOK                  = 200
)

//go:build !wasip1

package oauthmngr

import "net/http"

const (
	statusFound               = http.StatusFound
	statusBadRequest          = http.StatusBadRequest
	statusUnauthorized        = http.StatusUnauthorized
	statusForbidden           = http.StatusForbidden
	statusNotFound            = http.StatusNotFound
	statusMethodNotAllowed    = http.StatusMethodNotAllowed
	statusInternalServerError = http.StatusInternalServerError
	statusOK                  = http.StatusOK
)

// Package rules maintains established validation for shared aspects relating
// to a range of inbound requests, headers, and potential configurations.
package rules

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/go-playground/validator/v10"

	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
)

const (
	// Observe 8KB size maximum fallback for any check. Most can enforce
	// lower values if identified (nginx.org/en/docs/http/ngx_http_core_module.html).
	maxHeaderKB = 8192
)

var (
	reqTokenRegexp = regexp.MustCompile(`^[A-Fa-f0-9-]{36}\.[A-Za-z0-9\-_\.=/]{1,128}$`) // #nosec G101
	kidRegexp      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-_\.]{0,128}$`)
)

type Validator interface {
	// SafeHeader retrieves a header (given the specified key) from the request, validating
	// it against a specified struct tag. These tags must either be defined in our rules
	// packages or supported by the validation library defaults.
	SafeHeader(req *http.Request, key, tag string) (string, *errs.StatusError)
	// Struct validates a structs exposed fields, and automatically validates nested structs,
	// unless otherwise specified.
	Struct(s any) *errs.StatusError
	// Var validates a single variable using tag style validation.
	Var(field any, tag string) *errs.StatusError
}

type internal struct {
	v *validator.Validate
}

// NewValidator generates an interface to assist in user input validation.  The following
// custom rules registered in addition to any from github.com/go-playground/validator:
//   - reqToken (string): optionally ensures a valid generic authorization token has been
//     supplied that contains no potentially malicious characters and generic maximum length.
//   - kid (string): optionally ensure key ID found in JWT header.
//   - headerVal (string|[]string): optionally verify that the value can be safely injected into a
//     request/response header.
//   - wormholeURL (string|URLString): optionally ensure a valid URL is provided that can be used
//     in redirects or Envoy route management. Proper resolution of the URL is not enforced.
func NewValidator() Validator {
	v := validator.New()

	_ = v.RegisterValidation("reqToken", checkReqToken)
	_ = v.RegisterValidation("kid", checkKID)
	_ = v.RegisterValidation("headerVal", checkHeaderVal)
	_ = v.RegisterValidation("wormholeURL", checkWormholeURL)

	return internal{v: v}
}

func (i internal) SafeHeader(req *http.Request, key, tag string) (string, *errs.StatusError) {
	tar := req.Header.Get(key)

	if err := i.v.Var(tar, tag); err != nil {
		usrMsg := fmt.Sprintf("failed to validated %s header with %s", key, tag)
		return "", errs.NewBadReqErr(err, usrMsg)
	}

	return tar, nil
}

func (i internal) Struct(s any) *errs.StatusError {
	err := i.v.Struct(s)
	return wrapValidationError(err)
}

func (i internal) Var(field any, tag string) *errs.StatusError {
	err := i.v.Var(field, tag)
	return wrapValidationError(err)
}

func wrapValidationError(err error) *errs.StatusError {
	if err == nil {
		return nil
	}

	// For the moment lets just expose the entire validation error, we can
	// refine this in a future iteration once we are clear on all required
	// validations.
	return errs.NewBadReqErr(err, err.Error())
}

//

var checkReqToken validator.Func = func(fl validator.FieldLevel) bool {
	return optionalStrField(fl, reqTokenRegexp)
}

var checkKID validator.Func = func(fl validator.FieldLevel) bool {
	return optionalStrField(fl, kidRegexp)
}

var checkHeaderVal validator.Func = func(fl validator.FieldLevel) bool {
	switch v := fl.Field().Interface().(type) {
	case string:
		return validateHeaderVal(v)
	case []string:
		for _, val := range v {
			if !validateHeaderVal(val) {
				return false
			}
		}

		return true
	default:
		return false
	}
}

var checkWormholeURL validator.Func = func(fl validator.FieldLevel) bool {
	switch v := fl.Field().Interface().(type) {
	case string:
		return validateWormholeURL(v)
	case keys.URLString:
		return validateWormholeURL(v.Raw)
	default:
		return false
	}
}

//

func maximumHeader(s string) bool {
	// This is not strictly true for all potentially instance, but does at least set a
	// ceiling for otherwise uncapped values.
	return len(s) > maxHeaderKB
}

func optionalStrField(fl validator.FieldLevel, re *regexp.Regexp) bool {
	if s, ok := fl.Field().Interface().(string); ok {
		if maximumHeader(s) {
			return false
		} else if s == "" {
			return true
		}

		return re.MatchString(s)
	}

	return false
}

func validateHeaderVal(s string) bool {
	if maximumHeader(s) {
		return false
	} else if s == "" {
		return true
	}

	return (ValidateHeaderValue(s) == nil)
}

func validateWormholeURL(s string) bool {
	if s == "" {
		return true
	}

	_, err := ValidateURL(s, false)

	return err == nil
}

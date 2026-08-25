// Package errs provides internal mechanisms to generate and present error
// messages in a standardized manner. The provided wrappers create a distinction
// between the error itself and the details we can safely present to the user along
// with required response statuses.
package errs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

type ErrorType int

const (
	InternalErr ErrorType = iota
	AuthErr
	BadRequestErr
	RedirectErr
	NotFoundErr
)

type StatusError struct {
	details  string
	errMsg   string
	errType  ErrorType
	internal error
	code     int32
	url      string
	headers  map[string]string
}

// StatusErrOption configures optional, non-required attributes on a
// *StatusError at creation time.
type StatusErrOption func(*StatusError)

// WithHeaders adds the given key/value pairs to the set of headers carried
// alongside the error.
func WithHeaders(headers map[string]string) StatusErrOption {
	return func(r *StatusError) {
		if r.headers == nil {
			r.headers = make(map[string]string, len(headers))
		}

		for k, v := range headers {
			r.headers[strings.ToLower(k)] = v
		}
	}
}

// WithSetCookie is a helper around WithHeaders that populates a "set-cookie"
// header from the provided cookie.
func WithSetCookie(cookie *http.Cookie) StatusErrOption {
	return WithHeaders(map[string]string{keys.SetCookieHeader: cookie.String()})
}

//

// NewAuthErr generates a 401 error.
func NewAuthErr(err error, userDetails string, opts ...StatusErrOption) *StatusError {
	return newStatusError(AuthErr, err, userDetails, "", opts...)
}

// NewNotFoundErr generates a 404 error.
func NewNotFoundErr(err error, opts ...StatusErrOption) *StatusError {
	return newStatusError(NotFoundErr, err, "", "", opts...)
}

// NewBadReqErr generates a 400 error.
func NewBadReqErr(err error, userDetails string, opts ...StatusErrOption) *StatusError {
	return newStatusError(BadRequestErr, err, userDetails, "", opts...)
}

// NewInternalErr generates a 500 error.
func NewInternalErr(err error, userDetails string, opts ...StatusErrOption) *StatusError {
	return newStatusError(InternalErr, err, userDetails, "", opts...)
}

// NewRedirectErr generates a redirect.
func NewRedirectErr(url string, opts ...StatusErrOption) *StatusError {
	return newStatusError(RedirectErr, errors.New("redirect required"), "", url, opts...)
}

// SimpleAuthErr generate a 404 error with generic user message.
func SimpleAuthErr(err error) *StatusError {
	return newStatusError(AuthErr, err, "", "")
}

// SimpleBadReqErr generate a 400 error with generic user message.
func SimpleBadReqErr(err error) *StatusError {
	return newStatusError(BadRequestErr, err, "", "")
}

// SimpleInternalErr generate a 500 error with generic user message.
func SimpleInternalErr(err error) *StatusError {
	return newStatusError(InternalErr, err, "", "")
}

//

func (r *StatusError) Body() string {
	resp := struct {
		Code    int      `json:"code"`
		Message string   `json:"message"`
		Details []string `json:"details,omitempty"`
	}{
		Code:    int(r.code),
		Message: r.errMsg,
	}

	if r.details != "" {
		resp.Details = []string{r.details}
	}

	b, err := json.Marshal(resp)
	if err != nil {
		return `{"code":500,"message":"Failed to generate error response"}`
	}

	return string(b)
}

func (r *StatusError) Code() int32 {
	return r.code
}

func (r *StatusError) Error() string {
	if r.internal != nil {
		return fmt.Sprintf("%s: %s", r.errMsg, r.internal.Error())
	}

	return r.errMsg
}

func (r *StatusError) ExpandDetails(d string) {
	if r.details == "" {
		r.details = d
	} else {
		r.details = fmt.Sprintf("%s: %s", r.details, d)
	}
}

func (r *StatusError) Headers() map[string]string {
	if r.headers == nil {
		return nil
	}

	return maps.Clone(r.headers)
}

func (r *StatusError) ExpandInternal(err error) {
	if err == nil {
		return
	}

	if r.internal == nil {
		r.internal = err
		return
	}

	r.internal = fmt.Errorf("%w: %w", err, r.internal)
}

func (r *StatusError) LogError(ctx context.Context, ll logs.Logger) {
	if r.internal != nil {
		// The internal message should be logged according to the type. Any
		// internal error likely indicates an actual error with the plugin
		// or any of the target internal services.
		switch r.errType {
		case InternalErr:
			ll.ErrorCtx(ctx, r.internal.Error())
		case RedirectErr:
		default:
			ll.ErrorCtx(ctx, r.internal.Error())
		}
	}

	ll.DebugCtx(ctx, "request error: "+r.Error())

	if r.errType == RedirectErr {
		ll.InfoCtx(ctx, "redirecting request to "+r.url)
	}
}

func (r *StatusError) RedirectRequired() (bool, string) {
	if r.errType == RedirectErr {
		return true, r.url
	}

	return false, ""
}

//

func newStatusError(
	errType ErrorType,
	internal error,
	userDetails string,
	url string,
	opts ...StatusErrOption,
) *StatusError {
	r := &StatusError{
		details:  userDetails,
		errMsg:   errType.errorMsg(),
		errType:  errType,
		internal: internal,
		code:     errType.code(),
		url:      url,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

func (e ErrorType) errorMsg() string {
	switch e {
	case AuthErr:
		return "Unauthorized"
	case BadRequestErr:
		return "Bad Request"
	case InternalErr:
		return "Internal Server Error"
	case RedirectErr:
		return "Found"
	case NotFoundErr:
		return "Not Found"
	default:
		return "Unknown Error"
	}
}

func (e ErrorType) code() int32 {
	switch e {
	case AuthErr:
		return int32(codes.Unauthenticated)
	case BadRequestErr:
		return int32(codes.InvalidArgument)
	case InternalErr:
		return int32(codes.Internal)
	case NotFoundErr:
		return int32(codes.NotFound)
	// case Redirect:
	// These is no matching gRPC code for a 302 redirect that
	// we can leverage; however, in the existing flows this should
	// not present an issue.
	default:
		return int32(codes.Unknown)
	}
}

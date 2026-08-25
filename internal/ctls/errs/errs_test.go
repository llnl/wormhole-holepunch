package errs

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_logs"
)

func Test_AuthErr(t *testing.T) {
	internalErr := errors.New("authentication failed")

	t.Run("NewAuthErr", func(t *testing.T) {
		err := NewAuthErr(internalErr, "Invalid credentials")

		assert.Equal(t, int32(codes.Unauthenticated), err.Code())
		assert.Contains(t, err.Error(), "Unauthorized: authentication failed")

		body := err.Body()
		assert.Contains(t, body, "Invalid credentials", "details")
	})

	t.Run("SimpleAuthErr", func(t *testing.T) {
		err := SimpleAuthErr(internalErr)

		assert.Equal(t, int32(codes.Unauthenticated), err.Code())
	})

	t.Run("SimpleAuthErr - ExpandDetails", func(t *testing.T) {
		err := SimpleAuthErr(internalErr)
		err.ExpandDetails("foo")
		err.ExpandDetails("bar")

		body := err.Body()
		assert.Contains(t, body, "foo: bar", "details")
	})

	t.Run("ExpandDetails", func(t *testing.T) {
		err := NewAuthErr(internalErr, "foo")
		err.ExpandDetails("bar")

		body := err.Body()
		assert.Contains(t, body, "foo: bar", "details")
	})

	t.Run("ExpandInternal", func(t *testing.T) {
		err := NewAuthErr(internalErr, "Internal failure")
		err.ExpandInternal(errors.New("root cause A"))
		err.ExpandInternal(errors.New("root cause B"))

		assert.Contains(t, err.Error(), "root cause B: root cause A")
	})

	t.Run("ExpandInternal - nil err is a no-op", func(t *testing.T) {
		err := NewAuthErr(internalErr, "Internal failure")
		err.ExpandInternal(nil)

		assert.Equal(t, "Unauthorized: authentication failed", err.Error())
	})

	t.Run("ExpandInternal - starting from a nil internal error", func(t *testing.T) {
		err := SimpleAuthErr(nil)
		err.ExpandInternal(errors.New("root cause"))

		assert.Equal(t, "Unauthorized: root cause", err.Error())
		assert.NotContains(t, err.Error(), "%!w")
	})
}

func Test_NotFoundErr(t *testing.T) {
	internalErr := errors.New("resource not found")

	t.Run("NewNotFoundErr", func(t *testing.T) {
		err := NewNotFoundErr(internalErr)

		assert.Equal(t, int32(codes.NotFound), err.Code())
		assert.Contains(t, err.Error(), "Not Found: resource not found")
	})

	t.Run("NewNotFoundErr - no details omits the details field", func(t *testing.T) {
		err := NewNotFoundErr(internalErr)

		assert.JSONEq(t, `{"code":5,"message":"Not Found"}`, err.Body())
	})
}

func Test_BadReqErr(t *testing.T) {
	internalErr := errors.New("invalid request format")

	t.Run("NewBadReqErr", func(t *testing.T) {
		err := NewBadReqErr(internalErr, "Check JSON formatting")

		assert.Equal(t, int32(codes.InvalidArgument), err.Code())
		assert.Contains(t, err.Error(), "Bad Request")

		body := err.Body()
		assert.Contains(t, body, "Check JSON formatting")
	})

	t.Run("SimpleBadReqErr", func(t *testing.T) {
		err := SimpleBadReqErr(internalErr)

		assert.Equal(t, int32(codes.InvalidArgument), err.Code())
		assert.Contains(t, err.Error(), "Bad Request")
	})
}

func Test_InternalErr(t *testing.T) {
	internalErr := errors.New("database connection failed")

	t.Run("NewInternalErr", func(t *testing.T) {
		err := NewInternalErr(internalErr, "Please contact support")

		assert.Equal(t, int32(codes.Internal), err.Code())
		assert.Contains(t, err.Error(), "Internal Server Error")

		body := err.Body()
		assert.Contains(t, body, "Please contact support", "details")
	})

	t.Run("SimpleBadReqErr", func(t *testing.T) {
		err := SimpleInternalErr(internalErr)

		assert.Equal(t, int32(codes.Internal), err.Code())
		assert.Contains(t, err.Error(), "Internal Server Error")
	})

	t.Run("RedirectRequired", func(t *testing.T) {
		err := SimpleInternalErr(internalErr)
		isRedirect, _ := err.RedirectRequired()

		assert.False(t, isRedirect)
	})
}

func Test_RedirectErr(t *testing.T) {
	t.Run("RedirectRequired", func(t *testing.T) {
		err := NewRedirectErr("http://localhost/login")
		isRedirect, url := err.RedirectRequired()

		assert.True(t, isRedirect)
		assert.Equal(t, "http://localhost/login", url)
	})
}

func Test_StatusErrOptions(t *testing.T) {
	internalErr := errors.New("boom")

	t.Run("no options - Headers is nil", func(t *testing.T) {
		err := NewInternalErr(internalErr, "")

		assert.Nil(t, err.Headers())
	})

	t.Run("WithHeaders sets the provided headers", func(t *testing.T) {
		err := NewInternalErr(internalErr, "", WithHeaders(map[string]string{
			"x-retry-after": "30",
		}))

		assert.Equal(t, map[string]string{"x-retry-after": "30"}, err.Headers())
	})

	t.Run("WithHeaders merges across multiple calls", func(t *testing.T) {
		err := NewInternalErr(internalErr, "",
			WithHeaders(map[string]string{"a": "1"}),
			WithHeaders(map[string]string{"b": "2"}),
		)

		assert.Equal(t, map[string]string{"a": "1", "b": "2"}, err.Headers())
	})

	t.Run("WithHeaders - later call overrides earlier value for same key", func(t *testing.T) {
		err := NewInternalErr(internalErr, "",
			WithHeaders(map[string]string{"a": "1"}),
			WithHeaders(map[string]string{"a": "2"}),
		)

		assert.Equal(t, map[string]string{"a": "2"}, err.Headers())
	})

	t.Run("WithHeaders normalizes keys to lower case, overriding across case", func(t *testing.T) {
		err := NewInternalErr(internalErr, "",
			WithHeaders(map[string]string{"X-Foo": "1"}),
			WithHeaders(map[string]string{"x-foo": "2"}),
		)

		assert.Equal(t, map[string]string{"x-foo": "2"}, err.Headers())
	})

	t.Run("WithSetCookie sets the set-cookie header from the cookie", func(t *testing.T) {
		cookie := &http.Cookie{Name: "session", Value: "abc123"}

		err := NewAuthErr(internalErr, "", WithSetCookie(cookie))

		assert.Equal(t, map[string]string{keys.SetCookieHeader: cookie.String()}, err.Headers())
	})

	t.Run("Headers returns a copy - mutating it does not affect the error", func(t *testing.T) {
		err := NewInternalErr(internalErr, "", WithHeaders(map[string]string{"a": "1"}))

		got := err.Headers()
		got["a"] = "mutated"
		got["b"] = "injected"

		assert.Equal(t, map[string]string{"a": "1"}, err.Headers())
	})

	t.Run("WithSetCookie combines with WithHeaders", func(t *testing.T) {
		cookie := &http.Cookie{Name: "session", Value: "abc123", MaxAge: -1}

		err := NewAuthErr(internalErr, "",
			WithHeaders(map[string]string{"x-foo": "bar"}),
			WithSetCookie(cookie),
		)

		assert.Equal(t, map[string]string{
			"x-foo":              "bar",
			keys.SetCookieHeader: cookie.String(),
		}, err.Headers())
	})
}

func Test_NewErrOptionsPlumbing(t *testing.T) {
	internalErr := errors.New("boom")
	headers := map[string]string{"x-test": "value"}

	// Every New*Err constructor should forward its variadic
	// StatusErrOption values through to the resulting *StatusError.
	constructors := map[string]func(opts ...StatusErrOption) *StatusError{
		"NewAuthErr":     func(opts ...StatusErrOption) *StatusError { return NewAuthErr(internalErr, "", opts...) },
		"NewNotFoundErr": func(opts ...StatusErrOption) *StatusError { return NewNotFoundErr(internalErr, opts...) },
		"NewBadReqErr":   func(opts ...StatusErrOption) *StatusError { return NewBadReqErr(internalErr, "", opts...) },
		"NewInternalErr": func(opts ...StatusErrOption) *StatusError { return NewInternalErr(internalErr, "", opts...) },
		"NewRedirectErr": func(opts ...StatusErrOption) *StatusError {
			return NewRedirectErr("http://localhost/login", opts...)
		},
	}

	for name, newErr := range constructors {
		t.Run(name, func(t *testing.T) {
			err := newErr(WithHeaders(headers))

			assert.Equal(t, headers, err.Headers())
		})
	}
}

func Test_LogError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	internalErr := errors.New("error msg")

	t.Run("InternalError", func(t *testing.T) {
		ll := mock_logs.NewMockLogger(ctrl)
		ll.EXPECT().ErrorCtx(gomock.Any(), "error msg")
		ll.EXPECT().DebugCtx(gomock.Any(), gomock.Any())

		err := SimpleInternalErr(internalErr)

		err.LogError(t.Context(), ll)
	})

	t.Run("BadRequest", func(t *testing.T) {
		ll := mock_logs.NewMockLogger(ctrl)
		ll.EXPECT().ErrorCtx(gomock.Any(), "error msg")
		ll.EXPECT().DebugCtx(gomock.Any(), gomock.Any())

		err := SimpleBadReqErr(internalErr)

		err.LogError(t.Context(), ll)
	})

	t.Run("Redirect", func(t *testing.T) {
		ll := mock_logs.NewMockLogger(ctrl)
		ll.EXPECT().DebugCtx(gomock.Any(), gomock.Any())
		ll.EXPECT().InfoCtx(gomock.Any(), "redirecting request to http://localhost/login")

		err := NewRedirectErr("http://localhost/login")

		err.LogError(t.Context(), ll)
	})
}

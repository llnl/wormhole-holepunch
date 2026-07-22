package errs

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"

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
}

func Test_NotFoundErr(t *testing.T) {
	internalErr := errors.New("resource not found")

	t.Run("NewNotFoundErr", func(t *testing.T) {
		err := NewNotFoundErr(internalErr)

		assert.Equal(t, int32(codes.NotFound), err.Code())
		assert.Contains(t, err.Error(), "Not Found: resource not found")
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

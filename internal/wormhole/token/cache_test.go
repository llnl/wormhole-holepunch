package token

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/test/mocks/mock_aescipher"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_logs"
	"github.com/llnl/wormhole-holepunch/test/mocks/mock_streams"
)

func Test_internal_mustDecrypt(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("log error", func(t *testing.T) {
		ll := mock_logs.NewMockLogger(ctrl)
		ll.EXPECT().WarnCtx(gomock.Any(), gomock.Any())

		cipher := mock_aescipher.NewMockCipherer(ctrl)
		cipher.EXPECT().Decrypt("token").Return("", errors.New("error msg"))

		kvStore := mock_streams.NewMockKVStore(ctrl)
		kvStore.EXPECT().Delete(gomock.Any(), "key")

		i := internal{
			cipher:  cipher,
			kvStore: kvStore,
		}

		_ = i.mustDecrypt(t.Context(), ll, "key", "token")
	})

	t.Run("empty token", func(t *testing.T) {
		i := internal{}
		got := i.mustDecrypt(t.Context(), nil, "key", "")

		assert.Empty(t, got)
	})
}

func Test_internal_mustEncrypt(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("log error", func(t *testing.T) {
		ll := mock_logs.NewMockLogger(ctrl)
		ll.EXPECT().WarnCtx(gomock.Any(), gomock.Any())

		cipher := mock_aescipher.NewMockCipherer(ctrl)
		cipher.EXPECT().Encrypt("token").Return("", errors.New("error msg"))

		i := internal{
			cipher: cipher,
		}

		_ = i.mustEncrypt(t.Context(), ll, "token")
	})

	t.Run("empty plain", func(t *testing.T) {
		i := internal{}
		got := i.mustEncrypt(t.Context(), nil, "")

		assert.Empty(t, got)
	})
}

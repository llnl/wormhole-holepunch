package requests

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/mock/gomock"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

type webTest struct {
	tarURL          string
	v               any
	mockClient      httpClient
	assertError     func(*testing.T, *RequestFailedError)
	assertInterface func(*testing.T, any)
}

// https://groups.google.com/g/golang-nuts/c/J-Y4LtdGNSw?pli=1
type ClosingBuffer struct {
	*bytes.Buffer
}

func (cb *ClosingBuffer) Close() error {
	return nil
}

type FailingBuffer struct {
	*bytes.Buffer
}

func (*FailingBuffer) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("read error")
}

func (*FailingBuffer) Close() error {
	return nil
}

// mockHTTPClient is a simple mock for the httpClient interface.
type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc == nil {
		panic("mockHTTPClient.DoFunc is nil")
	}

	return m.DoFunc(req)
}

func createMockClient(
	respTxt string,
	statusTxt string,
	statusCode int,
) httpClient {
	return mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Status:     statusTxt,
				StatusCode: statusCode,
				Body:       &ClosingBuffer{bytes.NewBufferString(respTxt)},
				Request:    req,
				Header:     make(http.Header),
			}, nil
		},
	}
}

//

func Test_DefaultClient(t *testing.T) {
	t.Run("enforce default client type", func(t *testing.T) {
		got := DefaultClient(logs.InitializeDiscard())
		assert.IsType(t, manager{}, got)
	})

	t.Run("10 second default timeout", func(t *testing.T) {
		// time.Duration is not a valid constant.
		assert.Equal(t, 10*time.Second, defaultTimeout)
	})
}

func Test_manager_NoAuthGetJSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type Test struct {
		Hello string `json:"hello"`
	}

	tests := map[string]webTest{
		"request error": {
			tarURL: "://",
			v:      &Test{},
			assertError: func(t *testing.T, err *RequestFailedError) {
				assert.True(t, IsRequestFailedError(err))
				assert.ErrorContains(t, err, "failed to create request")
			},
		},
		"bad request (400)": {
			tarURL:     "https://example.com",
			mockClient: createMockClient(`{"error":"400 Bad Request"}`, "400 Bad Request", http.StatusBadRequest),
			v:          &Test{},
			assertError: func(t *testing.T, err *RequestFailedError) {
				assert.True(t, IsRequestFailedError(err))
				assert.ErrorContains(t, err, "400 Bad Request")
			},
		},
		"server error (500), empty response": {
			tarURL:     "https://example.com",
			mockClient: createMockClient("", "500 Internal Server Error", http.StatusInternalServerError),
			v:          &Test{},
			assertError: func(t *testing.T, err *RequestFailedError) {
				assert.True(t, IsRequestFailedError(err))
				assert.ErrorContains(t, err, "status code 500")
			},
		},
		"successful request": {
			tarURL:     "https://example.com",
			mockClient: createMockClient(`{"hello":"world"}`, "200 Successful", http.StatusOK),
			v:          &Test{},
			assertError: func(t *testing.T, err *RequestFailedError) {
				assert.Nil(t, err)
			},
			assertInterface: func(t *testing.T, i any) {
				assert.IsType(t, &Test{}, i)
				assert.Equal(t, "world", i.(*Test).Hello)
			},
		},
		"bad json response": {
			tarURL:     "https://example.com",
			mockClient: createMockClient(`"Invalid`, "200 Successful", http.StatusOK),
			v:          &Test{},
			assertError: func(t *testing.T, err *RequestFailedError) {
				assert.True(t, IsRequestFailedError(err))
				assert.ErrorContains(t, err, "JSON input")
			},
		},
		"missing response body": {
			tarURL: "https://example.com",
			mockClient: mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						Status:     "200 Successful",
						StatusCode: http.StatusOK,
						Body:       &FailingBuffer{bytes.NewBufferString("test")},
						Request:    req,
						Header:     make(http.Header),
					}, nil
				},
			},
			v: &Test{},
			assertError: func(t *testing.T, err *RequestFailedError) {
				assert.True(t, IsRequestFailedError(err))
				assert.ErrorContains(t, err, "failed to read response")
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := manager{
				client: tt.mockClient,
				ll:     logs.InitializeDiscard(),
			}.GetJSON(t.Context(), tt.tarURL, map[string]string{}, tt.v)

			tt.assertError(t, err)
			if tt.assertInterface != nil {
				tt.assertInterface(t, tt.v)
			}
		})
	}
}

func Test_manager_InjectsTraceparentHeader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Manually create a valid SpanContext with fixed IDs.
	tid, err := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	assert.NoError(t, err)

	sid, err := trace.SpanIDFromHex("0123456789abcdef")
	assert.NoError(t, err)

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	assert.True(t, sc.IsValid())

	ctx := trace.ContextWithSpanContext(t.Context(), sc)

	mc := mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			assert.Equal(t,
				"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
				req.Header.Get(keys.TraceparentHeader),
			)

			return &http.Response{
				Status:     "200 Successful",
				StatusCode: http.StatusOK,
				Body:       &ClosingBuffer{bytes.NewBufferString(`{"hello":"world"}`)},
				Request:    req,
				Header:     make(http.Header),
			}, nil
		},
	}

	type TestResp struct {
		Hello string `json:"hello"`
	}
	var v TestResp

	err = manager{
		client: mc,
		ll:     logs.InitializeDiscard(),
	}.GetJSON(ctx, "https://example.com", map[string]string{}, &v)

	assert.Nil(t, err)
	assert.Equal(t, "world", v.Hello)
}

package requests

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
)

const (
	defaultTimeout = 10 * time.Second
	respSnippetMax = 1024
)

type Client interface {
	// GetHeaders makes a request to the target URL and retrieves response headers.
	GetHeaders(
		ctx context.Context,
		url string,
		headers map[string]string,
		cookies []*http.Cookie,
	) (map[string]string, *RequestFailedError)

	// GetJSON sends a GET request to the specified URL, unmarshal the JSON response into the
	// provided reference variable.
	GetJSON(
		ctx context.Context,
		url string,
		headers map[string]string,
		v any,
	) *RequestFailedError

	GetJSONCookies(
		ctx context.Context,
		url string,
		headers map[string]string,
		cookies []*http.Cookie,
		v any,
	) *RequestFailedError

	PostJSONBody(
		ctx context.Context,
		url string,
		headers map[string]string,
		body io.Reader,
		v any,
	) *RequestFailedError
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type manager struct {
	client httpClient
	ll     logs.Logger
}

// DefaultClient returns a Client with the default configuration.
func DefaultClient(ll logs.Logger) Client {
	return manager{
		client: &http.Client{
			Timeout: defaultTimeout,
		},
		ll: ll,
	}
}

func (m manager) GetHeaders(
	ctx context.Context,
	url string,
	headers map[string]string,
	cookies []*http.Cookie,
) (map[string]string, *RequestFailedError) {
	ctx, endSpan := m.ll.StartSpan(ctx, "GetHeaders")
	defer endSpan()

	m.ll.DebugCtx(
		ctx,
		"preforming request",
		m.ll.StringArg("internal.url", url),
		m.ll.StringArg("internal.method", http.MethodGet),
	)

	_, code, respHeaders, err := m.runRequest(ctx, http.MethodGet, url, headers, cookies, nil)

	m.ll.DebugCtx(ctx, fmt.Sprintf("request status: %d", code))

	if err != nil {
		return nil, &RequestFailedError{
			Err:        fmt.Errorf("invalid request: %w", err),
			StatusCode: code,
			URL:        url,
		}
	}

	return HeaderToStringMap(respHeaders), nil
}

func (m manager) GetJSON(
	ctx context.Context,
	url string,
	headers map[string]string,
	v any,
) *RequestFailedError {
	ctx, endSpan := m.ll.StartSpan(ctx, "GetJSON")
	defer endSpan()

	return m.runAndUnmarshal(ctx, http.MethodGet, url, headers, []*http.Cookie{}, nil, v)
}

func (m manager) GetJSONCookies(
	ctx context.Context,
	url string,
	headers map[string]string,
	cookies []*http.Cookie,
	v any,
) *RequestFailedError {
	ctx, endSpan := m.ll.StartSpan(ctx, "GetJSONCookies")
	defer endSpan()

	return m.runAndUnmarshal(ctx, http.MethodGet, url, headers, cookies, nil, v)
}

func (m manager) PostJSONBody(
	ctx context.Context,
	url string,
	headers map[string]string,
	body io.Reader,
	v any,
) *RequestFailedError {
	ctx, endSpan := m.ll.StartSpan(ctx, "PostJSONBody")
	defer endSpan()

	headers["content-type"] = "application/json"

	return m.runAndUnmarshal(ctx, http.MethodPost, url, headers, []*http.Cookie{}, body, v)
}

//

func (m manager) runAndUnmarshal(
	ctx context.Context,
	method, url string,
	headers map[string]string,
	cookies []*http.Cookie,
	body io.Reader,
	v any,
) *RequestFailedError {
	m.ll.DebugCtx(
		ctx,
		"preforming request",
		m.ll.StringArg("internal.url", url),
		m.ll.StringArg("internal.method", method),
	)

	b, code, _, err := m.runRequest(ctx, method, url, headers, cookies, body)
	if err != nil {
		return &RequestFailedError{
			Err:        fmt.Errorf("invalid request: %w", err),
			StatusCode: code,
			URL:        url,
		}
	}

	if err := json.Unmarshal(b, v); err != nil {
		// include body to debug (cap to avoid huge output)
		snippet := string(b)
		if len(snippet) > respSnippetMax {
			snippet = snippet[:respSnippetMax]
		}

		return &RequestFailedError{
			Err: fmt.Errorf("invalid JSON: %w; body starts with: %q", err, snippet),
			URL: url,
		}
	}

	return nil
}

// runRequest now injects trace/span ids from ctx into HTTP headers.
func (m manager) runRequest(
	ctx context.Context,
	method, url string,
	headers map[string]string,
	cookies []*http.Cookie,
	body io.Reader,
) ([]byte, int, http.Header, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return []byte{}, 0, nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Copy provided headers first.
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Inject traceparent (do not overwrite if already set by caller).
	if req.Header.Get(keys.TraceparentHeader) == "" {
		if tp, ok := traceparentFromContext(ctx); ok {
			req.Header.Set(keys.TraceparentHeader, tp)
		}
	}

	for _, v := range cookies {
		req.AddCookie(v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return []byte{}, 0, nil, fmt.Errorf("request failed: %w", err)
	}
	defer closeResponseBody(resp)

	m.ll.DebugCtx(
		ctx,
		"response received",
		m.ll.StringArg("internal.status", resp.Status),
	)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return []byte{}, resp.StatusCode, resp.Header.Clone(), handleInvalidResponse(resp)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		m.ll.WarnCtx(
			ctx,
			"failed to read response body",
			m.ll.StringArg("error", err.Error()),
		)

		return []byte{}, resp.StatusCode, resp.Header.Clone(), fmt.Errorf("failed to read response body: %w", err)
	}

	return b, resp.StatusCode, resp.Header.Clone(), nil
}

// traceparentFromContext returns a W3C traceparent header value:
// <version>-<trace-id>-<parent-id>-<trace-flags>
func traceparentFromContext(ctx context.Context) (string, bool) {
	sc := trace.SpanFromContext(ctx).SpanContext()
	if !sc.IsValid() {
		return "", false
	}

	version := "00"
	traceID := sc.TraceID().String() // 32 hex chars
	parentID := sc.SpanID().String() // 16 hex chars

	// trace-flags: 2 hex chars (e.g. "01" sampled, "00" not sampled)
	flags := []byte{byte(sc.TraceFlags())}
	traceFlags := hex.EncodeToString(flags)

	return fmt.Sprintf("%s-%s-%s-%s", version, traceID, parentID, traceFlags), true
}

// handleInvalidResponse builds an error message that includes the status code and
// response body (if available).
func handleInvalidResponse(resp *http.Response) error {
	errorMessage := fmt.Sprintf("unexpected HTTP status code %d", resp.StatusCode)

	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			errorMessage = fmt.Sprintf("%s: %s", errorMessage, string(body))
		}
	}

	return errors.New(errorMessage)
}

func closeResponseBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

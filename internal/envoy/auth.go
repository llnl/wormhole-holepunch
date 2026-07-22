package envoy

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/llnl/wormhole-holepunch/internal/args"
	"github.com/llnl/wormhole-holepunch/internal/ctls/errs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/keys"
	"github.com/llnl/wormhole-holepunch/internal/ctls/logs"
	"github.com/llnl/wormhole-holepunch/internal/ctls/requests"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/registry"
	"github.com/llnl/wormhole-holepunch/internal/wormhole/token"
)

type authServer struct {
	auth.UnimplementedAuthorizationServer

	ll           logs.Logger
	routeReg     registry.Router
	tokenAuth    token.Authenticator
	tokenSvcArgs args.TokenService
}

func StartEnvoyAuth(
	ctx context.Context,
	ll logs.Logger,
	routeReg registry.Router,
	tokenAuth token.Authenticator,
	tokenSvcArgs args.TokenService,
	webArgs args.WebServer,
) error {
	ll.Info("starting auth server on " + webArgs.ServerAddress)

	lis, err := net.Listen("tcp", webArgs.ServerAddress)
	if err != nil {
		ll.Error("failed to listen: " + err.Error())
		return err
	}

	grpcServer := newGrpcServer(ll, webArgs)
	auth.RegisterAuthorizationServer(
		grpcServer,
		&authServer{
			ll:           ll,
			routeReg:     routeReg,
			tokenAuth:    tokenAuth,
			tokenSvcArgs: tokenSvcArgs,
		},
	)

	// Register health service.
	hs := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, hs)
	hs.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	return runServer(ctx, ll, grpcServer, lis)
}

//

func (s *authServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	ctx, reqLog, endSpan := s.authLogger(ctx, req)
	defer endSpan()

	s.headerDebug(ctx, req, reqLog)

	// Details on the available attributes established by Envoy can be found:
	// https://www.envoyproxy.io/docs/envoy/v1.38.3/intro/arch_overview/advanced/attributes.html
	// Though most of the required details are present, we will need to take a closer
	// look at best process to identify the request host/authority in a way that is
	// free of potential user/upstream influence (methods used with Istio may not work
	// the same in this instance). In the mean time we can rely on the x-wormhole-*
	// headers that have been established by pre-configured filters.
	http := req.GetAttributes().GetRequest().GetHttp()

	details := requests.RequestDetails{
		Headers: http.GetHeaders(),
		Host:    http.GetHeaders()[keys.WormholeHostHeader],
		Scheme:  http.GetHeaders()[keys.WormholeSchemeHeader],
		Path:    http.GetPath(),
	}

	tknCtx, authResp, sErr := s.tokenAuth.RequestHeader(ctx, reqLog, details)
	if sErr != nil {
		sErr.LogError(ctx, reqLog)

		redirect, redirectURL := sErr.RedirectRequired()
		if redirect {
			return s.redirectRequest(ctx, details, redirectURL, reqLog), nil
		}

		return s.denyRequest(ctx, sErr, reqLog), nil
	}

	sErr = s.routeReg.AuthorizeProxy(ctx, reqLog, details, tknCtx)
	if sErr != nil {
		sErr.LogError(ctx, reqLog)

		return s.denyRequest(ctx, sErr, reqLog), nil
	}

	subtoken, sErr := s.tokenAuth.SubtokenFlow(ctx, reqLog, details, tknCtx)
	if sErr != nil {
		reqLog.WarnCtx(
			ctx,
			"failed to generate subtoken",
			reqLog.StringArg("error", sErr.Error()),
		)

		return s.denyRequest(ctx, sErr, reqLog), nil
	}

	if subtoken != "" {
		authResp.SetHeaders[s.tokenSvcArgs.SubtokenHeader] = subtoken
	}

	return s.allowRequest(ctx, authResp, reqLog), nil
}

//

func (s *authServer) authLogger(
	ctx context.Context,
	req *auth.CheckRequest,
) (context.Context, logs.Logger, func()) {
	http := req.GetAttributes().GetRequest().GetHttp()

	ll := s.ll.With(
		[]slog.Attr{
			slog.String(keys.PikoHeader, http.GetHeaders()[keys.PikoHeader]),
			slog.String("guid:"+keys.RequestIDHeader, http.GetHeaders()[keys.RequestIDHeader]),
			slog.String("auth.method", http.GetMethod()),
			slog.String("auth.path", http.GetPath()),
			slog.String("auth.host", http.GetHost()),
		},
	)

	newCtx, endSpan := ll.StartSpan(ctx, "authServer.Check")

	return newCtx, ll, endSpan
}

func (s *authServer) headerDebug(ctx context.Context, req *auth.CheckRequest, ll logs.Logger) {
	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()

	if headers["upgrade"] == "websocket" {
		// Explicitly log so we have a clear link between the request/token
		// and the websocket. Future iterations will require additional logic.
		ll.InfoCtx(ctx, "websocket upgrade request")
	}

	if s.tokenSvcArgs.TokenHeaderDebug {
		for k, v := range headers {
			ll.DebugCtx(ctx, fmt.Sprintf("header: %s=%s", k, v))
		}
	}
}

func (s *authServer) allowRequest(
	ctx context.Context,
	authResp token.AuthResponse,
	reqLog logs.Logger,
) *auth.CheckResponse {
	reqLog.DebugCtx(ctx, "allowing auth request")

	headers := make([]*core.HeaderValueOption, 0) //nolint: prealloc
	for k, v := range authResp.SetHeaders {
		// Headers provided by token.Authenticator have already been validated
		// or based upon pre-established rules.
		headers = append(headers, &core.HeaderValueOption{
			Header: &core.HeaderValue{
				Key:   k,
				Value: v,
			},
			AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}

	return &auth.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.OK),
		},
		HttpResponse: &auth.CheckResponse_OkResponse{
			OkResponse: &auth.OkHttpResponse{
				Headers:         headers,
				HeadersToRemove: authResp.RemoveHeaders,
			},
		},
	}
}

func (s *authServer) denyRequest(
	ctx context.Context,
	sErr *errs.StatusError,
	reqLog logs.Logger,
) *auth.CheckResponse {
	code := statusCode(sErr)

	reqLog.DebugCtx(
		ctx,
		"denying auth request",
		reqLog.StringArg("deny.code", code.String()),
	)

	return &auth.CheckResponse{
		Status: &status.Status{
			Code:    sErr.Code(),
			Message: sErr.Error(),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: code,
				},
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   "content-type",
							Value: "application/json",
						},
					},
				},
				Body: sErr.Body(),
			},
		},
	}
}

// redirectRequest generate a redirect utilizing the trusted redirectURL established
// by the token package (derived by a combination of inputs from the Token Service
// and Route Registry).
func (s *authServer) redirectRequest(
	ctx context.Context,
	details requests.RequestDetails,
	redirectURL string,
	reqLog logs.Logger,
) *auth.CheckResponse {
	reqLog.DebugCtx(
		ctx,
		"redirecting auth request",
		reqLog.StringArg("redirect.url", redirectURL),
		reqLog.StringArg("redirect.code", envoy_type.StatusCode_Found.String()),
	)

	return &auth.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.Unauthenticated),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Found,
				},
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   "location",
							Value: redirectURL, // Redirect to this URL
						},
					}, {
						Header: &core.HeaderValue{
							Key:   keys.XForwardProtoHeader,
							Value: details.Scheme,
						},
					}, {
						Header: &core.HeaderValue{
							Key:   keys.XForwardHostHeader,
							Value: details.Host,
						},
					}, {
						Header: &core.HeaderValue{
							Key:   keys.XForwardURIHeader,
							Value: details.Path,
						},
					},
				},
				Body: fmt.Sprintf(
					`<html>
<body>
	Redirecting to login... <a href="%s"Click here</a> if not redirected.
</body>
</html>`,
					html.EscapeString(redirectURL),
				),
			},
		},
	}
}

//

// statusCode translates the gateway error to the matching HTTP status
// code for a deny auth response.
func statusCode(sErr *errs.StatusError) envoy_type.StatusCode {
	if sErr == nil {
		return envoy_type.StatusCode_Accepted
	}

	switch sErr.Code() {
	case int32(codes.Unauthenticated):
		return envoy_type.StatusCode_Unauthorized
	case int32(codes.InvalidArgument):
		return envoy_type.StatusCode_BadRequest
	case int32(codes.NotFound):
		return envoy_type.StatusCode_NotFound
	default:
		return envoy_type.StatusCode_InternalServerError
	}
}

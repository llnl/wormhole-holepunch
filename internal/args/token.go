package args

import (
	"github.com/urfave/cli/v3"
)

const (
	categoryTokens        = "Token Service"
	tokenHostName         = "token-host"
	tokenExchangePathName = "token-exchange-path"
	oauthExchangePathName = "oauth-exchange-path" //nolint:gosec
	tokenHeaderName       = "token-header"
	tokenHeaderDebugName  = "token-header-debug"
	oauthProxyName        = "oauth-proxy"         //nolint:gosec
	subtokenPathName      = "subtoken-path"       //nolint:gosec
	subtokenHeaderName    = "subtoken-header"     //nolint:gosec
	tokenServiceAdminName = "token-service-admin" //nolint:gosec
	tokenCipherKeyName    = "token-cipher-key"
)

type TokenService struct {
	TokenCipherKey    string
	TokenExchangePath string
	// TokenHeader is the key for the request header the token JWT will be set.
	TokenHeader      string
	TokenHeaderDebug bool
	TokenHost        string
	// TokenServiceAdmin is the optional token used in the x-token header.
	TokenServiceAdmin string //nolint:gosec
	OauthExchangePath string //nolint:gosec
	// OauthProxy target URL for interactions with the oauth2-proxy
	// service. Failure to include one will be used as an indication that
	// the oauth2 code flow should not be supported.
	OauthProxy string //nolint:gosec
	// SubtokenHeader is the key for the request header the sub-token JWT will be set.
	SubtokenHeader string //nolint:gosec
	SubtokenPath   string //nolint:gosec

}

func (f *FlagBuilder) TokenServiceFlags(ts *TokenService) *FlagBuilder {
	f.Flags = append(f.Flags, []cli.Flag{
		&cli.StringFlag{
			Category:    categoryTokens,
			Destination: &ts.TokenCipherKey,
			Name:        tokenCipherKeyName,
			Sources:     envWrapper("TOKEN_CIPHER_KEY"),
			Usage:       "Optionally define a key (value or file) used to encrypt cached tokens",
		},
		&cli.StringFlag{
			Category:    categoryTokens,
			Destination: &ts.TokenExchangePath,
			Name:        tokenExchangePathName,
			Sources:     envWrapper("TOKEN_EXCHANGE_PATH"),
			Usage:       "Path used to exchange user token for internal JWT",
			Value:       "/api/v1/token/jwt",
		},
		&cli.StringFlag{
			Category:    categoryTokens,
			Destination: &ts.TokenHeader,
			Name:        tokenHeaderName,
			Sources:     envWrapper("TOKEN_HEADER"),
			Usage:       "Header where user token will be located",
			Value:       "x-token",
		},
		&cli.BoolFlag{
			Category:    categoryTokens,
			Destination: &ts.TokenHeaderDebug,
			Name:        tokenHeaderDebugName,
			Sources:     envWrapper("TOKEN_HEADER_DEBUG"),
			Usage:       "Log all inbound requests to headers at debug level",
			Value:       false,
		},
		&cli.StringFlag{
			Action:      validateURLAction,
			Destination: &ts.TokenHost,
			Category:    categoryTokens,
			Name:        tokenHostName,
			Sources:     envWrapper("TOKEN_HOST"),
			Usage:       "Address for all requests to the token service",
			Required:    true,
		},
		&cli.StringFlag{
			Category:    categoryTokens,
			Destination: &ts.TokenServiceAdmin,
			Name:        tokenServiceAdminName,
			Sources:     envWrapper("TOKEN_SERVICE_ADMIN"),
			Usage:       "Token used to authenticate admin requests to the token service",
		},
		&cli.StringFlag{
			Category:    categoryTokens,
			Destination: &ts.OauthExchangePath,
			Name:        oauthExchangePathName,
			Sources:     envWrapper("OAUTH_EXCHANGE_PATH"),
			Usage:       "Path used to exchange oauth access_token for internal JWT",
			Value:       "/api/v1/mfa/jwt",
		},
		&cli.StringFlag{
			Action:      validateURLAction,
			Destination: &ts.OauthProxy,
			Category:    categoryTokens,
			Sources:     envWrapper("OAUTH_PROXY"),
			Name:        oauthProxyName,
			Usage:       "URL used when OAuth flow if support required",
		},
		&cli.StringFlag{
			Category:    categoryTokens,
			Destination: &ts.SubtokenHeader,
			Name:        subtokenHeaderName,
			Sources:     envWrapper("SUBTOKEN_HEADER"),
			Usage:       "Header where user sub-token should be set",
			Value:       "x-subtoken",
		},
		&cli.StringFlag{
			Category:    categoryTokens,
			Destination: &ts.SubtokenPath,
			Name:        subtokenPathName,
			Sources:     envWrapper("SUBTOKEN_PATH"),
			Usage:       "Path used to request subtokens when required",
			Value:       "/api/v1/admin/token",
		},
	}...)

	return f
}

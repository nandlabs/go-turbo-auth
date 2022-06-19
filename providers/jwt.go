package providers

import (
	"net/http"
	"time"

	turboAuth "github.com/nandlabs/turbo-auth"
)

type (
	JwtAuth struct {
		signKey   interface{}
		verifyKey interface{}

		options JwtOptions
	}

	JwtOptions struct {
		signingMethod         string
		privateKeyLocation    string
		publicKeyLocation     string
		bearerTokens          bool
		refreshTokenValidTime time.Duration
		authTokenValidTime    time.Duration
		authTokenName         string
		refreshTokenName      string
	}
)

func defaultOptions(options JwtOptions) JwtOptions {
	if options.refreshTokenValidTime <= 0 {
		options.refreshTokenValidTime = turboAuth.DefaultRefreshTokenValidTime
	}

	if options.authTokenValidTime <= 0 {
		options.authTokenValidTime = turboAuth.DefaultAuthTokenValidTime
	}

	if options.bearerTokens {
		if options.authTokenName == "" {
			options.authTokenName = turboAuth.DefaultBearerAuthTokenHeader
		}
		if options.refreshTokenName == "" {
			options.refreshTokenName = turboAuth.DefaultRefreshAuthTokenHeader
		}
	} else {
		if options.authTokenName == "" {
			options.authTokenName = turboAuth.DefaultCookieAuthTokenName
		}
		if options.refreshTokenName == "" {
			options.refreshTokenName = turboAuth.DefaultCookieRefreshTokenName
		}
	}
	return options
}

func (jwtAuth *JwtAuth) Apply(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		next.ServeHTTP(w, r)
	})
}

func CreateJwtAuthenticator(auth *JwtAuth, options JwtOptions) *JwtAuth {
	auth.options = defaultOptions(options)
	auth.options = options
	return auth
}

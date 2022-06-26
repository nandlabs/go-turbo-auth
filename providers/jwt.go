package providers

import (
	"net/http"
	"reflect"
	"time"

	turboAuth "github.com/nandlabs/turbo-auth"
	turboError "github.com/nandlabs/turbo-auth/errors"
)

type (
	JwtAuthConfig struct {
		SigningKey            string
		SigningMethod         string
		BearerTokens          bool
		RefreshTokenValidTime time.Duration
		AuthTokenValidTime    time.Duration
		AuthTokenName         string
		RefreshTokenName      string
	}
)

func defaultOptions(options JwtAuthConfig) JwtAuthConfig {
	if options.RefreshTokenValidTime <= 0 {
		options.RefreshTokenValidTime = turboAuth.DefaultRefreshTokenValidTime
	}

	if options.AuthTokenValidTime <= 0 {
		options.AuthTokenValidTime = turboAuth.DefaultAuthTokenValidTime
	}

	if options.BearerTokens {
		if options.AuthTokenName == "" {
			options.AuthTokenName = turboAuth.DefaultBearerAuthTokenHeader
		}
		if options.RefreshTokenName == "" {
			options.RefreshTokenName = turboAuth.DefaultRefreshAuthTokenHeader
		}
	} else {
		if options.AuthTokenName == "" {
			options.AuthTokenName = turboAuth.DefaultCookieAuthTokenName
		}
		if options.RefreshTokenName == "" {
			options.RefreshTokenName = turboAuth.DefaultCookieRefreshTokenName
		}
	}
	return options
}

func (authConfig *JwtAuthConfig) Apply(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		jwtErr := authConfig.handleRequest(w, r)
		var j turboError.JwtError

		if jwtErr != nil {
			_ = authConfig.NullifyTokens(w, r)
			if reflect.TypeOf(jwtErr) == reflect.TypeOf(&j) {

			}
			// send error
		}
		next.ServeHTTP(w, r)
	})
}

func CreateJwtAuthenticator(auth *JwtAuth, options JwtOptions) *JwtAuth {
	auth.options = defaultOptions(options)
	auth.options = options
	return auth
}

package providers

import (
	turboAuth "github.com/nandlabs/turbo-auth"
	turboError "github.com/nandlabs/turbo-auth/errors"
	"net/http"
	"reflect"
)

func defaultOptions(options *JwtAuthConfig) *JwtAuthConfig {
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

		jwtErr := authConfig.HandleRequest(w, r)
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

func CreateJwtAuthenticator(auth *JwtAuthConfig) *JwtAuthConfig {
	auth = defaultOptions(auth)
	return auth
}

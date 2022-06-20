package providers

import (
	"net/http"
	"reflect"
	"time"

	turboAuth "github.com/nandlabs/turbo-auth"
	"github.com/nandlabs/turbo-auth/errors"
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

		jwtErr := jwtAuth.handleRequest(w, r)
		var j errors.JwtError

		if jwtErr != nil {
			_ = jwtAuth.NullifyTokens(w, r)
			if reflect.TypeOf(jwtErr) == reflect.TypeOf(&j) {

			}
			// send error
		}
		next.ServeHTTP(w, r)
	})
}

func (jwtAuth *JwtAuth) handleRequest(w http.ResponseWriter, r *http.Request) *errors.JwtError {

	if r.Method == "OPTIONS" {
		logger.InfoF("Requested Method is OPTIONS")
		return nil
	}

	var c credentials
	if err := jwtAuth.fetchCredsFronRequest(r, &c); err != nil {
		return errors.NewJwtError(err, 500)
	}

	if err := c.validateAndUpdateCreds(); err != nil {
		return errors.NewJwtError(err, 500)
	}

	return nil
}

func (jwtAuth *JwtAuth) NullifyTokens(w http.ResponseWriter, r *http.Request) error {

}

func CreateJwtAuthenticator(auth *JwtAuth, options JwtOptions) *JwtAuth {
	auth.options = defaultOptions(options)
	auth.options = options
	return auth
}

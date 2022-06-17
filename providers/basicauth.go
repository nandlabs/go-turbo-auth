package providers

import (
	"encoding/base64"
	turboAuth "github.com/nandlabs/turbo-auth"
	"github.com/nandlabs/turbo-auth/errors"
	"github.com/nandlabs/turbo-auth/providers/basicauth"
	"go.nandlabs.io/l3"
	"net/http"
	"strings"
)

type (
	BasicAuthFilter struct {
		basicAuthProvider bool
		dbProvider        bool
		dbConfig          basicauth.DBConfig
		ldapProvider      bool
		ldapConfig        basicauth.LdapConfig
		Validator         BasicAuthValidator
	}

	// BasicAuthValidator expects username and password
	BasicAuthValidator func(string, string) (bool, error)
)

var (
	logger                       = l3.Get()
	DefaultBasicAuthFilterConfig = BasicAuthFilter{
		basicAuthProvider: true,
		dbProvider:        false,
		ldapProvider:      false,
	}
)

func (ba *BasicAuthFilter) Apply(next http.Handler) http.Handler {

	// check for providers
	if ba.dbProvider {
		return ba.dbConfig.Apply(next)
	}

	if ba.ldapProvider {
		return ba.ldapConfig.Apply(next)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic Auth Implementation
		if ba.Validator == nil {
			httpError := &errors.HttpError{
				StatusCode: http.StatusBadRequest,
				Message:    "Error : Basic auth filter requires a validator function \n",
			}
			httpError.GenerateError(w, r)
		}
		// perform pre-requisite checks
		auth := r.Header.Get(turboAuth.HeaderAuthorization)
		l := len(turboAuth.Basic)
		if len(auth) > l+1 && strings.EqualFold(auth[:l], turboAuth.Basic) {
			basicAuth, err := base64.StdEncoding.DecodeString(auth[l+1:])
			if err != nil {
				httpError := &errors.HttpError{
					StatusCode: http.StatusBadRequest,
					Message:    "Error decoding authorization token \n",
				}
				httpError.GenerateError(w, r)
			}
			logger.InfoF("basic token: %s", basicAuth)
			tokenUsername := strings.Split(string(basicAuth), ":")[0]
			tokenPassword := strings.Split(string(basicAuth), ":")[1]

			valid, err := ba.Validator(tokenUsername, tokenPassword)
			if err != nil {
				httpError := &errors.HttpError{
					StatusCode: http.StatusForbidden,
					Message:    "Invalid Token provided for the request \n",
				}
				httpError.GenerateError(w, r)
			} else if valid {
				next.ServeHTTP(w, r)
			}
		}
		// handle in case of authorization token not sent
		httpError := &errors.HttpError{
			StatusCode: http.StatusUnauthorized,
			Message:    "Incoming request cannot be authorized \n",
		}
		httpError.GenerateError(w, r)
	})
}

func CreateBasicAuthAuthenticator(fn BasicAuthValidator) BasicAuthFilter {
	filterConfig := DefaultBasicAuthFilterConfig
	filterConfig.Validator = fn
	return filterConfig
}

package providers

import (
	"encoding/base64"
	"go.nandlabs.io/l3"
	"go.nandlabs.io/turboauth"
	"net/http"
	"strings"
)

type (
	BasicAuthFilter struct {
		Validator BasicAuthValidator
	}

	httpError struct {
		statusCode int
		message    string
	}

	// BasicAuthValidator expects username and password
	BasicAuthValidator func(string, string) (bool, error)
)

var (
	logger                       = l3.Get()
	DefaultBasicAuthFilterConfig = BasicAuthFilter{}
)

func (ba *BasicAuthFilter) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic Auth Implementation
		if ba.Validator == nil {
			httpError := &httpError{
				statusCode: http.StatusBadRequest,
				message:    "Error : Basic auth filter requires a validator function \n",
			}
			httpError.generateError(w, r)
		}
		// perform pre-requisite checks
		auth := r.Header.Get(turboauth.HeaderAuthorization)
		l := len(turboauth.Basic)
		if len(auth) > l+1 && strings.EqualFold(auth[:l], turboauth.Basic) {
			basicAuth, err := base64.StdEncoding.DecodeString(auth[l+1:])
			if err != nil {
				httpError := &httpError{
					statusCode: http.StatusBadRequest,
					message:    "Error decoding authorization token \n",
				}
				httpError.generateError(w, r)
			}
			logger.InfoF("basic token: %s", basicAuth)
			tokenUsername := strings.Split(string(basicAuth), ":")[0]
			tokenPassword := strings.Split(string(basicAuth), ":")[1]

			valid, err := ba.Validator(tokenUsername, tokenPassword)
			if err != nil {
				httpError := &httpError{
					statusCode: http.StatusForbidden,
					message:    "Invalid Token provided for the request \n",
				}
				httpError.generateError(w, r)
			} else if valid {
				next.ServeHTTP(w, r)
			}
		}
		// handle in case of authorization token not sent
		httpError := &httpError{
			statusCode: http.StatusUnauthorized,
			message:    "Incoming request cannot be authorized \n",
		}
		httpError.generateError(w, r)
	})
}

func CreateBasicAuthAuthenticator(fn BasicAuthValidator) BasicAuthFilter {
	filterConfig := DefaultBasicAuthFilterConfig
	filterConfig.Validator = fn
	return filterConfig
}

func (httpError *httpError) generateError(w http.ResponseWriter, r *http.Request) {
	logger.ErrorF("Error occurred at endpoint: %s", r.URL.Path)
	logger.ErrorF("Error Message: %s", httpError.message)
	w.WriteHeader(httpError.statusCode)
	_, err := w.Write([]byte(httpError.message))
	if err != nil {
		return
	}
}

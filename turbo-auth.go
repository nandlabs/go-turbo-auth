package turbo_auth

import "net/http"

type Authenticator interface {
	Apply(handler http.Handler) http.Handler
}

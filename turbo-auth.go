package turboauth

import "net/http"

type Authenticator interface {
	Apply(handler http.Handler) http.Handler
}

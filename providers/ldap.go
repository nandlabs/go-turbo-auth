package providers

import (
	"github.com/nandlabs/turbo-auth/errors"
	"net/http"
)

type (
	LdapConfig struct {
	}
)

func (config *LdapConfig) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (LdapConfig{}) == *config {
			httpError := &errors.HttpError{
				StatusCode: http.StatusBadRequest,
				Message:    "Error : LDAP filter requires a LDAP Config \n",
			}
			httpError.GenerateError(w, r)
		}
	})
}

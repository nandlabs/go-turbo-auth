package basicauth

import (
	"github.com/nandlabs/turbo-auth/errors"
	"net/http"
)

type (
	DBConfig struct {
		driver string
	}
)

func (config *DBConfig) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (DBConfig{}) == *config {
			httpError := &errors.HttpError{
				StatusCode: http.StatusBadRequest,
				Message:    "Error : DB filter requires a DB Config \n",
			}
			httpError.GenerateError(w, r)
		}

	})
}

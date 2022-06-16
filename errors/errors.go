package errors

import (
	"go.nandlabs.io/l3"
	"net/http"
)

type (
	HttpError struct {
		StatusCode int
		Message    string
	}
)

var (
	logger = l3.Get()
)

func (httpError *HttpError) GenerateError(w http.ResponseWriter, r *http.Request) {
	logger.ErrorF("Error occurred at endpoint: %s", r.URL.Path)
	logger.ErrorF("Error Message: %s", httpError.Message)
	w.WriteHeader(httpError.StatusCode)
	_, err := w.Write([]byte(httpError.Message))
	if err != nil {
		return
	}
}

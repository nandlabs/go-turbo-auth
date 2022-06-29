package errors

import (
	"go.nandlabs.io/l3"
	"net/http"
	"reflect"
)

type (
	HttpError struct {
		StatusCode int
		Message    string
	}

	JwtError struct {
		Err  error
		Code int
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
	return
}

func NewJwtError(err interface{}, errCode int) *JwtError {
	var j JwtError
	if reflect.TypeOf(err) == reflect.TypeOf(&j) {
		return err.(*JwtError)
	}
	if err == nil {
		return nil
	}
	return &JwtError{
		Err:  err.(error),
		Code: errCode,
	}
}

func (err JwtError) Error() string {
	if err.Err != nil {
		return err.Err.Error()
	}
	return "Unknown Error Occurred"
}

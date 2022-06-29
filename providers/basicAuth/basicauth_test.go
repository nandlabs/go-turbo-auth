package basicAuth

/*import (
	turboAuth "go.nandlabs.io/turbo-auth"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func basicAuthFilter(username, password string) (bool, error) {
	if username == "username" && password == "password" {
		return true, nil
	}
	return false, nil
}

func TestCreateBasicAuthAuthenticator(t *testing.T) {
	var authConfig = CreateBasicAuthAuthenticator(basicAuthFilter)

	handler := func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "something failed", http.StatusInternalServerError)
	}
	responseHandler := authConfig.Apply(handler)

	var w *httptest.ResponseRecorder
	var r *http.Request

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(turboAuth.HeaderAuthorization, "Basic Nlcm5hbWU6cGFzc3dvcmQ=")

	responseHandler.ServeHTTP(w, r)
	if w.Result().StatusCode != http.StatusOK {
		t.Error("Auth Filter not working")
	}
}*/

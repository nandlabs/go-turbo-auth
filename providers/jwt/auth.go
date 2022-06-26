package jwt

import (
	"errors"
	turboError "github.com/nandlabs/turbo-auth/errors"
	"net/http"
	"strings"
	"time"
)

func (authConfig *providers.JwtAuthConfig) fetchCredsFromRequest(r *http.Request, creds *Credentials) *turboError.JwtError {
	authToken, refreshToken, err := jwtAuth.fetchTokensFromRequest(r)
	if err != nil {
		return turboError.NewJwtError(err, 500)
	}

	csrf, err := jwtAuth.fetchCsrfFromRequest(r)
	if err != nil {
		return turboError.NewJwtError(err, 500)
	}

	if err := jwtAuth.buildCredentials(authToken, refreshToken, csrf, creds); err != nil {
		return turboError.NewJwtError(err, 500)
	}
	return nil
}

func (authConfig *JwtAuthConfig) handleRequest(w http.ResponseWriter, r *http.Request) *turboError.JwtError {

	if r.Method == "OPTIONS" {
		logger.InfoF("Requested Method is OPTIONS")
		return nil
	}

	var c jwt.Credentials
	if err := authConfig.fetchCredsFromRequest(r, &c); err != nil {
		return turboError.NewJwtError(err, 500)
	}

	if err := c.ValidateAndUpdateCreds(); err != nil {
		return turboError.NewJwtError(err, 500)
	}

	return nil
}

func (authConfig *JwtAuthConfig) NullifyTokens(w http.ResponseWriter, r *http.Request) error {
	var c jwt.Credentials
	if err := jwtAuth.fetchCredsFromRequest(r, &c); err != nil {
		return turboError.NewJwtError("Error fetching credentials from request", 500)
	}

	if jwtAuth.options.bearerTokens {
		w.Header().Set(jwtAuth.options.authTokenName, "")
		w.Header().Set(jwtAuth.options.refreshTokenName, "")
	} else {
		authCookie := http.Cookie{
			Name:    jwtAuth.options.authTokenName,
			Value:   "",
			Expires: time.Now().Add(-1000 * time.Hour),
		}

		http.SetCookie(w, &authCookie)

		refreshCookie := http.Cookie{
			Name:    jwtAuth.options.refreshTokenName,
			Value:   "",
			Expires: time.Now().Add(-1000 * time.Hour),
		}

		http.SetCookie(w, &refreshCookie)
	}
	return nil
}

func (jwtAuth *JwtAuth) fetchTokensFromRequest(r *http.Request) (string, string, error) {
	if jwtAuth.options.bearerTokens {
		return r.Header.Get(jwtAuth.options.authTokenName), r.Header.Get(jwtAuth.options.refreshTokenName), nil
	}

	var (
		authCookieValue    string
		refreshCookieValue string
	)

	AuthCookie, err := r.Cookie(jwtAuth.options.authTokenName)
	if err == http.ErrNoCookie {
		return "", "", turboError.NewJwtError(errors.New("no auth cookie present"), 401)
	} else if err != nil {
		return "", "", turboError.NewJwtError(errors.New("internal server error"), 500)
	}

	RefreshCookie, err := r.Cookie(jwtAuth.options.refreshTokenName)
	if err != nil && err == http.ErrNoCookie {
		return "", "", turboError.NewJwtError(errors.New("internal server error"), 500)
	}

	if AuthCookie != nil {
		authCookieValue = AuthCookie.Value
	}
	if RefreshCookie != nil {
		refreshCookieValue = RefreshCookie.Value
	}

	return authCookieValue, refreshCookieValue, nil
}

func (jwtAuth *JwtAuth) fetchCsrfFromRequest(r *http.Request) (string, *turboError.JwtError) {
	csrfString := r.FormValue(jwtAuth.options.CSRFTokenName)
	if csrfString != "" {
		return csrfString, nil
	}

	csrfString = r.Header.Get(jwtAuth.options.CSRFTokenName)
	if csrfString != "" {
		return csrfString, nil
	}

	auth := r.Header.Get("Authorization")
	csrfString = strings.Split(auth, " ")[1]
	if csrfString == "" {
		return csrfString, turboError.NewJwtError(errors.New("no csrf string present"), 401)
	}
	return csrfString, nil
}

func (jwtAuth *JwtAuth) buildCredentials(authToken string, refreshToken string, csrf string, creds *jwt.Credentials) *turboError.JwtError {
	creds.CsrfString = csrf
	creds.Options.AuthTokenValidTime = jwtAuth.options.authTokenValidTime
	creds.Options.RefreshTokenValidTime = jwtAuth.options.refreshTokenValidTime
	creds.Options.SigningMethod = jwtAuth.options.signingMethod

	creds.AuthToken = creds.BuildTokenWithClaims(authToken, jwtAuth.verifyKey, jwtAuth.options.authTokenValidTime)

	if refreshToken != "" {
		creds.RefreshToken = creds.BuildTokenWithClaims(refreshToken, jwtAuth.verifyKey, jwtAuth.options.refreshTokenValidTime)
	}
	return nil
}

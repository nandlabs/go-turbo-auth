package jwt

import (
	"errors"
	turboError "github.com/nandlabs/turbo-auth/errors"
	"net/http"
	"strings"
	"time"
)

// HandleRequest fetch and validate incoming request token
func (authConfig *JwtAuthConfig) HandleRequest(w http.ResponseWriter, r *http.Request) *turboError.JwtError {

	if r.Method == "OPTIONS" {
		//logger.InfoF("Requested Method is OPTIONS")
		return nil
	}

	var c Credentials
	// fetch info from token
	if err := authConfig.fetchCredsFromRequest(r, &c); err != nil {
		return turboError.NewJwtError(err, 500)
	}

	// validate
	if err := c.ValidateAndUpdateCreds(); err != nil {
		return turboError.NewJwtError(err, 500)
	}

	return nil
}

func (authConfig *JwtAuthConfig) IssueNewToken(username string, duration time.Duration) (string, error) {
	payload, err := NewPayload(username, duration)
	if err != nil {
		return "", err
	}
	jwtToken := BuildTokenWithClaims(authConfig.SigningMethod, payload)
	token, err := jwtToken.SignedString([]byte(authConfig.SigningKey))
	return token, err
}

func (authConfig *JwtAuthConfig) fetchCredsFromRequest(r *http.Request, creds *Credentials) *turboError.JwtError {
	authToken, refreshToken, err := authConfig.fetchTokensFromRequest(r)
	if err != nil {
		return turboError.NewJwtError(err, 500)
	}

	csrf, err := authConfig.fetchCsrfFromRequest(r)
	if err != nil {
		return turboError.NewJwtError(err, 500)
	}

	if err := authConfig.buildCredentials(authToken, refreshToken, csrf, creds); err != nil {
		return turboError.NewJwtError(err, 500)
	}
	return nil
}

func (authConfig *JwtAuthConfig) NullifyTokens(w http.ResponseWriter, r *http.Request) error {
	var c Credentials
	if err := authConfig.fetchCredsFromRequest(r, &c); err != nil {
		return turboError.NewJwtError("Error fetching credentials from request", 500)
	}

	if authConfig.BearerTokens {
		w.Header().Set(authConfig.AuthTokenName, "")
		w.Header().Set(authConfig.RefreshTokenName, "")
	} else {
		authCookie := http.Cookie{
			Name:    authConfig.AuthTokenName,
			Value:   "",
			Expires: time.Now().Add(-1000 * time.Hour),
		}

		http.SetCookie(w, &authCookie)

		refreshCookie := http.Cookie{
			Name:    authConfig.RefreshTokenName,
			Value:   "",
			Expires: time.Now().Add(-1000 * time.Hour),
		}

		http.SetCookie(w, &refreshCookie)
	}
	return nil
}

func (authConfig *JwtAuthConfig) fetchTokensFromRequest(r *http.Request) (string, string, error) {
	if authConfig.BearerTokens {
		return r.Header.Get(authConfig.AuthTokenName), r.Header.Get(authConfig.RefreshTokenName), nil
	}

	var (
		authCookieValue    string
		refreshCookieValue string
	)

	AuthCookie, err := r.Cookie(authConfig.AuthTokenName)
	if err == http.ErrNoCookie {
		return "", "", turboError.NewJwtError(errors.New("no auth cookie present"), 401)
	} else if err != nil {
		return "", "", turboError.NewJwtError(errors.New("internal server error"), 500)
	}

	RefreshCookie, err := r.Cookie(authConfig.RefreshTokenName)
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

func (authConfig *JwtAuthConfig) fetchCsrfFromRequest(r *http.Request) (string, *turboError.JwtError) {
	csrfString := r.FormValue(authConfig.CSRFTokenName)
	if csrfString != "" {
		return csrfString, nil
	}

	csrfString = r.Header.Get(authConfig.CSRFTokenName)
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

func (authConfig *JwtAuthConfig) buildCredentials(authToken string, refreshToken string, csrf string, creds *Credentials) *turboError.JwtError {
	creds.CsrfString = csrf
	creds.Options.AuthTokenValidTime = authConfig.AuthTokenValidTime
	creds.Options.RefreshTokenValidTime = authConfig.RefreshTokenValidTime
	creds.Options.SigningMethod = authConfig.SigningMethod

	creds.AuthToken = creds.BuildTokenWithClaims(authToken, authConfig.VerifyKey, authConfig.AuthTokenValidTime)

	if refreshToken != "" {
		creds.RefreshToken = creds.BuildTokenWithClaims(refreshToken, authConfig.verifyKey, authConfig.RefreshTokenValidTime)
	}
	return nil
}

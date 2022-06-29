package jwt

import "time"

type (
	JwtAuthConfig struct {
		SigningKey            string
		SigningMethod         string
		BearerTokens          bool
		RefreshTokenValidTime time.Duration
		AuthTokenValidTime    time.Duration
		AuthTokenName         string
		RefreshTokenName      string
	}

	Credentials struct {
		CsrfString string

		AuthToken    *jwtToken
		RefreshToken *jwtToken

		Options credentialOptions
	}

	credentialOptions struct {
		AuthTokenValidTime    time.Duration
		RefreshTokenValidTime time.Duration
		SigningMethod         string
	}

	jwtToken struct {
	}
)

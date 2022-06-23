package jwt

import (
	"time"
)

type (
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

func (creds *Credentials) ValidateAndUpdateCreds() error {
	return nil
}

func (creds *Credentials) BuildTokenWithClaims(token string, verifyKey interface{}, validTime time.Duration) *jwtToken {
	return nil
}

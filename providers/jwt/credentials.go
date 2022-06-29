package jwt

import (
	"github.com/golang-jwt/jwt/v4"
	"time"
)

func (creds *Credentials) ValidateAndUpdateCreds() error {
	return nil
}

func (creds *Credentials) BuildTokenWithClaims(token string, verifyKey interface{}, validTime time.Duration) *jwtToken {
	return nil
}

func BuildTokenWithClaims(signingMethod string, payload *Payload) *jwt.Token {
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	return jwtToken
}

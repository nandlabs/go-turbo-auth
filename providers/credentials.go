package providers

import (
	"time"
)

func (creds *Credentials) ValidateAndUpdateCreds() error {
	return nil
}

func (creds *Credentials) BuildTokenWithClaims(token string, verifyKey interface{}, validTime time.Duration) *jwtToken {
	return nil
}

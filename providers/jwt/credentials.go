package jwt

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"time"
)

// currently working only for HMAC algo
func (creds *Credentials) ValidateToken(signKey string) error {
	if creds.AuthToken == "" {
		return errors.New("empty auth token")
	}
	token, err := jwt.Parse(creds.AuthToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(signKey), nil
	})
	if err != nil {
		return err
	}
	if token.Valid {
		fmt.Println("token validated")
	} else {
		return errors.New("invalid token passed")
	}
	return nil
}

func (creds *Credentials) BuildTokenWithClaims(token string, verifyKey interface{}, validTime time.Duration) *jwtToken {
	return nil
}

func BuildTokenWithClaims(signingMethod string, payload *Payload) (*jwt.Token, error) {
	var jwtToken *jwt.Token
	if signingMethod == "HS256" {
		jwtToken = jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	} else if signingMethod == "RS256" {
		jwtToken = jwt.NewWithClaims(jwt.SigningMethodRS256, payload)
	} else {
		return nil, errors.New("singing method not supported")
	}
	return jwtToken, nil
}

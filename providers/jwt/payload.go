package jwt

import (
	"errors"
	"github.com/google/uuid"
	"time"
)

type Payload struct {
	ID        uuid.UUID
	Username  string
	IssuedAt  time.Time
	ExpiredAt time.Time
}

func NewPayload(username string, duration time.Duration) (*Payload, error) {
	token, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	if username == "" {
		return nil, errors.New("username is required to generate payload")
	}
	if duration == 0 {
		return nil, errors.New("duration cannot be 0")
	}
	payload := &Payload{
		ID:        token,
		Username:  username,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}
	return payload, nil
}

func (payload *Payload) Valid() error {
	if time.Now().After(payload.ExpiredAt) {
		return errors.New("token has expired")
	}
	return nil
}

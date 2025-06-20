package internal

import (
	"crypto/rand"
	"encoding/base64"
)

func FreshChallenge() (*AuthChallenge, []byte, error) {
	challenge, err := random(64)
	if err != nil {
		return nil, nil, err
	}

	token, err := random(64)
	if err != nil {
		return nil, nil, err
	}

	return &AuthChallenge{
		Token:     base64.StdEncoding.EncodeToString(token),
		Challenge: base64.StdEncoding.EncodeToString(challenge),
	}, challenge, nil
}

func random(n int) ([]byte, error) {
	b := make([]byte, n)

	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

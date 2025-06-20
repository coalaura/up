package internal

import (
	"time"

	"golang.org/x/crypto/ssh"
)

type ChallengeEntry struct {
	Challenge []byte
	PublicKey ssh.PublicKey
	Expires   time.Time
}

type SessionEntry struct {
	PublicKey ssh.PublicKey
	Expires   time.Time
}

type AuthRequest struct {
	Public string `json:"public"`
}

type AuthChallenge struct {
	Token     string `json:"token"`
	Challenge string `json:"challenge"`
}

type AuthResponse struct {
	Token     string `json:"token"`
	Public    string `json:"public"`
	Format    string `json:"format"`
	Signature string `json:"signature"`
}

type AuthResult struct {
	Token string `json:"token"`
}

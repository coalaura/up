package main

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func GetAuthorizedKeysPath() (string, error) {
	home, err := os.UserHomeDir()

	if err != nil {
		return "", err
	}

	return filepath.Join(home, ".ssh", "authorized_keys"), nil
}

func LoadAuthorizedKeys() (map[string]ssh.PublicKey, error) {
	path, err := GetAuthorizedKeysPath()
	if err != nil {
		return nil, err
	}

	keys := make(map[string]ssh.PublicKey)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for len(data) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, err
		}

		keys[string(pubKey.Marshal())] = pubKey

		data = rest
	}

	return keys, nil
}

func RandomToken(n int) (string, error) {
	b := make([]byte, n)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

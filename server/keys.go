package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
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

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("authorized_keys file is missing")
		} else if os.IsPermission(err) {
			return nil, errors.New("no permissions to read authorized_keys file")
		}

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

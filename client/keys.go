package main

import (
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

var DefaultKeyNames = []string{
	"id_ed25519",
	"id_ecdsa",
	"id_rsa",
}

func FindPrivateKey() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	for _, name := range DefaultKeyNames {
		path := filepath.Join(home, ".ssh", name)

		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}

			return "", err
		}

		return path, nil
	}

	return "", nil
}

func LoadPrivateKey(path string) (ssh.Signer, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

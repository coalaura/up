package main

import (
	"os"
	"path/filepath"

	"github.com/kevinburke/ssh_config"
)

func SSHConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, ".ssh", "config"), nil
}

func LoadSSHConfig() (*ssh_config.Config, error) {
	path, err := SSHConfigPath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return new(ssh_config.Config), nil
	}

	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	cfg, err := ssh_config.Decode(file)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

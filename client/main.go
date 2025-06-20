package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coalaura/logger"
	"github.com/urfave/cli/v3"
)

var (
	Version = "dev"

	log = logger.New().DetectTerminal().WithOptions(logger.Options{
		NoTime:  true,
		NoLevel: true,
	})
)

func main() {
	app := &cli.Command{
		Name:      "up",
		Usage:     "UP client",
		Version:   Version,
		ArgsUsage: "<file> <host>",
		UsageText: "up [options] <file> <host>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "identity",
				Aliases: []string{"i"},
				Usage:   "private key file for authentication",
			},
		},
		Action:                 run,
		EnableShellCompletion:  true,
		UseShortOptionHandling: true,
		Suggest:                true,
	}

	err := app.Run(context.Background(), os.Args)
	log.MustPanic(err)
}

func run(_ context.Context, cmd *cli.Command) error {
	log.Println("Loading certificate store...")

	store, err := LoadCertificateStore()
	if err != nil {
		return fmt.Errorf("failed to load certificate store: %v", err)
	}

	client := NewPinnedClient(store)

	path := cmd.String("key")
	if path == "" {
		return errors.New("missing private key")
	}

	kPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get key path: %v", err)
	}

	log.Printf("Using key: %s\n", kPath)

	path = cmd.String("file")
	if path == "" {
		return errors.New("missing file")
	}

	fPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get file path: %v", err)
	}

	log.Printf("Using file: %s\n", fPath)

	file, err := os.OpenFile(fPath, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}

	defer file.Close()

	target := cmd.String("target")
	if target == "" {
		return errors.New("missing target")
	}

	target = fmt.Sprintf("https://%s", target)

	log.Printf("Using target: %s\n", target)

	log.Printf("Loading key...")

	private, err := LoadPrivateKey(kPath)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}

	public := base64.StdEncoding.EncodeToString(private.PublicKey().Marshal())

	log.Println("Requesting challenge...")

	challenge, err := RequestChallenge(client, target, public)
	if err != nil {
		return err
	}

	log.Println("Completing challenge...")

	response, err := CompleteChallenge(client, target, public, private, challenge)
	if err != nil {
		return err
	}

	return SendFile(client, target, response.Token, file)
}

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v3"
)

var Version = "dev"

func main() {
	app := &cli.Command{
		Name:    "up",
		Usage:   "UP client",
		Version: Version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "key",
				Aliases: []string{"k"},
				Usage:   "private key file for authentication",
			},
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				Usage:   "file to upload",
			},
			&cli.StringFlag{
				Name:    "target",
				Aliases: []string{"t"},
				Usage:   "target to upload to",
			},
		},
		Action:                 run,
		EnableShellCompletion:  true,
		UseShortOptionHandling: true,
		Suggest:                true,
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Printf("fatal: %v\n", err)

		os.Exit(1)
	}
}

func run(_ context.Context, cmd *cli.Command) error {
	path := cmd.String("key")
	if path == "" {
		return errors.New("missing private key")
	}

	kPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get key path: %v", err)
	}

	log.Printf("using key %s", kPath)

	path = cmd.String("file")
	if path == "" {
		return errors.New("missing file")
	}

	fPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get file path: %v", err)
	}

	log.Printf("using file %s", fPath)

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

	log.Printf("using target %s", target)

	log.Printf("loading key")

	private, err := LoadPrivateKey(kPath)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}

	public := base64.StdEncoding.EncodeToString(private.PublicKey().Marshal())

	log.Println("requesting challenge")

	challenge, err := RequestChallenge(target, public)
	if err != nil {
		return err
	}

	log.Println("completing challenge")

	response, err := CompleteChallenge(target, public, private, challenge)
	if err != nil {
		return err
	}

	log.Println("uploading file")

	return SendFile(target, response.Token, file)
}

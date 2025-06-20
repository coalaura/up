package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coalaura/logger"
	"github.com/urfave/cli/v3"
)

var log *logger.Logger

func Before(ctx context.Context, _ *cli.Command) (context.Context, error) {
	log = logger.New().DetectTerminal().WithOptions(logger.Options{
		NoTime:  true,
		NoLevel: true,
	})

	return ctx, nil
}

func Run(_ context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	if len(args) != 2 {
		return errors.New("Usage: up [options] <file> <host>")
	}

	fileArg := args[0]
	hostArg := args[1]

	path, err := filepath.Abs(fileArg)
	if err != nil {
		return fmt.Errorf("failed to get file path: %v", err)
	}

	log.Printf("Using file: %s\n", path)

	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}

	defer file.Close()

	cfg, err := LoadSSHConfig()
	if err != nil {
		return fmt.Errorf("failed to load SSH config: %v", err)
	}

	var (
		port     string
		hostname = hostArg
		identity = cmd.String("identity")
	)

	if index := strings.Index(hostArg, ":"); index != -1 {
		hostname = hostname[:index]
		port = hostArg[index+1:]
	}

	if identity == "" {
		if found, _ := cfg.Get(hostname, "IdentityFile"); found != "" {
			identity = found
		} else {
			identity, err = FindPrivateKey()
			if err != nil {
				return err
			}
		}
	}

	if found, _ := cfg.Get(hostname, "HostName"); found != "" {
		hostname, err = StripPort(found)
		if err != nil {
			return err
		}
	}

	if hostname == "" {
		return errors.New("missing or invalid host")
	}

	if port != "" {
		hostname += ":" + port
	}

	log.Printf("Using host: %s\n", hostname)

	if identity == "" {
		return errors.New("missing or invalid identity file")
	}

	path, err = filepath.Abs(identity)
	if err != nil {
		return fmt.Errorf("failed to get identity file path: %v", err)
	}

	log.Printf("Using identity file: %s\n", path)

	log.Println("Loading key...")

	private, err := LoadPrivateKey(path)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}

	public := base64.StdEncoding.EncodeToString(private.PublicKey().Marshal())

	log.Println("Loading certificate store...")

	store, err := LoadCertificateStore()
	if err != nil {
		return fmt.Errorf("failed to load certificate store: %v", err)
	}

	useHttp3 := cmd.Bool("http3")

	if useHttp3 {
		log.Println("Using http3 over udp")
	} else {
		log.Println("Using http2 over tcp")
	}

	if err = PreFetchServerCertificate(store, hostname, useHttp3); err != nil {
		return err
	}

	client := NewPinnedClient(store, useHttp3)

	log.Println("Requesting challenge...")

	challenge, err := RequestChallenge(client, hostname, public)
	if err != nil {
		return err
	}

	log.Println("Completing challenge...")

	response, err := CompleteChallenge(client, hostname, public, private, challenge)
	if err != nil {
		return err
	}

	return SendFile(client, hostname, response.Token, file)
}

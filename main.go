package main

import (
	"context"
	"fmt"
	"os"

	"github.com/coalaura/up/client"
	"github.com/coalaura/up/server"
	"github.com/urfave/cli/v3"
)

var Version = "dev"

func main() {
	app := &cli.Command{
		Name:        "up",
		Description: "fast, drop-in file transfer tool using HTTPS",
		UsageText:   "up <command> [command options]",
		Version:     Version,
		Commands: []*cli.Command{
			{
				Name:      "send",
				Usage:     "send a file to an up server",
				Version:   Version,
				ArgsUsage: "<file> <host>",
				UsageText: "up send [options] <file> <host>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "identity",
						Aliases: []string{"i"},
						Usage:   "private key file for authentication",
					},
				},
				Before: client.Before,
				Action: client.Run,
			},
			{
				Name:  "receive",
				Usage: "receive files from up clients",
				Flags: []cli.Flag{
					&cli.UintFlag{
						Name:    "port",
						Aliases: []string{"p"},
						Usage:   "custom port",
						Value:   7966,
					},
				},
				Before: server.Before,
				Action: server.Run,
			},
		},
		EnableShellCompletion:  true,
		UseShortOptionHandling: true,
		Suggest:                true,
	}

	err := app.Run(context.Background(), os.Args)
	if err != nil {
		fmt.Printf("error: %s", err)
		os.Exit(1)
	}
}

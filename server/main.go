package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/coalaura/logger"
	"github.com/coalaura/up/internal"
	"github.com/go-chi/chi/v5"
	"github.com/patrickmn/go-cache"
	"github.com/urfave/cli/v3"
)

const (
	// Max amount of parallel sessions/challenges per client
	MaxClientParallel = 8

	// Max amount of parallel sessions/challenges overall
	MaxGlobalParallel = MaxClientParallel * 8
)

var (
	Version = "dev"
	log     = logger.New().DetectTerminal().WithOptions(logger.Options{
		NoLevel: true,
	})

	challenges = cache.New(10*time.Second, time.Minute)
	sessions   = cache.New(10*time.Second, time.Minute)
	rates      = NewRateLimiter()
)

func init() {
	challenges.OnEvicted(func(_ string, entry interface{}) {
		challenge := entry.(internal.ChallengeEntry)

		rates.Dec(challenge.Client)
	})

	sessions.OnEvicted(func(_ string, entry interface{}) {
		session := entry.(internal.SessionEntry)

		rates.Dec(session.Client)
	})
}

func main() {
	app := &cli.Command{
		Name:    "up",
		Usage:   "up server",
		Version: Version,
		Flags: []cli.Flag{
			&cli.UintFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Usage:   "custom port",
				Value:   7966,
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
	log.Printf("up server %s\n", Version)

	port := cmd.Uint("port")
	if port <= 0 || port > 65534 {
		port = 7966
	}

	authorized, err := LoadAuthorizedKeys()
	log.MustPanic(err)

	err = EnsureCertificate("cert.pem", "key.pem")
	log.MustPanic(err)

	r := chi.NewRouter()

	r.Post("/request", func(w http.ResponseWriter, r *http.Request) {
		HandleChallengeRequest(w, r, authorized)
	})

	r.Post("/complete", func(w http.ResponseWriter, r *http.Request) {
		HandleCompleteRequest(w, r, authorized)
	})

	r.Post("/receive", HandleReceiveRequest)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("Server listening on :%d\n", port)

	return srv.ListenAndServeTLS("cert.pem", "key.pem")
}

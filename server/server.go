package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
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
	log        *logger.Logger
	rates      *RateLimiter
	challenges *cache.Cache
	sessions   *cache.Cache
)

func Before(ctx context.Context, _ *cli.Command) (context.Context, error) {
	log = logger.New().DetectTerminal().WithOptions(logger.Options{
		NoLevel: true,
	})

	rates = NewRateLimiter()

	challenges = cache.New(10*time.Second, time.Minute)
	challenges.OnEvicted(func(_ string, entry interface{}) {
		challenge := entry.(internal.ChallengeEntry)

		rates.Dec(challenge.Client)
	})

	sessions = cache.New(10*time.Second, time.Minute)
	sessions.OnEvicted(func(_ string, entry interface{}) {
		session := entry.(internal.SessionEntry)

		rates.Dec(session.Client)
	})

	return ctx, nil
}

func Run(_ context.Context, cmd *cli.Command) error {
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

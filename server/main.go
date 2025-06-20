package main

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/coalaura/logger"
	"github.com/coalaura/up/internal"
	"github.com/go-chi/chi/v5"
	"github.com/patrickmn/go-cache"
)

const MaxParallel = 8

var (
	log = logger.New().DetectTerminal().WithOptions(logger.Options{
		NoLevel: true,
	})

	challenges = cache.New(10*time.Second, time.Minute)
	sessions   = cache.New(10*time.Second, time.Minute)
	rates      = NewRateLimiter()
)

func main() {
	challenges.OnEvicted(func(_ string, entry interface{}) {
		challenge := entry.(internal.ChallengeEntry)

		rates.Dec(challenge.Client)
	})

	sessions.OnEvicted(func(_ string, entry interface{}) {
		session := entry.(internal.SessionEntry)

		rates.Dec(session.Client)
	})

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
		Addr:    ":7966",
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Println("Server listening on :7966")
	srv.ListenAndServeTLS("cert.pem", "key.pem")
}

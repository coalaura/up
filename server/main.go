package main

import (
	"net/http"
	"time"

	"github.com/coalaura/logger"
	"github.com/go-chi/chi/v5"
	"github.com/patrickmn/go-cache"
)

var (
	log = logger.New().DetectTerminal().WithOptions(logger.Options{
		NoLevel: true,
	})

	challenges = cache.New(10*time.Second, time.Minute)
	sessions   = cache.New(10*time.Second, time.Minute)
)

func main() {
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

	log.Println("Listening on :7966")
	http.ListenAndServeTLS(":7966", "cert.pem", "key.pem", r)
}

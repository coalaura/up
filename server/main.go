package main

import (
	"net/http"
	"sync"

	"github.com/coalaura/logger"
	"github.com/go-chi/chi/v5"
)

var (
	log = logger.New().WithOptions(logger.Options{
		NoLevel: true,
	})

	challenges sync.Map
	sessions   sync.Map
)

func main() {
	authorized, err := LoadAuthorizedKeys()
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
	http.ListenAndServe(":7966", r)
}

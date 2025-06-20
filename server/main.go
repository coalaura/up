package main

import (
	"sync"

	"github.com/coalaura/logger"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
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

	r := router.New()

	r.POST("/request", func(ctx *fasthttp.RequestCtx) {
		HandleChallengeRequest(ctx, authorized)
	})

	r.POST("/complete", func(ctx *fasthttp.RequestCtx) {
		HandleCompleteRequest(ctx, authorized)
	})

	r.POST("/receive", HandleReceiveRequest)

	log.Println("Listening on :7966")
	fasthttp.ListenAndServe(":7966", r.Handler)
}

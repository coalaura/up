package server

import (
	"sync"
	"sync/atomic"
)

type RateLimiter struct {
	sync.Map
	total atomic.Uint32
}

const MinusOne uint32 = ^uint32(0)

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{}
}

func (rl *RateLimiter) Get(key string) *atomic.Uint32 {
	val, ok := rl.Map.Load(key)
	if ok {
		return val.(*atomic.Uint32)
	}

	actual, _ := rl.Map.LoadOrStore(key, &atomic.Uint32{})

	return actual.(*atomic.Uint32)
}

func (rl *RateLimiter) Inc(key string) (uint32, func(), func()) {
	if rl.total.Add(1) > MaxGlobalParallel {
		rl.total.Add(MinusOne)

		return 0, nil, nil
	}

	val := rl.Get(key)
	new := val.Add(1)

	var done uint32

	pass := func() {
		atomic.CompareAndSwapUint32(&done, 0, 1)
	}

	fail := func() {
		if !atomic.CompareAndSwapUint32(&done, 0, 1) {
			return
		}

		rl.total.Add(MinusOne)

		if val.Add(MinusOne) == 0 {
			// potential race, but ok
			rl.Map.Delete(key)
		}
	}

	return new, pass, fail
}

func (rl *RateLimiter) Dec(key string) uint32 {
	rl.total.Add(MinusOne)

	val := rl.Get(key)

	return val.Add(MinusOne)
}

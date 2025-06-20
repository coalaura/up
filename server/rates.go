package main

import (
	"sync"
	"sync/atomic"
)

type RateLimiter struct {
	sync.Map
}

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

		val.Add(^uint32(0))
	}

	return new, pass, fail
}

func (rl *RateLimiter) Dec(key string) uint32 {
	val := rl.Get(key)

	return val.Add(^uint32(0))
}

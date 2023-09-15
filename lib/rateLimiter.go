package lib

import (
	"net/http"
	"sync"
	"time"
)

type RateLimiter struct {
	WindowDuration time.Duration
	Limits         map[string]int
	Requests       map[string][]time.Time
	Mutex          sync.Mutex
}

func NewRateLimiter(window time.Duration) *RateLimiter {
	return &RateLimiter{
		WindowDuration: window,
		Limits: map[string]int{
			"api":  3000, // 300 requests per minute for API endpoints
			"auth": 100,  // 10 requests per minute for authentication endpoints
		},
		Requests: make(map[string][]time.Time),
	}
}

func (rl *RateLimiter) Wrap(limitType string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		remoteIP := r.RemoteAddr

		rl.Mutex.Lock()
		defer rl.Mutex.Unlock()

		// Clear expired request records
		now := time.Now()
		validRequests := rl.Requests[remoteIP][:0]
		for _, t := range rl.Requests[remoteIP] {
			if now.Sub(t) <= rl.WindowDuration {
				validRequests = append(validRequests, t)
			}
		}
		rl.Requests[remoteIP] = validRequests

		limit := rl.Limits[limitType]
		if len(rl.Requests[remoteIP]) >= limit {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		rl.Requests[remoteIP] = append(rl.Requests[remoteIP], time.Now())

		next(w, r)
	}
}

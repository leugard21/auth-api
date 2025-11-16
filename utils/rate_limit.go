package utils

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type rateLimiter struct {
	mu          sync.Mutex
	requests    map[string]*rateEntry
	maxRequests int
	window      time.Duration
}

type rateEntry struct {
	count     int
	windowEnd time.Time
}

func newRateLimiter(maxRequests int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		requests:    make(map[string]*rateEntry),
		maxRequests: maxRequests,
		window:      window,
	}
}

func (rl *rateLimiter) allow(key string) bool {
	now := time.Now().UTC()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.requests[key]
	if !exists || now.After(entry.windowEnd) {
		rl.requests[key] = &rateEntry{
			count:     1,
			windowEnd: now.Add(rl.window),
		}
		return true
	}

	if entry.count >= rl.maxRequests {
		return false
	}

	entry.count++
	return true
}

func RateLimit(maxRequests int, window time.Duration) func(http.Handler) http.Handler {
	rl := newRateLimiter(maxRequests, window)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIPFromRequest(r)
			key := ip + "|" + r.URL.Path

			if !rl.allow(key) {
				WriteError(w, http.StatusTooManyRequests, http.ErrHandlerTimeout)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

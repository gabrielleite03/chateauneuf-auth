package transporthttp

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimiter limits requests per client IP.
type RateLimiter struct {
	mu     sync.Mutex
	window time.Duration
	limit  int
	keys   map[string][]time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if limit <= 0 {
		limit = 20
	}
	if window <= 0 {
		window = time.Minute
	}
	return &RateLimiter{limit: limit, window: window, keys: make(map[string][]time.Time)}
}

func (rl *RateLimiter) Allow(key string) bool {
	if key == "" {
		return false
	}
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	entries := rl.keys[key]
	filtered := entries[:0]
	for _, ts := range entries {
		if now.Sub(ts) < rl.window {
			filtered = append(filtered, ts)
		}
	}
	if len(filtered) >= rl.limit {
		rl.keys[key] = filtered
		return false
	}
	filtered = append(filtered, now)
	rl.keys[key] = filtered
	return true
}

func RateLimitMiddleware(limit int, window time.Duration) func(http.Handler) http.Handler {
	limiter := NewRateLimiter(limit, window)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if !limiter.Allow(ip) {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if host, _, err := net.SplitHostPort(forwarded); err == nil {
			return host
		}
		return forwarded
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

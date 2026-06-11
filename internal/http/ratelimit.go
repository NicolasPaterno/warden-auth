package http

import (
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-redis/redis_rate/v10"
)

func clientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if first, _, found := strings.Cut(fwd, ","); found {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(fwd)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func allow(w http.ResponseWriter, r *http.Request, limiter *redis_rate.Limiter, key string, limit redis_rate.Limit) bool {
	res, err := limiter.Allow(r.Context(), key, limit)
	if err != nil {
		slog.ErrorContext(r.Context(), "rate limiter unavailable", "error", err, "key", key)
		return true
	}

	w.Header().Set("RateLimit-Limit", strconv.Itoa(limit.Burst))
	w.Header().Set("RateLimit-Remaining", strconv.Itoa(res.Remaining))
	w.Header().Set("RateLimit-Reset", strconv.Itoa(int(res.ResetAfter.Seconds())))

	if res.Allowed == 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(res.RetryAfter.Seconds())))
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return false
	}
	return true
}

func rateLimitByIP(limiter *redis_rate.Limiter, name string, limit redis_rate.Limit) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := name + ":ip:" + clientIP(r)
			if !allow(w, r, limiter, key, limit) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/NicolasPaterno/warden-auth"
	"github.com/go-redis/redis_rate/v10"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		realIP     string
		forwarded  string
		remoteAddr string
		want       string
	}{
		{"prefers X-Real-IP", "203.0.113.5", "198.51.100.1, 10.0.0.1", "10.0.0.9:1234", "203.0.113.5"},
		{"first hop of X-Forwarded-For", "", "198.51.100.1, 10.0.0.1", "10.0.0.9:1234", "198.51.100.1"},
		{"single X-Forwarded-For", "", "198.51.100.7", "10.0.0.9:1234", "198.51.100.7"},
		{"falls back to RemoteAddr host", "", "", "10.0.0.9:1234", "10.0.0.9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.realIP != "" {
				r.Header.Set("X-Real-IP", tc.realIP)
			}
			if tc.forwarded != "" {
				r.Header.Set("X-Forwarded-For", tc.forwarded)
			}
			if got := clientIP(r); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRateLimitByIP(t *testing.T) {
	limiter := newTestLimiter(t)
	var served int
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		w.WriteHeader(http.StatusOK)
	})
	h := rateLimitByIP(limiter, "test", redis_rate.PerMinute(2))(next)

	send := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/login", nil)
		r.Header.Set("X-Real-IP", "203.0.113.5")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	first := send()
	if first.Code != http.StatusOK {
		t.Fatalf("request 1 status = %d, want 200", first.Code)
	}
	if first.Header().Get("RateLimit-Limit") != "2" {
		t.Fatalf("RateLimit-Limit = %q, want 2", first.Header().Get("RateLimit-Limit"))
	}
	if first.Header().Get("RateLimit-Remaining") != "1" {
		t.Fatalf("RateLimit-Remaining = %q, want 1", first.Header().Get("RateLimit-Remaining"))
	}

	send()
	third := send()
	if third.Code != http.StatusTooManyRequests {
		t.Fatalf("request 3 status = %d, want 429", third.Code)
	}
	if third.Header().Get("Retry-After") == "" {
		t.Fatal("429 response missing Retry-After header")
	}
	if served != 2 {
		t.Fatalf("next handler served %d times, want 2", served)
	}
}

func TestRateLimitByIPIsolatesDifferentIPs(t *testing.T) {
	limiter := newTestLimiter(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := rateLimitByIP(limiter, "test", redis_rate.PerMinute(1))(next)

	send := func(ip string) int {
		r := httptest.NewRequest(http.MethodPost, "/login", nil)
		r.Header.Set("X-Real-IP", ip)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}

	if code := send("203.0.113.5"); code != http.StatusOK {
		t.Fatalf("ip A request 1 = %d, want 200", code)
	}
	if code := send("203.0.113.5"); code != http.StatusTooManyRequests {
		t.Fatalf("ip A request 2 = %d, want 429", code)
	}
	if code := send("198.51.100.9"); code != http.StatusOK {
		t.Fatalf("ip B request 1 = %d, want 200 (must not share ip A budget)", code)
	}
}

func TestLoginPerEmailRateLimit(t *testing.T) {
	svc := &fakeAuthService{loginErr: auth.ErrUnauthorized}
	h := newTestRouter(t, svc)

	body := `{"email":"victim@b.com","password":"guess"}`
	for i := 1; i <= 5; i++ {
		rec := doRequest(t, h, http.MethodPost, "/login", body)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i, rec.Code)
		}
	}

	rec := doRequest(t, h, http.MethodPost, "/login", body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 6 status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 response missing Retry-After header")
	}
}

package authn

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/NicolasPaterno/warden-auth"
	"github.com/golang-jwt/jwt/v5"
)

func tokenEndpoint(t *testing.T, tokenHits, exchangeHits *atomic.Int64, lastSubjectToken *string) *httptest.Server {
	t.Helper()
	key := testKey(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenHits.Add(1)
		c := baseClaims()
		c.Subject = "brain"
		c.Scope = "service"
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(15 * time.Minute))
		writeToken(w, signRS256(t, key, testKID, c))
	})
	mux.HandleFunc("/token/exchange", func(w http.ResponseWriter, r *http.Request) {
		exchangeHits.Add(1)
		body, _ := io.ReadAll(r.Body)
		var req struct {
			SubjectToken string `json:"subject_token"`
		}
		_ = json.Unmarshal(body, &req)
		if lastSubjectToken != nil {
			*lastSubjectToken = req.SubjectToken
		}
		c := baseClaims()
		c.Act = &auth.Actor{Subject: "brain"}
		writeToken(w, signRS256(t, key, testKID, c))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeToken(w http.ResponseWriter, token string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"access_token": token, "token_type": "Bearer"})
}

func TestTokenSourceCachesClientCredentials(t *testing.T) {
	var tokenHits, exchangeHits atomic.Int64
	srv := tokenEndpoint(t, &tokenHits, &exchangeHits, nil)
	src := NewTokenSource(srv.URL, "brain", "s3cret", testAudience)

	var first string
	for i := 0; i < 3; i++ {
		tok, err := src.Token(t.Context())
		if err != nil {
			t.Fatalf("Token %d: %v", i, err)
		}
		if i == 0 {
			first = tok
		} else if tok != first {
			t.Fatal("Token returned a different value despite valid cache")
		}
	}
	if got := tokenHits.Load(); got != 1 {
		t.Fatalf("token endpoint called %d times, want 1 (should cache until exp)", got)
	}
}

func TestTokenSourceExchangeForwardsSubject(t *testing.T) {
	var tokenHits, exchangeHits atomic.Int64
	var lastSubject string
	srv := tokenEndpoint(t, &tokenHits, &exchangeHits, &lastSubject)
	src := NewTokenSource(srv.URL, "brain", "s3cret", testAudience)

	tok, err := src.Exchange(t.Context(), "user-access-token")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok == "" {
		t.Fatal("Exchange returned empty token")
	}
	if lastSubject != "user-access-token" {
		t.Fatalf("subject_token forwarded = %q, want user-access-token", lastSubject)
	}
	if exchangeHits.Load() != 1 {
		t.Fatalf("exchange endpoint called %d times, want 1", exchangeHits.Load())
	}
}

func TestTokenSourceCachesExchangePerUser(t *testing.T) {
	var tokenHits, exchangeHits atomic.Int64
	srv := tokenEndpoint(t, &tokenHits, &exchangeHits, nil)
	src := NewTokenSource(srv.URL, "brain", "s3cret", testAudience)

	key := testKey(t)
	userToken := func(sub string) string {
		c := baseClaims()
		c.Subject = sub
		return signRS256(t, key, testKID, c)
	}

	subA := userToken("user-A")
	for i := 0; i < 3; i++ {
		if _, err := src.Exchange(t.Context(), subA); err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
	}
	if got := exchangeHits.Load(); got != 1 {
		t.Fatalf("same user exchanged %d times, want 1 (should cache per user)", got)
	}

	if _, err := src.Exchange(t.Context(), userToken("user-B")); err != nil {
		t.Fatalf("exchange user-B: %v", err)
	}
	if got := exchangeHits.Load(); got != 2 {
		t.Fatalf("a different user should mint a new token, hits=%d want 2", got)
	}
}

func TestTokenSourceRequestErrorOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	src := NewTokenSource(srv.URL, "brain", "wrong", testAudience)

	if _, err := src.Token(t.Context()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v, want a 401 failure", err)
	}
}

package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/NicolasPaterno/warden-auth"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

const (
	testKID      = "test-kid"
	testIssuer   = "warden-auth"
	testAudience = "warden-engine"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func jwksServer(t *testing.T, kid string, pub *rsa.PublicKey, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       pub,
		KeyID:     kid,
		Algorithm: "RS256",
		Use:       "sig",
	}}}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func baseClaims() auth.Claims {
	now := time.Now()
	return auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			Issuer:    testIssuer,
			Audience:  jwt.ClaimStrings{testAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
		},
		Scope: "access",
	}
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims auth.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func TestVerifyAcceptsValidToken(t *testing.T) {
	key := testKey(t)
	srv := jwksServer(t, testKID, &key.PublicKey, nil)
	v := New(srv.URL, testIssuer, testAudience)

	token := signRS256(t, key, testKID, baseClaims())
	claims, err := v.Verify(t.Context(), token)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if claims.Subject != "user-1" || claims.Scope != "access" {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestVerifyRejects(t *testing.T) {
	key := testKey(t)
	other := testKey(t)
	srv := jwksServer(t, testKID, &key.PublicKey, nil)

	tests := []struct {
		name  string
		token func() string
	}{
		{"expired", func() string {
			c := baseClaims()
			c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
			return signRS256(t, key, testKID, c)
		}},
		{"wrong audience", func() string {
			c := baseClaims()
			c.Audience = jwt.ClaimStrings{"someone-else"}
			return signRS256(t, key, testKID, c)
		}},
		{"wrong issuer", func() string {
			c := baseClaims()
			c.Issuer = "evil"
			return signRS256(t, key, testKID, c)
		}},
		{"refresh scope rejected as access", func() string {
			c := baseClaims()
			c.Scope = "refresh"
			return signRS256(t, key, testKID, c)
		}},
		{"signed by unknown key", func() string {
			return signRS256(t, other, testKID, baseClaims())
		}},
		{"unknown kid", func() string {
			return signRS256(t, key, "nope", baseClaims())
		}},
		{"missing kid", func() string {
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, baseClaims())
			s, err := tok.SignedString(key)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			return s
		}},
		{"hs256 downgrade", func() string {
			tok := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims())
			tok.Header["kid"] = testKID
			s, err := tok.SignedString([]byte("secret"))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			return s
		}},
		{"garbage", func() string { return "not.a.jwt" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := New(srv.URL, testIssuer, testAudience)
			if _, err := v.Verify(t.Context(), tc.token()); err == nil {
				t.Fatal("Verify accepted a token it should have rejected")
			}
		})
	}
}

func TestVerifyCachesJWKS(t *testing.T) {
	key := testKey(t)
	var hits atomic.Int64
	srv := jwksServer(t, testKID, &key.PublicKey, &hits)
	v := New(srv.URL, testIssuer, testAudience)

	token := signRS256(t, key, testKID, baseClaims())
	for i := 0; i < 3; i++ {
		if _, err := v.Verify(t.Context(), token); err != nil {
			t.Fatalf("Verify %d: %v", i, err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("jwks fetched %d times, want 1 (should cache)", got)
	}
}

func TestMiddleware(t *testing.T) {
	key := testKey(t)
	srv := jwksServer(t, testKID, &key.PublicKey, nil)
	v := New(srv.URL, testIssuer, testAudience)

	var gotSub string
	protected := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			t.Error("claims missing from context")
		} else {
			gotSub = claims.Subject
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("no authorization header returns 401", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, r)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("invalid token returns 401", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
		r.Header.Set("Authorization", "Bearer not.a.jwt")
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, r)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("valid token passes and injects claims", func(t *testing.T) {
		token := signRS256(t, key, testKID, baseClaims())
		r := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if gotSub != "user-1" {
			t.Fatalf("context subject = %q, want user-1", gotSub)
		}
	})
}

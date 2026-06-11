package authn

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	auth "github.com/NicolasPaterno/warden-auth"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type Verifier struct {
	jwksURL    string
	issuer     string
	audience   string
	scopes     map[string]bool
	httpClient *http.Client
	ttl        time.Duration
	minRefresh time.Duration

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time

	fetchMu   sync.Mutex
	lastFetch time.Time
}

type Option func(*Verifier)

func WithScope(scope string) Option {
	return WithScopes(scope)
}

func WithScopes(scopes ...string) Option {
	return func(v *Verifier) {
		set := make(map[string]bool, len(scopes))
		for _, s := range scopes {
			if s != "" {
				set[s] = true
			}
		}
		v.scopes = set
	}
}

func WithHTTPClient(c *http.Client) Option {
	return func(v *Verifier) { v.httpClient = c }
}

func WithCacheTTL(ttl time.Duration) Option {
	return func(v *Verifier) { v.ttl = ttl }
}

func New(jwksURL, issuer, audience string, opts ...Option) *Verifier {
	v := &Verifier{
		jwksURL:    jwksURL,
		issuer:     issuer,
		audience:   audience,
		scopes:     map[string]bool{"access": true},
		httpClient: &http.Client{Timeout: 5 * time.Second},
		ttl:        5 * time.Minute,
		minRefresh: time.Minute,
		keys:       map[string]*rsa.PublicKey{},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

func (v *Verifier) Verify(ctx context.Context, token string) (*auth.Claims, error) {
	claims := &auth.Claims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return v.publicKey(ctx, kid)
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	if len(v.scopes) > 0 && !v.scopes[claims.Scope] {
		return nil, fmt.Errorf("verifier: unexpected scope %q", claims.Scope)
	}
	return claims, nil
}

func (v *Verifier) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("verifier: token missing kid")
	}

	v.mu.RLock()
	key, ok := v.keys[kid]
	expired := time.Now().After(v.expiresAt)
	v.mu.RUnlock()
	if ok && !expired {
		return key, nil
	}

	if err := v.refresh(ctx); err != nil {
		return nil, err
	}

	v.mu.RLock()
	key, ok = v.keys[kid]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("verifier: unknown key id %q", kid)
	}
	return key, nil
}

func (v *Verifier) refresh(ctx context.Context) error {
	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()

	v.mu.RLock()
	fresh := time.Now().Before(v.expiresAt)
	v.mu.RUnlock()
	if fresh && time.Since(v.lastFetch) < v.minRefresh {
		return nil
	}

	keys, err := v.fetch(ctx)
	if err != nil {
		return err
	}

	v.mu.Lock()
	v.keys = keys
	v.expiresAt = time.Now().Add(v.ttl)
	v.mu.Unlock()
	v.lastFetch = time.Now()
	return nil
}

func (v *Verifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verifier: jwks fetch status %d", resp.StatusCode)
	}

	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		pub, ok := jwk.Key.(*rsa.PublicKey)
		if !ok {
			continue
		}
		keys[jwk.KeyID] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("verifier: jwks has no RSA public keys")
	}
	return keys, nil
}

func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		claims, err := v.Verify(r.Context(), token)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
	})
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}

type contextKey struct{}

var claimsKey contextKey

func WithClaims(ctx context.Context, claims *auth.Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

func ClaimsFromContext(ctx context.Context) (*auth.Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(*auth.Claims)
	return claims, ok
}

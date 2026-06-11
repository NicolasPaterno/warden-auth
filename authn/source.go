package authn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenSource struct {
	tokenURL     string
	exchangeURL  string
	clientID     string
	clientSecret string
	audience     string
	httpClient   *http.Client
	skew         time.Duration

	mu       sync.Mutex
	token    string
	expireAt time.Time

	exMu      sync.Mutex
	exchanged map[string]cachedToken
}

type cachedToken struct {
	token    string
	expireAt time.Time
}

func NewTokenSource(authBaseURL, clientID, clientSecret, audience string, opts ...Option) *TokenSource {
	base := strings.TrimRight(authBaseURL, "/")
	s := &TokenSource{
		tokenURL:     base + "/token",
		exchangeURL:  base + "/token/exchange",
		clientID:     clientID,
		clientSecret: clientSecret,
		audience:     audience,
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		skew:         30 * time.Second,
		exchanged:    map[string]cachedToken{},
	}
	v := &Verifier{httpClient: s.httpClient}
	for _, opt := range opts {
		opt(v)
	}
	s.httpClient = v.httpClient
	return s
}

func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().Before(s.expireAt.Add(-s.skew)) {
		return s.token, nil
	}

	token, err := s.request(ctx, s.tokenURL, map[string]string{
		"client_id":     s.clientID,
		"client_secret": s.clientSecret,
		"audience":      s.audience,
	})
	if err != nil {
		return "", err
	}

	s.token = token
	s.expireAt = expiry(token)
	return token, nil
}

func (s *TokenSource) Exchange(ctx context.Context, subjectToken string) (string, error) {
	key := subjectOf(subjectToken)

	s.exMu.Lock()
	if c, ok := s.exchanged[key]; ok && time.Now().Before(c.expireAt.Add(-s.skew)) {
		s.exMu.Unlock()
		return c.token, nil
	}
	s.exMu.Unlock()

	token, err := s.request(ctx, s.exchangeURL, map[string]string{
		"client_id":     s.clientID,
		"client_secret": s.clientSecret,
		"subject_token": subjectToken,
		"audience":      s.audience,
	})
	if err != nil {
		return "", err
	}

	s.exMu.Lock()
	s.evictExpired()
	s.exchanged[key] = cachedToken{token: token, expireAt: expiry(token)}
	s.exMu.Unlock()
	return token, nil
}

func (s *TokenSource) evictExpired() {
	now := time.Now()
	for k, c := range s.exchanged {
		if now.After(c.expireAt) {
			delete(s.exchanged, k)
		}
	}
}

func (s *TokenSource) request(ctx context.Context, url string, body map[string]string) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authn: token request to %s failed with status %d", url, resp.StatusCode)
	}

	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("authn: token response from %s missing access_token", url)
	}
	return out.AccessToken, nil
}

func expiry(token string) time.Time {
	var claims jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &claims); err != nil || claims.ExpiresAt == nil {
		return time.Now()
	}
	return claims.ExpiresAt.Time
}

func subjectOf(token string) string {
	var claims jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &claims); err == nil && claims.Subject != "" {
		return claims.Subject
	}
	return token
}

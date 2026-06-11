package service

import (
	"context"
	"crypto/subtle"
	"net/mail"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	auth "github.com/NicolasPaterno/warden-auth"
	"github.com/NicolasPaterno/warden-auth/internal/keys"
	pwd "github.com/NicolasPaterno/warden-auth/internal/password"
)

const (
	minPasswordLen = 8
	defaultTenant  = "default"
)

var _ auth.Service = (*Service)(nil)

type Service struct {
	keys       *keys.Set
	users      auth.UserRepository
	issuer     string
	audience   []string
	clients    map[string]string
	audiences  map[string]bool
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func New(k *keys.Set, users auth.UserRepository, issuer string, audience []string, clients map[string]string, audiences map[string]bool) *Service {
	return &Service{
		keys:       k,
		users:      users,
		issuer:     issuer,
		audience:   audience,
		clients:    clients,
		audiences:  audiences,
		accessTTL:  15 * time.Minute,
		refreshTTL: 30 * 24 * time.Hour,
	}
}

func (s *Service) Register(ctx context.Context, email, password, tenant string) (auth.User, error) {
	if _, err := mail.ParseAddress(email); err != nil {
		return auth.User{}, auth.ErrInvalid
	}
	if len(password) < minPasswordLen {
		return auth.User{}, auth.ErrInvalid
	}
	if tenant == "" {
		tenant = defaultTenant
	}

	hash, err := pwd.Hash(password)
	if err != nil {
		return auth.User{}, err
	}

	user := auth.User{
		ID:           uuid.NewString(),
		Email:        email,
		TenantID:     tenant,
		PasswordHash: hash,
	}
	if err := s.users.Create(ctx, user); err != nil {
		return auth.User{}, err
	}

	user.PasswordHash = ""
	return user, nil
}

func (s *Service) Login(ctx context.Context, email, password string) (auth.TokenPair, error) {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return auth.TokenPair{}, auth.ErrUnauthorized
	}

	ok, err := pwd.Verify(user.PasswordHash, password)
	if err != nil || !ok {
		return auth.TokenPair{}, auth.ErrUnauthorized
	}

	return s.Issue(user)
}

func (s *Service) Issue(user auth.User) (auth.TokenPair, error) {
	access, err := s.sign(user.ID, s.audience, s.accessTTL, "access", user.TenantID, nil)
	if err != nil {
		return auth.TokenPair{}, err
	}
	refresh, err := s.sign(user.ID, s.audience, s.refreshTTL, "refresh", user.TenantID, nil)
	if err != nil {
		return auth.TokenPair{}, err
	}
	return auth.TokenPair{AccessToken: access, RefreshToken: refresh}, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (string, error) {
	claims, err := s.parse(refreshToken)
	if err != nil {
		return "", auth.ErrUnauthorized
	}
	if claims.Scope != "refresh" {
		return "", auth.ErrUnauthorized
	}
	return s.sign(claims.Subject, s.audience, s.accessTTL, "access", claims.Tenant, nil)
}

func (s *Service) Token(ctx context.Context, clientID, clientSecret, audience string) (string, error) {
	if err := s.authClient(clientID, clientSecret); err != nil {
		return "", err
	}
	if !s.audiences[audience] {
		return "", auth.ErrInvalid
	}
	return s.sign(clientID, []string{audience}, s.accessTTL, "service", "", nil)
}

func (s *Service) Exchange(ctx context.Context, clientID, clientSecret, subjectToken, audience string) (string, error) {
	if err := s.authClient(clientID, clientSecret); err != nil {
		return "", err
	}
	if !s.audiences[audience] {
		return "", auth.ErrInvalid
	}
	claims, err := s.parse(subjectToken)
	if err != nil || claims.Scope != "access" {
		return "", auth.ErrUnauthorized
	}
	return s.sign(claims.Subject, []string{audience}, s.accessTTL, "access", claims.Tenant, &auth.Actor{Subject: clientID})
}

func (s *Service) authClient(clientID, clientSecret string) error {
	secret, ok := s.clients[clientID]
	if !ok || subtle.ConstantTimeCompare([]byte(secret), []byte(clientSecret)) != 1 {
		return auth.ErrUnauthorized
	}
	return nil
}

func (s *Service) parse(token string) (auth.Claims, error) {
	var claims auth.Claims
	parsed, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
		return &s.keys.Private().PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		return auth.Claims{}, err
	}
	return claims, nil
}

func (s *Service) sign(subject string, audience []string, ttl time.Duration, scope, tenant string, act *auth.Actor) (string, error) {
	now := time.Now()

	claims := auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings(audience),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Scope:  scope,
		Tenant: tenant,
		Act:    act,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keys.KID()
	return token.SignedString(s.keys.Private())
}

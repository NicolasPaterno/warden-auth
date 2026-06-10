package service

import (
	"context"
	"net/mail"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	auth "github.com/NicolasPaterno/warden-auth"
	"github.com/NicolasPaterno/warden-auth/internal/keys"
	pwd "github.com/NicolasPaterno/warden-auth/internal/password"
)

const minPasswordLen = 8

var _ auth.AuthService = (*Service)(nil)

type Service struct {
	keys       *keys.Set
	users      auth.UserRepository
	issuer     string
	audience   string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func New(k *keys.Set, users auth.UserRepository, issuer, audience string) *Service {
	return &Service{
		keys:       k,
		users:      users,
		issuer:     issuer,
		audience:   audience,
		accessTTL:  15 * time.Minute,
		refreshTTL: 30 * 24 * time.Hour,
	}
}

func (s *Service) Register(ctx context.Context, email, password string) (auth.User, error) {
	if _, err := mail.ParseAddress(email); err != nil {
		return auth.User{}, auth.ErrInvalid
	}
	if len(password) < minPasswordLen {
		return auth.User{}, auth.ErrInvalid
	}

	hash, err := pwd.Hash(password)
	if err != nil {
		return auth.User{}, err
	}

	user := auth.User{
		ID:           uuid.NewString(),
		Email:        email,
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
	access, err := s.sign(user, s.accessTTL, "access")
	if err != nil {
		return auth.TokenPair{}, err
	}
	refresh, err := s.sign(user, s.refreshTTL, "refresh")
	if err != nil {
		return auth.TokenPair{}, err
	}
	return auth.TokenPair{AccessToken: access, RefreshToken: refresh}, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (string, error) {
	var claims auth.Claims
	token, err := jwt.ParseWithClaims(refreshToken, &claims, func(t *jwt.Token) (any, error) {
		return &s.keys.Private().PublicKey, nil
	})
	if err != nil || !token.Valid {
		return "", auth.ErrUnauthorized
	}

	if claims.Scope != "refresh" {
		return "", auth.ErrUnauthorized
	}
	user := auth.User{ID: claims.Subject}
	return s.sign(user, s.accessTTL, "access")
}

func (s *Service) sign(user auth.User, ttl time.Duration, scope string) (string, error) {
	now := time.Now()

	claims := auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{s.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Scope: scope,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keys.KID()
	return token.SignedString(s.keys.Private())
}

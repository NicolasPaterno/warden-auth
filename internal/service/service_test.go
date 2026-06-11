package service_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	auth "github.com/NicolasPaterno/warden-auth"
	"github.com/NicolasPaterno/warden-auth/internal/keys"
	"github.com/NicolasPaterno/warden-auth/internal/password"
	"github.com/NicolasPaterno/warden-auth/internal/service"
)

type fakeUsers map[string]auth.User

func (f fakeUsers) FindByEmail(_ context.Context, email string) (auth.User, error) {
	u, ok := f[email]
	if !ok {
		return auth.User{}, auth.ErrNotFound
	}
	return u, nil
}

func (f fakeUsers) Create(_ context.Context, u auth.User) error {
	if _, ok := f[u.Email]; ok {
		return auth.ErrConflict
	}
	f[u.Email] = u
	return nil
}

func TestLogin_Succeeds(t *testing.T) {
	hash, err := password.Hash("s3cret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	repo := fakeUsers{"a@b.com": {ID: "user-123", Email: "a@b.com", PasswordHash: hash}}
	svc := service.New(testKeys(t), repo, "warden-auth", []string{"warden-engine"},nil, nil)

	pair, err := svc.Login(context.Background(), "a@b.com", "s3cret")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("expected both tokens to be set")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	hash, err := password.Hash("s3cret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	repo := fakeUsers{"a@b.com": {ID: "user-123", Email: "a@b.com", PasswordHash: hash}}
	svc := service.New(testKeys(t), repo, "warden-auth", []string{"warden-engine"},nil, nil)

	if _, err := svc.Login(context.Background(), "a@b.com", "wrong"); err != auth.ErrUnauthorized {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestLogin_UnknownEmail(t *testing.T) {
	svc := service.New(testKeys(t), fakeUsers{}, "warden-auth", []string{"warden-engine"},nil, nil)

	if _, err := svc.Login(context.Background(), "ghost@b.com", "whatever"); err != auth.ErrUnauthorized {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestRegister_Succeeds(t *testing.T) {
	repo := fakeUsers{}
	svc := service.New(testKeys(t), repo, "warden-auth", []string{"warden-engine"},nil, nil)

	user, err := svc.Register(context.Background(), "a@b.com", "s3cretpw", "tenant-x")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if user.ID == "" {
		t.Fatal("expected a generated id")
	}
	if user.Email != "a@b.com" {
		t.Fatalf("email = %q, want a@b.com", user.Email)
	}
	if user.TenantID != "tenant-x" {
		t.Fatalf("tenant = %q, want tenant-x", user.TenantID)
	}
	if user.PasswordHash != "" {
		t.Fatal("password hash must not leak out of Register")
	}

	// O usuário foi persistido e a senha confere via Login.
	if _, err := svc.Login(context.Background(), "a@b.com", "s3cretpw"); err != nil {
		t.Fatalf("login after register: %v", err)
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	repo := fakeUsers{}
	svc := service.New(testKeys(t), repo, "warden-auth", []string{"warden-engine"},nil, nil)

	if _, err := svc.Register(context.Background(), "a@b.com", "s3cretpw", "tenant-x"); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if _, err := svc.Register(context.Background(), "a@b.com", "another1", "tenant-x"); err != auth.ErrConflict {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestRegister_Invalid(t *testing.T) {
	svc := service.New(testKeys(t), fakeUsers{}, "warden-auth", []string{"warden-engine"},nil, nil)

	cases := map[string]struct{ email, password string }{
		"bad email":      {"not-an-email", "s3cretpw"},
		"empty email":    {"", "s3cretpw"},
		"short password": {"a@b.com", "short"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.Register(context.Background(), tc.email, tc.password, ""); err != auth.ErrInvalid {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func testKeys(t *testing.T) *keys.Set {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	set, err := keys.Load(pemBytes)
	if err != nil {
		t.Fatalf("load keys: %v", err)
	}
	return set
}

func TestIssue_AccessTokenIsVerifiable(t *testing.T) {
	k := testKeys(t)
	svc := service.New(k, nil, "warden-auth", []string{"warden-engine"},nil, nil)
	user := auth.User{ID: "user-123", Email: "a@b.com"}

	pair, err := svc.Issue(user)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("expected both tokens to be set")
	}

	var claims auth.Claims
	tok, err := jwt.ParseWithClaims(pair.AccessToken, &claims, func(token *jwt.Token) (any, error) {
		return &k.Private().PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !tok.Valid {
		t.Fatal("token not valid")
	}

	if tok.Header["kid"] != k.KID() {
		t.Fatalf("kid mismatch: header=%v set=%v", tok.Header["kid"], k.KID())
	}

	if claims.Subject != "user-123" {
		t.Fatalf("subject = %q, want user-123", claims.Subject)
	}
	if claims.Issuer != "warden-auth" {
		t.Fatalf("issuer = %q, want warden-auth", claims.Issuer)
	}
	if claims.Scope != "access" {
		t.Fatalf("scope = %q, want access", claims.Scope)
	}
	if claims.ExpiresAt == nil || time.Until(claims.ExpiresAt.Time) <= 0 {
		t.Fatal("access token already expired")
	}
}

func TestRefresh_IssuesNewAccessToken(t *testing.T) {
	k := testKeys(t)
	svc := service.New(k, nil, "warden-auth", []string{"warden-engine"},nil, nil)
	user := auth.User{ID: "user-123", Email: "a@b.com"}

	pair, err := svc.Issue(user)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	access, err := svc.Refresh(context.Background(), pair.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	var claims auth.Claims
	tok, err := jwt.ParseWithClaims(access, &claims, func(token *jwt.Token) (any, error) {
		return &k.Private().PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !tok.Valid {
		t.Fatal("refreshed token not valid")
	}
	if claims.Subject != "user-123" {
		t.Fatalf("subject = %q, want user-123", claims.Subject)
	}
	if claims.Scope != "access" {
		t.Fatalf("scope = %q, want access", claims.Scope)
	}
}

func TestRefresh_RejectsAccessToken(t *testing.T) {
	k := testKeys(t)
	svc := service.New(k, nil, "warden-auth", []string{"warden-engine"},nil, nil)

	pair, err := svc.Issue(auth.User{ID: "user-123"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Passar o access token onde se espera um refresh deve falhar (scope errado).
	if _, err := svc.Refresh(context.Background(), pair.AccessToken); err != auth.ErrUnauthorized {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestRefresh_RejectsGarbage(t *testing.T) {
	k := testKeys(t)
	svc := service.New(k, nil, "warden-auth", []string{"warden-engine"},nil, nil)

	if _, err := svc.Refresh(context.Background(), "not.a.jwt"); err != auth.ErrUnauthorized {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func serviceWithClients(t *testing.T, k *keys.Set) *service.Service {
	t.Helper()
	clients := map[string]string{"brain": "s3cret"}
	audiences := map[string]bool{"warden-engine": true}
	return service.New(k, nil, "warden-auth", []string{"warden-engine"},clients, audiences)
}

func parseSigned(t *testing.T, k *keys.Set, token string) auth.Claims {
	t.Helper()
	var claims auth.Claims
	tok, err := jwt.ParseWithClaims(token, &claims, func(*jwt.Token) (any, error) {
		return &k.Private().PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !tok.Valid {
		t.Fatal("token not valid")
	}
	return claims
}

func TestToken_Succeeds(t *testing.T) {
	k := testKeys(t)
	svc := serviceWithClients(t, k)

	token, err := svc.Token(context.Background(), "brain", "s3cret", "warden-engine")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	claims := parseSigned(t, k, token)
	if claims.Subject != "brain" {
		t.Fatalf("subject = %q, want brain", claims.Subject)
	}
	if claims.Scope != "service" {
		t.Fatalf("scope = %q, want service", claims.Scope)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "warden-engine" {
		t.Fatalf("audience = %v, want [warden-engine]", claims.Audience)
	}
	if claims.Act != nil {
		t.Fatalf("act = %+v, want nil for client credentials", claims.Act)
	}
}

func TestToken_WrongSecret(t *testing.T) {
	svc := serviceWithClients(t, testKeys(t))

	if _, err := svc.Token(context.Background(), "brain", "nope", "warden-engine"); err != auth.ErrUnauthorized {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestToken_UnknownClient(t *testing.T) {
	svc := serviceWithClients(t, testKeys(t))

	if _, err := svc.Token(context.Background(), "ghost", "s3cret", "warden-engine"); err != auth.ErrUnauthorized {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestToken_AudienceNotAllowed(t *testing.T) {
	svc := serviceWithClients(t, testKeys(t))

	if _, err := svc.Token(context.Background(), "brain", "s3cret", "warden-foo"); err != auth.ErrInvalid {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestExchange_Succeeds(t *testing.T) {
	k := testKeys(t)
	svc := serviceWithClients(t, k)

	pair, err := svc.Issue(auth.User{ID: "user-123"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	token, err := svc.Exchange(context.Background(), "brain", "s3cret", pair.AccessToken, "warden-engine")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	claims := parseSigned(t, k, token)
	if claims.Subject != "user-123" {
		t.Fatalf("subject = %q, want user-123 (the user, preserved)", claims.Subject)
	}
	if claims.Scope != "access" {
		t.Fatalf("scope = %q, want access", claims.Scope)
	}
	if claims.Act == nil || claims.Act.Subject != "brain" {
		t.Fatalf("act = %+v, want {sub: brain}", claims.Act)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "warden-engine" {
		t.Fatalf("audience = %v, want [warden-engine]", claims.Audience)
	}
}

func TestExchange_RejectsRefreshAsSubject(t *testing.T) {
	svc := serviceWithClients(t, testKeys(t))

	pair, err := svc.Issue(auth.User{ID: "user-123"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if _, err := svc.Exchange(context.Background(), "brain", "s3cret", pair.RefreshToken, "warden-engine"); err != auth.ErrUnauthorized {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestExchange_WrongClientSecret(t *testing.T) {
	svc := serviceWithClients(t, testKeys(t))

	pair, err := svc.Issue(auth.User{ID: "user-123"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if _, err := svc.Exchange(context.Background(), "brain", "nope", pair.AccessToken, "warden-engine"); err != auth.ErrUnauthorized {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestExchange_AudienceNotAllowed(t *testing.T) {
	svc := serviceWithClients(t, testKeys(t))

	pair, err := svc.Issue(auth.User{ID: "user-123"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if _, err := svc.Exchange(context.Background(), "brain", "s3cret", pair.AccessToken, "warden-foo"); err != auth.ErrInvalid {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestTenantClaim_PropagatesAndIsolated(t *testing.T) {
	k := testKeys(t)
	svc := serviceWithClients(t, k)

	pair, err := svc.Issue(auth.User{ID: "user-1", TenantID: "tenant-x"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if got := parseSigned(t, k, pair.AccessToken).Tenant; got != "tenant-x" {
		t.Fatalf("access tenant = %q, want tenant-x", got)
	}

	refreshed, err := svc.Refresh(context.Background(), pair.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := parseSigned(t, k, refreshed).Tenant; got != "tenant-x" {
		t.Fatalf("refreshed tenant = %q, want tenant-x (preserved)", got)
	}

	ex, err := svc.Exchange(context.Background(), "brain", "s3cret", pair.AccessToken, "warden-engine")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if got := parseSigned(t, k, ex).Tenant; got != "tenant-x" {
		t.Fatalf("exchanged tenant = %q, want tenant-x (propagated)", got)
	}

	svcTok, err := svc.Token(context.Background(), "brain", "s3cret", "warden-engine")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got := parseSigned(t, k, svcTok).Tenant; got != "" {
		t.Fatalf("service token tenant = %q, want empty (no user, no tenant)", got)
	}
}

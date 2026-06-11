package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/NicolasPaterno/warden-auth"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"
)

func newTestLimiter(t *testing.T) *redis_rate.Limiter {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return redis_rate.NewLimiter(rdb)
}

// fakeAuthService is an in-memory auth.Service for handler tests. Each field
// forces the outcome of one method.
type fakeAuthService struct {
	user        auth.User
	registerErr error
	pair        auth.TokenPair
	loginErr    error
	access      string
	refreshErr  error
	serviceTok  string
	tokenErr    error
	exchangeTok string
	exchangeErr error
	gotEmail    string
	gotPassword string
}

func (f *fakeAuthService) Register(_ context.Context, email, password, _ string) (auth.User, error) {
	f.gotEmail, f.gotPassword = email, password
	return f.user, f.registerErr
}

func (f *fakeAuthService) Login(_ context.Context, email, password string) (auth.TokenPair, error) {
	f.gotEmail, f.gotPassword = email, password
	return f.pair, f.loginErr
}

func (f *fakeAuthService) Refresh(_ context.Context, _ string) (string, error) {
	return f.access, f.refreshErr
}

func (f *fakeAuthService) Token(_ context.Context, _, _, _ string) (string, error) {
	return f.serviceTok, f.tokenErr
}

func (f *fakeAuthService) Exchange(_ context.Context, _, _, _, _ string) (string, error) {
	return f.exchangeTok, f.exchangeErr
}

func newTestRouter(t *testing.T, svc auth.Service) http.Handler {
	router := &Router{service: svc, limiter: newTestLimiter(t)}
	r := chi.NewRouter()
	r.Post("/register", router.handleRegister)
	r.Post("/login", router.handleLogin)
	r.Post("/refresh", router.handleRefresh)
	r.Post("/token", router.handleToken)
	r.Post("/token/exchange", router.handleExchange)
	return r
}

func doRequest(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestHandleRegister(t *testing.T) {
	t.Run("valid body returns 201 with id and email, no hash", func(t *testing.T) {
		svc := &fakeAuthService{user: auth.User{ID: "u-1", Email: "a@b.com"}}
		rec := doRequest(t, newTestRouter(t, svc), http.MethodPost, "/register", `{"email":"a@b.com","password":"s3cretpw"}`)

		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body.String())
		}
		var got userResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("response is not valid userResponse JSON: %v", err)
		}
		if got.ID != "u-1" || got.Email != "a@b.com" {
			t.Fatalf("body = %+v", got)
		}
		if strings.Contains(rec.Body.String(), "password") {
			t.Fatal("response leaked a password field")
		}
	})

	t.Run("duplicate email returns 409", func(t *testing.T) {
		svc := &fakeAuthService{registerErr: auth.ErrConflict}
		rec := doRequest(t, newTestRouter(t, svc), http.MethodPost, "/register", `{"email":"a@b.com","password":"s3cretpw"}`)

		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rec.Code)
		}
	})

	t.Run("invalid input returns 400", func(t *testing.T) {
		svc := &fakeAuthService{registerErr: auth.ErrInvalid}
		rec := doRequest(t, newTestRouter(t, svc), http.MethodPost, "/register", `{"email":"x","password":"short"}`)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("malformed JSON returns 400", func(t *testing.T) {
		rec := doRequest(t, newTestRouter(t, &fakeAuthService{}), http.MethodPost, "/register", "{not json")

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestHandleLogin(t *testing.T) {
	t.Run("valid credentials return 200 with both tokens", func(t *testing.T) {
		svc := &fakeAuthService{pair: auth.TokenPair{AccessToken: "acc", RefreshToken: "ref"}}
		rec := doRequest(t, newTestRouter(t, svc), http.MethodPost, "/login", `{"email":"a@b.com","password":"s3cret"}`)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		if svc.gotEmail != "a@b.com" || svc.gotPassword != "s3cret" {
			t.Fatalf("service got email=%q password=%q", svc.gotEmail, svc.gotPassword)
		}
		var got tokenPairResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("response is not valid tokenPairResponse JSON: %v", err)
		}
		if got.AccessToken != "acc" || got.RefreshToken != "ref" {
			t.Fatalf("body = %+v", got)
		}
	})

	t.Run("bad credentials return 401", func(t *testing.T) {
		svc := &fakeAuthService{loginErr: auth.ErrUnauthorized}
		rec := doRequest(t, newTestRouter(t, svc), http.MethodPost, "/login", `{"email":"a@b.com","password":"wrong"}`)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("malformed JSON returns 400", func(t *testing.T) {
		rec := doRequest(t, newTestRouter(t, &fakeAuthService{}), http.MethodPost, "/login", "{not json")

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestHandleRefresh(t *testing.T) {
	t.Run("valid refresh token returns 200 with a new access token", func(t *testing.T) {
		svc := &fakeAuthService{access: "new-access"}
		rec := doRequest(t, newTestRouter(t, svc), http.MethodPost, "/refresh", `{"refresh_token":"ref"}`)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		var got accessTokenResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("response is not valid accessTokenResponse JSON: %v", err)
		}
		if got.AccessToken != "new-access" {
			t.Fatalf("access_token = %q", got.AccessToken)
		}
	})

	t.Run("invalid refresh token returns 401", func(t *testing.T) {
		svc := &fakeAuthService{refreshErr: auth.ErrUnauthorized}
		rec := doRequest(t, newTestRouter(t, svc), http.MethodPost, "/refresh", `{"refresh_token":"bad"}`)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

func TestHandleToken(t *testing.T) {
	t.Run("valid client credentials return 200 with a bearer token", func(t *testing.T) {
		svc := &fakeAuthService{serviceTok: "svc-token"}
		rec := doRequest(t, newTestRouter(t, svc), http.MethodPost, "/token", `{"client_id":"brain","client_secret":"s3cret","audience":"warden-engine"}`)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		var got serviceTokenResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("response is not valid serviceTokenResponse JSON: %v", err)
		}
		if got.AccessToken != "svc-token" || got.TokenType != "Bearer" {
			t.Fatalf("body = %+v", got)
		}
	})

	t.Run("bad client credentials return 401", func(t *testing.T) {
		svc := &fakeAuthService{tokenErr: auth.ErrUnauthorized}
		rec := doRequest(t, newTestRouter(t, svc), http.MethodPost, "/token", `{"client_id":"brain","client_secret":"wrong","audience":"warden-engine"}`)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("disallowed audience returns 400", func(t *testing.T) {
		svc := &fakeAuthService{tokenErr: auth.ErrInvalid}
		rec := doRequest(t, newTestRouter(t, svc), http.MethodPost, "/token", `{"client_id":"brain","client_secret":"s3cret","audience":"warden-foo"}`)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("malformed JSON returns 400", func(t *testing.T) {
		rec := doRequest(t, newTestRouter(t, &fakeAuthService{}), http.MethodPost, "/token", "{not json")

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestHandleExchange(t *testing.T) {
	t.Run("valid exchange returns 200 with a bearer token", func(t *testing.T) {
		svc := &fakeAuthService{exchangeTok: "exchanged"}
		rec := doRequest(t, newTestRouter(t, svc), http.MethodPost, "/token/exchange", `{"client_id":"brain","client_secret":"s3cret","subject_token":"user-access","audience":"warden-engine"}`)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		var got serviceTokenResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("response is not valid serviceTokenResponse JSON: %v", err)
		}
		if got.AccessToken != "exchanged" || got.TokenType != "Bearer" {
			t.Fatalf("body = %+v", got)
		}
	})

	t.Run("invalid subject token returns 401", func(t *testing.T) {
		svc := &fakeAuthService{exchangeErr: auth.ErrUnauthorized}
		rec := doRequest(t, newTestRouter(t, svc), http.MethodPost, "/token/exchange", `{"client_id":"brain","client_secret":"s3cret","subject_token":"bad","audience":"warden-engine"}`)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("malformed JSON returns 400", func(t *testing.T) {
		rec := doRequest(t, newTestRouter(t, &fakeAuthService{}), http.MethodPost, "/token/exchange", "{not json")

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

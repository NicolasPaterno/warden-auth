package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	auth "github.com/NicolasPaterno/warden-auth"
)

type Router struct {
	service auth.AuthService
	jwks    []byte
}

func NewRouter(service auth.AuthService, jwks []byte, health *HealthHandler) http.Handler {
	router := Router{service: service, jwks: jwks}
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RequestSize(1 << 20))

	r.Get("/health/live", health.Live)
	r.Get("/health/ready", health.Ready)

	r.Get("/.well-known/jwks.json", router.handleJWKS)

	r.Post("/register", router.handleRegister)
	r.Post("/login", router.handleLogin)
	r.Post("/refresh", router.handleRefresh)

	return r
}

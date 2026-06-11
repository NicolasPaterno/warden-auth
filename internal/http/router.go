package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-redis/redis_rate/v10"

	auth "github.com/NicolasPaterno/warden-auth"
)

type Router struct {
	service auth.Service
	jwks    []byte
	limiter *redis_rate.Limiter
}

func NewRouter(service auth.Service, jwks []byte, limiter *redis_rate.Limiter, health *HealthHandler) http.Handler {
	router := Router{service: service, jwks: jwks, limiter: limiter}
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RequestSize(1 << 20))

	r.Get("/health/live", health.Live)
	r.Get("/health/ready", health.Ready)

	r.Get("/.well-known/jwks.json", router.handleJWKS)

	r.With(rateLimitByIP(limiter, "register", redis_rate.PerHour(10))).Post("/register", router.handleRegister)
	r.With(rateLimitByIP(limiter, "login", redis_rate.PerMinute(10))).Post("/login", router.handleLogin)
	r.Post("/refresh", router.handleRefresh)

	r.With(rateLimitByIP(limiter, "token", redis_rate.PerMinute(10))).Post("/token", router.handleToken)
	r.With(rateLimitByIP(limiter, "exchange", redis_rate.PerMinute(10))).Post("/token/exchange", router.handleExchange)

	return r
}

package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"

	"github.com/NicolasPaterno/warden-auth/internal/config"
	httptransport "github.com/NicolasPaterno/warden-auth/internal/http"
	"github.com/NicolasPaterno/warden-auth/internal/keys"
	"github.com/NicolasPaterno/warden-auth/internal/postgres"
	"github.com/NicolasPaterno/warden-auth/internal/service"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if err := godotenv.Load(); err != nil {
		slog.Info("no .env file found")
	}
	cfg := config.Load()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pemBytes, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		slog.Error("failed to read private key", "error", err)
		os.Exit(1)
	}
	keySet, err := keys.Load(pemBytes)
	if err != nil {
		slog.Error("failed to load keys", "error", err)
		os.Exit(1)
	}
	jwks, err := keySet.JWKS()
	if err != nil {
		slog.Error("failed to build jwks", "error", err)
		os.Exit(1)
	}

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		slog.Error("failed to parse redis url", "error", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(opt)

	defer func() {
		if err := rdb.Close(); err != nil {
			slog.Error("failed to close redis client", "error", err)
		}
	}()

	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Error("failed to connect to redis", "error", err)
		os.Exit(1)
	}

	limiter := redis_rate.NewLimiter(rdb)

	userRepo := postgres.NewUserRepo(pool)
	authService := service.New(keySet, userRepo, cfg.Issuer, cfg.Audience)

	healthHandler := httptransport.NewHealthHandler(pool)
	router := httptransport.NewRouter(authService, jwks, limiter, healthHandler)
	server := &http.Server{Addr: cfg.HTTPPort, Handler: router}

	go func() {
		slog.Info("auth listening", "addr", cfg.HTTPPort)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("failed to listen and serve", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("failed to shutdown gracefully", "error", err)
	}
}

package http

import (
	"net/http"
	"strings"

	"github.com/go-redis/redis_rate/v10"
)

func (router *Router) handleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req registerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	user, err := router.service.Register(ctx, req.Email, req.Password)
	if err != nil {
		writeError(ctx, w, err)
		return
	}
	respondJSON(ctx, w, http.StatusCreated, newUserResponse(user))
}

func (router *Router) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	emailKey := "login:email:" + strings.ToLower(req.Email)
	if !allow(w, r, router.limiter, emailKey, redis_rate.PerMinute(5)) {
		return
	}
	pair, err := router.service.Login(ctx, req.Email, req.Password)
	if err != nil {
		writeError(ctx, w, err)
		return
	}
	respondJSON(ctx, w, http.StatusOK, newTokenPairResponse(pair))
}

func (router *Router) handleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req refreshRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	access, err := router.service.Refresh(ctx, req.RefreshToken)
	if err != nil {
		writeError(ctx, w, err)
		return
	}
	respondJSON(ctx, w, http.StatusOK, newAccessTokenResponse(access))
}

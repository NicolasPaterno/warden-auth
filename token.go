package auth

import "github.com/golang-jwt/jwt/v5"

type Actor struct {
	Subject string `json:"sub"`
}

type Claims struct {
	jwt.RegisteredClaims
	Scope  string `json:"scope"`
	Tenant string `json:"tenant,omitempty"`
	Act    *Actor `json:"act,omitempty"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

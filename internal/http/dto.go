package http

import auth "github.com/NicolasPaterno/warden-auth"

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Tenant   string `json:"tenant"`
}

type userResponse struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Tenant string `json:"tenant"`
}

func newUserResponse(u auth.User) userResponse {
	return userResponse{ID: u.ID, Email: u.Email, Tenant: u.TenantID}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type tokenPairResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func newTokenPairResponse(p auth.TokenPair) tokenPairResponse {
	return tokenPairResponse{
		AccessToken:  p.AccessToken,
		RefreshToken: p.RefreshToken,
	}
}

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func newAccessTokenResponse(token string) accessTokenResponse {
	return accessTokenResponse{AccessToken: token}
}

type tokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
}

type exchangeRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	SubjectToken string `json:"subject_token"`
	Audience     string `json:"audience"`
}

type serviceTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func newServiceTokenResponse(token string) serviceTokenResponse {
	return serviceTokenResponse{AccessToken: token, TokenType: "Bearer"}
}

package http

import auth "github.com/NicolasPaterno/warden-auth"

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func newUserResponse(u auth.User) userResponse {
	return userResponse{ID: u.ID, Email: u.Email}
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

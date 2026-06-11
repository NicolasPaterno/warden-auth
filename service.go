package auth

import "context"

type Service interface {
	Register(ctx context.Context, email, password, tenant string) (User, error)
	Login(ctx context.Context, email, password string) (TokenPair, error)
	Refresh(ctx context.Context, refreshToken string) (string, error)
	Token(ctx context.Context, clientID, clientSecret, audience string) (string, error)
	Exchange(ctx context.Context, clientID, clientSecret, subjectToken, audience string) (string, error)
}

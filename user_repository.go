package auth

import "context"

type UserRepository interface {
	FindByEmail(ctx context.Context, email string) (User, error)
	Create(ctx context.Context, user User) error
}

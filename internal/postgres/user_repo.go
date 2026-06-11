package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	auth "github.com/NicolasPaterno/warden-auth"
	db "github.com/NicolasPaterno/warden-auth/db/generated"
)

var _ auth.UserRepository = (*UserRepo)(nil)

type UserRepo struct {
	queries *db.Queries
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{queries: db.New(pool)}
}

func (r *UserRepo) FindByEmail(ctx context.Context, email string) (auth.User, error) {
	row, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.User{}, auth.ErrNotFound
		}
		return auth.User{}, err
	}
	return toAuthUser(row), nil
}

func (r *UserRepo) Create(ctx context.Context, u auth.User) error {
	_, err := r.queries.CreateUser(ctx, db.CreateUserParams{
		ID:           u.ID,
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		TenantID:     u.TenantID,
		CreatedAt:    pgtype.Timestamptz{Time: time.Now(), Valid: true},
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return auth.ErrConflict
		}
		return err
	}
	return nil
}

func toAuthUser(u db.User) auth.User {
	return auth.User{
		ID:           u.ID,
		Email:        u.Email,
		TenantID:     u.TenantID,
		PasswordHash: u.PasswordHash,
	}
}

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: CreateUser :one
INSERT INTO users (id, email, password_hash, tenant_id, created_at)
VALUES ($1, $2, $3, $4, $5)
    RETURNING *;

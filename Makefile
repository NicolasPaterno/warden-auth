.PHONY: build run test lint sqlc migrate-up migrate-down

# migrate/migrate over the local stack's network (postgres service from
# warden-infra). Run `make up` in warden-infra first. No local install needed.
MIGRATE_IMAGE=migrate/migrate:v4.18.1
MIGRATE_NETWORK=warden-local
MIGRATE_DB_URL=postgres://postgres:warden@postgres:5432/warden_auth_db?sslmode=disable

build:
	go build -o bin/auth cmd/auth/main.go

run:
	go run cmd/auth/main.go

test:
	go test ./... -race

lint:
	golangci-lint run ./...

sqlc:
	sqlc generate

migrate-up:
	docker run --rm --network $(MIGRATE_NETWORK) \
		-v $(PWD)/db/migrations:/migrations:ro \
		$(MIGRATE_IMAGE) -path=/migrations -database="$(MIGRATE_DB_URL)" up

migrate-down:
	docker run --rm --network $(MIGRATE_NETWORK) \
		-v $(PWD)/db/migrations:/migrations:ro \
		$(MIGRATE_IMAGE) -path=/migrations -database="$(MIGRATE_DB_URL)" down 1

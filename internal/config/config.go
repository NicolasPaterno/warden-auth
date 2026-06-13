package config

import (
	"os"
	"strings"
)

type Config struct {
	DatabaseURL      string
	HTTPPort         string
	PrivateKeyPath   string
	Issuer           string
	Audience         []string
	RedisURL         string
	ServiceClients   map[string]string
	ServiceAudiences map[string]bool
}

func Load() Config {
	return Config{
		DatabaseURL:      getEnv("DATABASE_URL", "postgres://postgres:warden@localhost:5432/warden_auth_db"),
		HTTPPort:         getEnv("HTTP_PORT", ":8082"),
		PrivateKeyPath:   getEnv("PRIVATE_KEY_PATH", "dev-private.pem"),
		Issuer:           getEnv("ISSUER", "warden-auth"),
		Audience:         parseList(getEnv("AUDIENCE", "warden-engine,warden-gateway,warden-brain")),
		RedisURL:         getEnv("REDIS_URL", "redis://localhost:6379"),
		ServiceClients:   parseClients(getEnv("SERVICE_CLIENTS", "")),
		ServiceAudiences: parseSet(getEnv("SERVICE_AUDIENCES", "")),
	}
}

func parseList(raw string) []string {
	var list []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	return list
}

func parseClients(raw string) map[string]string {
	clients := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		id, secret, ok := strings.Cut(pair, ":")
		if !ok || id == "" || secret == "" {
			continue
		}
		clients[id] = secret
	}
	return clients
}

func parseSet(raw string) map[string]bool {
	set := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		set[item] = true
	}
	return set
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

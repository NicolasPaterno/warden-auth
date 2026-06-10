package config

import "os"

type Config struct {
	DatabaseURL    string
	HTTPPort       string
	PrivateKeyPath string
	Issuer         string
	Audience       string
	RedisURL       string
}

func Load() Config {
	return Config{
		DatabaseURL:    getEnv("DATABASE_URL", "postgres://postgres:warden@localhost:5432/warden_auth_db"),
		HTTPPort:       getEnv("HTTP_PORT", ":8082"),
		PrivateKeyPath: getEnv("PRIVATE_KEY_PATH", "dev-private.pem"),
		Issuer:         getEnv("ISSUER", "warden-auth"),
		Audience:       getEnv("AUDIENCE", "warden-engine"),
		RedisURL:       getEnv("REDIS_URL", "localhost:6379"),
	}
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

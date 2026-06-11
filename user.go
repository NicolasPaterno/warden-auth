package auth

type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	TenantID     string `json:"tenant_id"`
	PasswordHash string `json:"-"`
}

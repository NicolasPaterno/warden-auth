package keys_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/NicolasPaterno/warden-auth/internal/keys"
)

func testPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

func TestLoad(t *testing.T) {
	set, err := keys.Load(testPEM(t))
	_ = set
	_ = err
	t.Skip("implement assertions")
}

func TestLoad_StableKID(t *testing.T) {
	pemBytes := testPEM(t)
	_ = pemBytes
	t.Skip("implement assertions")
}

func TestLoad_InvalidPEM(t *testing.T) {
	_, err := keys.Load([]byte("not a pem"))
	_ = err
	t.Skip("implement assertions")
}

func TestJWKS(t *testing.T) {
	set, err := keys.Load(testPEM(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	jwks, err := set.JWKS()
	_ = jwks
	_ = err
	t.Skip("implement assertions")
}

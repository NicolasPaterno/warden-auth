package keys_test

import (
	"bytes"
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
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if set.Private() == nil {
		t.Fatal("private key is nil")
	}
}

func TestLoad_StableKID(t *testing.T) {
	pemBytes := testPEM(t)
	a, err := keys.Load(pemBytes)
	if err != nil {
		t.Fatalf("load a: %v", err)
	}
	b, err := keys.Load(pemBytes)
	if err != nil {
		t.Fatalf("load b: %v", err)
	}
	if a.KID() != b.KID() {
		t.Fatalf("kid not stable: %q != %q", a.KID(), b.KID())
	}
}

func TestLoad_InvalidPEM(t *testing.T) {
	_, err := keys.Load([]byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid pem")
	}
}

func TestJWKS(t *testing.T) {
	set, err := keys.Load(testPEM(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	jwks, err := set.JWKS()
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	if len(jwks) == 0 {
		t.Fatal("jwks is empty")
	}
	if !bytes.Contains(jwks, []byte(set.KID())) {
		t.Fatal("jwks missing kid")
	}
}

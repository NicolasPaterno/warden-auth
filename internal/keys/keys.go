package keys

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	"github.com/go-jose/go-jose/v4"
)

type Set struct {
	priv *rsa.PrivateKey
	kid  string
	jwks []byte
}

func Load(pemBytes []byte) (*Set, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid pem")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	jwk := jose.JSONWebKey{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	kid := base64.RawURLEncoding.EncodeToString(tp)

	return &Set{priv: key, kid: kid, jwks: nil}, nil
}

func (s *Set) Private() *rsa.PrivateKey {
	return s.priv
}
func (s *Set) KID() string {
	return s.kid
}
func (s *Set) JWKS() ([]byte, error) {
	return s.jwks, nil
}

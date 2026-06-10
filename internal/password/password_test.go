package password_test

import (
	"strings"
	"testing"

	"github.com/NicolasPaterno/warden-auth/internal/password"
)

func TestHashThenVerify(t *testing.T) {
	encoded, err := password.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$") {
		t.Fatalf("encoded = %q, want $argon2id$ prefix", encoded)
	}

	ok, err := password.Verify(encoded, "correct horse battery staple")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("verify returned false for the right password")
	}
}

func TestVerify_WrongPassword(t *testing.T) {
	encoded, err := password.Hash("hunter2")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	ok, err := password.Verify(encoded, "hunter3")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("verify returned true for the wrong password")
	}
}

func TestHash_SaltIsRandom(t *testing.T) {
	a, err := password.Hash("same")
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	b, err := password.Hash("same")
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical — salt is not random")
	}
}

func TestVerify_MalformedEncoding(t *testing.T) {
	if _, err := password.Verify("not-a-phc-string", "whatever"); err == nil {
		t.Fatal("expected error for malformed encoded hash")
	}
}

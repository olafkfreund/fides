package crypto

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword("correct horse battery", hash) {
		t.Fatalf("correct password should verify")
	}
	if VerifyPassword("wrong password", hash) {
		t.Fatalf("wrong password must not verify")
	}
}

func TestHashPasswordSaltsAreRandom(t *testing.T) {
	a, _ := HashPassword("samepassword")
	b, _ := HashPassword("samepassword")
	if a == b {
		t.Fatalf("two hashes of the same password must differ (random salt)")
	}
	if !VerifyPassword("samepassword", a) || !VerifyPassword("samepassword", b) {
		t.Fatalf("both hashes must verify")
	}
}

func TestHashPasswordRejectsShort(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatalf("passwords under 8 chars must be rejected")
	}
}

func TestVerifyPasswordRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "notscrypt$x$y", "scrypt$only-two", "scrypt$@@@$@@@"} {
		if VerifyPassword("whatever", bad) {
			t.Fatalf("malformed hash %q must not verify", bad)
		}
	}
}

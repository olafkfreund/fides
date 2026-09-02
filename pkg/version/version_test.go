package version

import "testing"

func TestString(t *testing.T) {
	orig := Version
	defer func() { Version = orig }()

	t.Run("ldflags value wins when set", func(t *testing.T) {
		Version = "v1.2.3"
		if got := String(); got != "v1.2.3" {
			t.Fatalf("String() = %q, want %q", got, "v1.2.3")
		}
	})

	t.Run("falls back to build info when unset", func(t *testing.T) {
		Version = ""
		if got := String(); got == "" {
			t.Fatal("String() returned empty string; want a build-info revision or \"dev\"")
		}
	})
}

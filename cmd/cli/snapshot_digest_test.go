package main

import "testing"

// The snapshot path used to coerce whatever it had into the sha256 field: it
// fell back to container.ImageID, then to container.Image (a TAG), then
// truncated to 64 characters so the result fit. A tag trimmed to 64 chars is
// indistinguishable from a digest by length, which is exactly why length was
// the wrong test (#430).
//
// The values below are the real ones observed on the dora-aws-prod
// environment, where the fabricated entry produced a shadow change that no
// allowlist entry or CI-registered artifact could ever match -- an environment
// pinned at non-compliant for a reason its operator had no way to fix.
func TestIsSHA256HexRejectsTruncatedImageReferences(t *testing.T) {
	truncated := "ghcr.io/olafkfreund/fides-k8s-reporter:c35b868d52ba306c77956ab87"

	// The bug depended on this being plausible-looking, so assert the trap
	// itself: it is within a hair of digest length, and was truncated TO 64.
	if len(truncated) > 64 {
		t.Fatalf("fixture is %d chars; the old code truncated to 64, so keep it <= 64", len(truncated))
	}
	if isSHA256Hex(truncated) {
		t.Error("accepted a truncated image reference as a sha256 digest")
	}

	for name, in := range map[string]string{
		"empty":       "",
		"tag":         "ghcr.io/org/app:latest",
		"short":       "c127b69288d60290be9a2da7fc220d8dd161921aa4b18dff75c98a1cc14a229",
		"long":        "c127b69288d60290be9a2da7fc220d8dd161921aa4b18dff75c98a1cc14a229aa",
		"non-hex-64":  "zzzzb69288d60290be9a2da7fc220d8dd161921aa4b18dff75c98a1cc14a229a",
		"prefix-kept": "sha256:c127b69288d60290be9a2da7fc220d8dd161921aa4b18dff75c98a1cc14",
	} {
		if isSHA256Hex(in) {
			t.Errorf("%s: accepted %q as a sha256 digest", name, in)
		}
	}
}

func TestIsSHA256HexAcceptsRealDigests(t *testing.T) {
	for _, in := range []string{
		"c127b69288d60290be9a2da7fc220d8dd161921aa4b18dff75c98a1cc14a229a",
		"C127B69288D60290BE9A2DA7FC220D8DD161921AA4B18DFF75C98A1CC14A229A",
		"6908dbe4ac396480a6f4f7bd5123428a79aaf945afdf34da0ad6155e0b9070ee",
	} {
		if !isSHA256Hex(in) {
			t.Errorf("rejected a valid sha256 digest %q", in)
		}
	}
}

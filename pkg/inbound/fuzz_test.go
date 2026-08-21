package inbound

import (
	"testing"
)

// These take bytes straight off the internet: a webhook endpoint is reachable
// by anyone who learns the URL, and the signature check happens on the same
// bytes it is meant to protect. A panic in either is a remote denial of service
// on the server every pipeline calls for a release verdict.

// Verify decides whether a webhook is genuine. It must answer true or false for
// any input at all -- including a signature header shaped to break the parser
// rather than to pass it.
func FuzzVerify(f *testing.F) {
	for _, provider := range []string{"github", "gitlab", "", "GitHub"} {
		f.Add(provider, "s3cr3t", "sha256=deadbeef", []byte(`{"ref":"refs/heads/main"}`))
	}
	f.Add("github", "", "", []byte(``))
	f.Add("github", "k", "sha256=", []byte(`x`))
	f.Add("github", "k", "sha256=zzzz", []byte(`x`))   // not hex
	f.Add("github", "k", "sha1=deadbeef", []byte(`x`)) // wrong algorithm
	f.Add("gitlab", "k", "\x00\xff", []byte(`x`))

	f.Fuzz(func(t *testing.T, provider, secret, sigOrToken string, body []byte) {
		// The only invariant that always holds: it returns a decision rather
		// than panicking. Whether it says yes is the job of the table tests.
		_ = Verify(provider, secret, sigOrToken, body)
	})
}

// ParsePush turns a provider's push payload into a trail. It runs on bodies
// that have already been signature-checked in production, but it must not be
// the reason a malformed-but-signed payload takes the process down -- and in
// the inbound path it is reached before some callers check the second return.
func FuzzParsePush(f *testing.F) {
	seeds := []string{
		`{"ref":"refs/heads/main","after":"abc123","repository":{"full_name":"o/r"},"head_commit":{"id":"abc","message":"m","author":{"email":"a@b.c"}}}`,
		`{"ref":null,"head_commit":null}`,
		`{"head_commit":{"author":null}}`,
		`{"commits":[]}`,
		`{"object_kind":"push","checkout_sha":"abc","project":{"path_with_namespace":"o/r"}}`,
		`{}`,
		`[]`,
		``,
	}
	for _, provider := range []string{"github", "gitlab"} {
		for _, s := range seeds {
			f.Add(provider, []byte(s))
		}
	}
	f.Fuzz(func(t *testing.T, provider string, body []byte) {
		_, _ = ParsePush(provider, body)
	})
}

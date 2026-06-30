package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"fides/pkg/events"
)

type fakeLoader struct {
	targets []Target
	err     error
}

func (f fakeLoader) Targets(context.Context, uuid.UUID, string) ([]Target, error) {
	return f.targets, f.err
}

func TestSignMatchesManualHMAC(t *testing.T) {
	secret, ts, body := "topsecret", "1700000000", []byte(`{"a":1}`)
	got := Sign(secret, ts, body)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Fatalf("Sign mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestDeliverSignsAndPosts(t *testing.T) {
	var gotSig, gotTs, gotID, gotType string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Fides-Signature")
		gotTs = r.Header.Get("X-Fides-Timestamp")
		gotID = r.Header.Get("X-Fides-Event-Id")
		gotType = r.Header.Get("X-Fides-Event-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewSink(fakeLoader{targets: []Target{{URL: srv.URL, Secret: "shh"}}})
	sink.validate = func(string) error { return nil } // allow loopback in test
	sink.now = func() time.Time { return time.Unix(1700000000, 0) }

	ev := events.Event{ID: uuid.New(), OrgID: uuid.New(), Type: "snapshot.noncompliant", Payload: []byte(`{"x":1}`)}
	if err := sink.Deliver(context.Background(), ev); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	if gotID != ev.ID.String() || gotType != ev.Type {
		t.Fatalf("headers mismatch: id=%s type=%s", gotID, gotType)
	}
	if gotTs != "1700000000" {
		t.Fatalf("timestamp header = %s", gotTs)
	}
	if want := Sign("shh", gotTs, gotBody); gotSig != want {
		t.Fatalf("signature mismatch:\n got %s\nwant %s", gotSig, want)
	}
}

func TestDeliverPropagatesNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink := NewSink(fakeLoader{targets: []Target{{URL: srv.URL, Secret: "s"}}})
	sink.validate = func(string) error { return nil }

	if err := sink.Deliver(context.Background(), events.Event{ID: uuid.New(), Payload: []byte("{}")}); err == nil {
		t.Fatalf("expected error on non-2xx response")
	}
}

func TestDeliverNoTargetsIsNoop(t *testing.T) {
	sink := NewSink(fakeLoader{})
	if err := sink.Deliver(context.Background(), events.Event{ID: uuid.New(), Payload: []byte("{}")}); err != nil {
		t.Fatalf("no targets should be a no-op, got %v", err)
	}
}

func TestValidateTargetURLSSRF(t *testing.T) {
	bad := []string{
		"http://example.com/hook",        // not https
		"https://127.0.0.1/hook",         // loopback
		"https://10.0.0.5/hook",          // private
		"https://169.254.169.254/latest", // cloud metadata (link-local)
		"https://[::1]/hook",             // ipv6 loopback
		"https:///nohost",                // no host
	}
	for _, u := range bad {
		if err := validateTargetURL(u); err == nil {
			t.Errorf("expected %s to be rejected", u)
		}
	}
}

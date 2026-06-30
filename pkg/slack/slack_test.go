package slack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"fides/pkg/events"
)

type fakeLoader struct {
	url     string
	enabled bool
}

func (f fakeLoader) SlackWebhook(context.Context, uuid.UUID) (string, bool, error) {
	return f.url, f.enabled, nil
}

func TestSlackSinkPostsMessage(t *testing.T) {
	var got map[string]string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewSink(fakeLoader{url: srv.URL, enabled: true})
	sink.http = srv.Client() // trust the test TLS cert

	ev := events.Event{OrgID: uuid.New(), Type: "compliance.evaluated", Payload: []byte(`{"trail_id":"t1","compliant":false}`)}
	if err := sink.Deliver(context.Background(), ev); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if !strings.Contains(got["text"], "NON-COMPLIANT") || !strings.Contains(got["text"], "t1") {
		t.Fatalf("unexpected slack text: %q", got["text"])
	}
}

func TestSlackSinkSkips(t *testing.T) {
	var called bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()

	// disabled tenant
	d := NewSink(fakeLoader{url: srv.URL, enabled: false})
	d.http = srv.Client()
	_ = d.Deliver(context.Background(), events.Event{Type: "compliance.evaluated", Payload: []byte(`{}`)})

	// unrelated event type
	u := NewSink(fakeLoader{url: srv.URL, enabled: true})
	u.http = srv.Client()
	_ = u.Deliver(context.Background(), events.Event{Type: "other", Payload: []byte(`{}`)})

	if called {
		t.Fatalf("Slack must not be called for disabled/unrelated events")
	}
}

func TestFormatMessage(t *testing.T) {
	shadow := formatMessage(events.Event{Type: "snapshot.noncompliant", Payload: []byte(`{"environment_id":"e1","shadows":["a"],"drifts":[]}`)})
	if !strings.Contains(shadow, "non-compliant snapshot") || !strings.Contains(shadow, "e1") {
		t.Fatalf("shadow message wrong: %q", shadow)
	}
	if formatMessage(events.Event{Type: "irrelevant"}) != "" {
		t.Fatalf("irrelevant events must produce no message")
	}
}

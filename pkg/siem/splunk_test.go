package siem

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"fides/pkg/events"
)

func TestSplunkSinkDeliver(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewSplunkSink(srv.URL, "sekret-token")
	ev := events.Event{
		ID:        uuid.New(),
		OrgID:     uuid.New(),
		Type:      "compliance.evaluated",
		Payload:   json.RawMessage(`{"trail_id":"t1","compliant":true}`),
		CreatedAt: time.Unix(1700000000, 0),
	}
	if err := sink.Deliver(context.Background(), ev); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	if gotAuth != "Splunk sekret-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Splunk sekret-token")
	}
	// Verify the HEC envelope shape and that the event type + payload survived.
	var env struct {
		Time       int64  `json:"time"`
		Sourcetype string `json:"sourcetype"`
		Event      struct {
			Type    string          `json:"type"`
			Payload json.RawMessage `json:"payload"`
		} `json:"event"`
	}
	if err := json.Unmarshal([]byte(gotBody), &env); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, gotBody)
	}
	if env.Time != 1700000000 || env.Sourcetype != "fides:event" || env.Event.Type != "compliance.evaluated" {
		t.Errorf("envelope = %+v, want time/sourcetype/type set", env)
	}
	if string(env.Event.Payload) != `{"trail_id":"t1","compliant":true}` {
		t.Errorf("payload = %s, want passthrough", env.Event.Payload)
	}
}

func TestSplunkSinkErrorOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	sink := NewSplunkSink(srv.URL, "t")
	// A non-200 must return an error so the dispatcher retries (not silently drop).
	if err := sink.Deliver(context.Background(), events.Event{CreatedAt: time.Now()}); err == nil {
		t.Fatal("expected an error on non-200 HEC response")
	}
}

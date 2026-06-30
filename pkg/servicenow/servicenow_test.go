package servicenow

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// testClient builds a Client pointing at a test server, bypassing the SSRF guard.
func testClient(url string, auth AuthType, client *http.Client) *Client {
	return &Client{
		cfg:        Config{InstanceURL: url, AuthType: auth, ClientID: "id", Secret: "secret"},
		http:       client,
		now:        time.Now,
		validate:   func(string) error { return nil },
		maxRetries: 2,
	}
}

func TestIdentifyReconcileBasicAuth(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody IREPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result":{"items":[]}}`))
	}))
	defer srv.Close()

	c := testClient(srv.URL, AuthBasic, srv.Client())
	payload := IREPayload{
		Items:     []IREItem{{ClassName: "cmdb_ci_docker_image", Values: map[string]any{"name": "x"}}},
		Relations: []IRERelation{{Parent: 0, Child: 0, Type: "Instantiated From"}},
	}
	if err := c.IdentifyReconcile(context.Background(), payload, nil); err != nil {
		t.Fatalf("IdentifyReconcile: %v", err)
	}
	if gotPath != "/api/now/identifyreconcile" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotAuth == "" || gotAuth[:6] != "Basic " {
		t.Fatalf("expected Basic auth, got %q", gotAuth)
	}
	if len(gotBody.Items) != 1 || gotBody.Items[0].ClassName != "cmdb_ci_docker_image" {
		t.Fatalf("payload not sent correctly: %+v", gotBody)
	}
}

func TestOAuth2TokenFetchedOnceAndCached(t *testing.T) {
	var tokenCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth_token.do" {
			atomic.AddInt32(&tokenCalls, 1)
			w.Write([]byte(`{"access_token":"abc123","expires_in":3600}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer abc123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"result":[]}`))
	}))
	defer srv.Close()

	c := testClient(srv.URL, AuthOAuth2, srv.Client())
	for i := 0; i < 3; i++ {
		if _, err := c.QueryTable(context.Background(), "change_request", "state=3"); err != nil {
			t.Fatalf("QueryTable %d: %v", i, err)
		}
	}
	if n := atomic.LoadInt32(&tokenCalls); n != 1 {
		t.Fatalf("expected token fetched once (cached), got %d", n)
	}
}

func TestRetryOn5xxThenSuccess(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := testClient(srv.URL, AuthBasic, srv.Client())
	if err := c.SendEvents(context.Background(), Event{Source: "Fides", Severity: "1", Description: "test"}); err != nil {
		t.Fatalf("SendEvents should have retried then succeeded: %v", err)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("expected 2 calls (1 fail + 1 success), got %d", n)
	}
}

func TestSendEventsPostsRecords(t *testing.T) {
	var gotPath string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := testClient(srv.URL, AuthBasic, srv.Client())
	if err := c.SendEvents(context.Background(), Event{Source: "Fides-Compliance", EventClass: "ShadowDeployment", Severity: "1", Description: "shadow"}); err != nil {
		t.Fatalf("SendEvents: %v", err)
	}
	if gotPath != "/api/global/em/jsonv2" {
		t.Fatalf("path = %s", gotPath)
	}
	if _, ok := body["records"]; !ok {
		t.Fatalf("expected a 'records' array, got %+v", body)
	}
}

func TestQueryAndCreateTable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET":
			if r.URL.Query().Get("sysparm_query") != "state=3" {
				t.Errorf("query not passed: %s", r.URL.RawQuery)
			}
			w.Write([]byte(`{"result":[{"number":"CHG0030192","state":"3"}]}`))
		case r.Method == "POST":
			w.Write([]byte(`{"result":{"sys_id":"abc","number":"INC0012345"}}`))
		}
	}))
	defer srv.Close()

	c := testClient(srv.URL, AuthBasic, srv.Client())
	res, err := c.QueryTable(context.Background(), "change_request", "state=3", "number", "state")
	if err != nil || len(res.Result) != 1 || res.Result[0]["number"] != "CHG0030192" {
		t.Fatalf("QueryTable result wrong: %+v err=%v", res, err)
	}
	rec, err := c.CreateRecord(context.Background(), "incident", map[string]any{"short_description": "x"})
	if err != nil || rec["number"] != "INC0012345" {
		t.Fatalf("CreateRecord result wrong: %+v err=%v", rec, err)
	}
}

func TestValidateInstanceURLSSRF(t *testing.T) {
	for _, u := range []string{
		"http://acme.service-now.com", // not https
		"https://127.0.0.1",           // loopback
		"https://10.1.2.3",            // private
		"https://169.254.169.254",     // metadata
		"https://[::1]",               // ipv6 loopback
	} {
		if err := validateInstanceURL(u); err == nil {
			t.Errorf("expected %s to be rejected", u)
		}
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(Config{InstanceURL: "http://x.service-now.com", AuthType: AuthBasic}); err == nil {
		t.Fatalf("expected http to be rejected")
	}
	if _, err := New(Config{InstanceURL: "https://x.service-now.com", AuthType: "weird"}); err == nil {
		t.Fatalf("expected unknown auth type to be rejected")
	}
}

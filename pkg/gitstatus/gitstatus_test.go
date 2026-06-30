package gitstatus

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"fides/pkg/events"
)

func TestParseRepo(t *testing.T) {
	cases := []struct {
		in   string
		host string
		path string
	}{
		{"https://github.com/acme/widgets.git", "github.com", "acme/widgets"},
		{"https://github.com/acme/widgets", "github.com", "acme/widgets"},
		{"git@github.com:acme/widgets.git", "github.com", "acme/widgets"},
		{"https://gitlab.com/group/sub/project.git", "gitlab.com", "group/sub/project"},
		{"git@gitlab.example.com:group/sub/project.git", "gitlab.example.com", "group/sub/project"},
		{"ssh://git@gitlab.com/group/project.git", "gitlab.com", "group/project"},
	}
	for _, c := range cases {
		r, err := ParseRepo(c.in)
		if err != nil {
			t.Errorf("ParseRepo(%q): %v", c.in, err)
			continue
		}
		if r.Host != c.host || r.Path != c.path {
			t.Errorf("ParseRepo(%q) = {%s %s}, want {%s %s}", c.in, r.Host, r.Path, c.host, c.path)
		}
	}
	if _, err := ParseRepo(""); err == nil {
		t.Errorf("empty url should error")
	}
}

func TestOwnerRepo(t *testing.T) {
	r := Repo{Host: "github.com", Path: "acme/widgets"}
	or, err := r.OwnerRepo()
	if err != nil || or != "acme/widgets" {
		t.Fatalf("OwnerRepo = %q, %v", or, err)
	}
}

func TestPostGitHubStatus(t *testing.T) {
	var gotPath, gotAuth, gotState, gotContext string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		var body map[string]string
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		gotState = body["state"]
		gotContext = body["context"]
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	err := PostStatus(context.Background(), srv.Client(), ProviderGitHub, srv.URL, "tok",
		Repo{Host: "github.com", Path: "acme/widgets"}, "abc123",
		Verdict{Compliant: false, Context: "fides/compliance"})
	if err != nil {
		t.Fatalf("PostStatus: %v", err)
	}
	if gotPath != "/repos/acme/widgets/statuses/abc123" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("auth = %s", gotAuth)
	}
	if gotState != "failure" {
		t.Fatalf("non-compliant should map to github 'failure', got %s", gotState)
	}
	if gotContext != "fides/compliance" {
		t.Fatalf("context = %s", gotContext)
	}
}

func TestPostGitLabStatus(t *testing.T) {
	var gotPath, gotToken, gotState string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		gotToken = r.Header.Get("PRIVATE-TOKEN")
		var body map[string]string
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		gotState = body["state"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := PostStatus(context.Background(), srv.Client(), ProviderGitLab, srv.URL, "glpat",
		Repo{Host: "gitlab.com", Path: "group/sub/project"}, "def456",
		Verdict{Compliant: true, Context: "fides/compliance"})
	if err != nil {
		t.Fatalf("PostStatus: %v", err)
	}
	// GitLab project path must be URL-encoded.
	if gotPath != "/projects/group%2Fsub%2Fproject/statuses/def456" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotToken != "glpat" {
		t.Fatalf("token header = %s", gotToken)
	}
	if gotState != "success" {
		t.Fatalf("compliant should map to gitlab 'success', got %s", gotState)
	}
}

// fakeLoader drives the sink without a DB.
type fakeLoader struct {
	providers []ProviderConfig
	trail     TrailGit
}

func (f fakeLoader) Providers(context.Context, uuid.UUID) ([]ProviderConfig, error) {
	return f.providers, nil
}
func (f fakeLoader) TrailGit(context.Context, uuid.UUID, uuid.UUID) (TrailGit, error) {
	return f.trail, nil
}

func TestSinkPostsStatusForMatchingHost(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	loader := fakeLoader{
		providers: []ProviderConfig{{Provider: ProviderGitHub, Host: "github.com", APIBase: srv.URL, Token: "t"}},
		trail:     TrailGit{Repository: "https://github.com/acme/widgets.git", Commit: "abc"},
	}
	sink := NewSink(loader, "https://fides.example.com")

	trailID := uuid.New()
	payload, _ := json.Marshal(map[string]any{"trail_id": trailID.String(), "compliant": false})
	ev := events.Event{ID: uuid.New(), OrgID: uuid.New(), Type: EventType, Payload: payload}

	if err := sink.Deliver(context.Background(), ev); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if !hit {
		t.Fatalf("expected the sink to POST a commit status")
	}
}

func TestSinkIgnoresUnrelatedEventsAndHosts(t *testing.T) {
	loader := fakeLoader{
		providers: []ProviderConfig{{Provider: ProviderGitHub, Host: "github.com", APIBase: "http://unused", Token: "t"}},
		trail:     TrailGit{Repository: "https://bitbucket.org/x/y.git", Commit: "abc"},
	}
	sink := NewSink(loader, "https://fides.example.com")

	// Wrong event type -> no-op.
	if err := sink.Deliver(context.Background(), events.Event{Type: "other", Payload: []byte("{}")}); err != nil {
		t.Fatalf("unrelated event should be a no-op: %v", err)
	}
	// Matching event but unconfigured host -> no-op (no panic, no error).
	payload, _ := json.Marshal(map[string]any{"trail_id": uuid.New().String(), "compliant": true})
	if err := sink.Deliver(context.Background(), events.Event{OrgID: uuid.New(), Type: EventType, Payload: payload}); err != nil {
		t.Fatalf("unconfigured host should be a no-op: %v", err)
	}
}

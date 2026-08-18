package servicenow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"fides/pkg/events"
)

type fakeControls struct{ refs []ControlRef }

func (f fakeControls) ControlsForAttestation(context.Context, uuid.UUID, string) ([]ControlRef, error) {
	return f.refs, nil
}

// grcInstance is a ServiceNow stand-in for the two tables the GRC sink touches.
// controlHits decides whether the compliance control exists in the catalogue;
// created records are kept so the dedup query can find them on redelivery,
// which is what makes the idempotency assertion below meaningful rather than
// just "it did not crash twice".
type grcInstance struct {
	mu          sync.Mutex
	controlHits int
	created     []map[string]any
}

func (g *grcInstance) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/"+grcControlTable):
			if g.controlHits == 0 {
				w.Write([]byte(`{"result":[]}`))
				return
			}
			w.Write([]byte(`{"result":[{"sys_id":"ctl-sys-1"}]}`))

		case strings.HasSuffix(r.URL.Path, "/"+grcTestTable) && r.Method == http.MethodGet:
			marker := r.URL.Query().Get("sysparm_query")
			for _, rec := range g.created {
				if res, _ := rec["actual_results"].(string); strings.Contains(marker, "actual_resultsLIKE") &&
					strings.Contains(res, marker[strings.Index(marker, "actual_resultsLIKE")+len("actual_resultsLIKE"):]) {
					w.Write([]byte(`{"result":[{"sys_id":"existing"}]}`))
					return
				}
			}
			w.Write([]byte(`{"result":[]}`))

		case strings.HasSuffix(r.URL.Path, "/"+grcTestTable) && r.Method == http.MethodPost:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode POST body: %v", err)
			}
			g.created = append(g.created, body)
			w.Write([]byte(`{"result":{"sys_id":"test-1"}}`))

		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}
}

func grcEvent(t *testing.T, compliant bool) events.Event {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"trail_id":    "c14feed8-dae0-49fc-9322-ebf995b003e7",
		"attestation": "snyk-scan",
		"compliant":   compliant,
	})
	return events.Event{Type: GRCEventType, OrgID: uuid.New(), Payload: payload}
}

func newGRCSink(t *testing.T, srv *httptest.Server, enabled bool, refs []ControlRef) *GRCSink {
	t.Helper()
	s := NewGRCSink(fakeLoader{enabled: true}, fakeControls{refs: refs})
	s.enabled = func() bool { return enabled }
	s.newClient = func(Config) (*Client, error) {
		return testClient(srv.URL, AuthBasic, srv.Client()), nil
	}
	return s
}

var oneControl = []ControlRef{{Key: "SOC2-CC7.1", Name: "Vulnerability scanning"}}

// The GRC catalogue belongs to whoever runs the compliance programme, so
// filing control tests into it is opt-in. A sink that wrote by default would
// start depositing one record per control per attestation per deploy into
// somebody else's audit module without them agreeing to carry the volume.
func TestGRCSinkOffByDefault(t *testing.T) {
	inst := &grcInstance{controlHits: 1}
	srv := httptest.NewServer(inst.handler(t))
	defer srv.Close()

	if err := newGRCSink(t, srv, false, oneControl).Deliver(context.Background(), grcEvent(t, true)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(inst.created) != 0 {
		t.Fatalf("gated sink wrote %d record(s); it must write none", len(inst.created))
	}
}

// control_effectiveness is derived from the two dimensions below. Setting it
// directly is accepted by ServiceNow and silently ignored — the record comes
// back "none" — so writing it would look like success and produce an audit
// record that says nothing. Same failure shape as an unregistered
// discovery_source, and as IRE answering 200 with hasError true.
func TestGRCSinkFilesControlTestWithoutDerivedEffectiveness(t *testing.T) {
	inst := &grcInstance{controlHits: 1}
	srv := httptest.NewServer(inst.handler(t))
	defer srv.Close()

	if err := newGRCSink(t, srv, true, oneControl).Deliver(context.Background(), grcEvent(t, true)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(inst.created) != 1 {
		t.Fatalf("expected 1 control test, got %d", len(inst.created))
	}
	rec := inst.created[0]
	if _, set := rec["control_effectiveness"]; set {
		t.Error("control_effectiveness must never be written — it is derived and " +
			"setting it is accepted then silently ignored")
	}
	for _, f := range []string{"design_effectiveness", "operation_effectiveness"} {
		if rec[f] != "effective" {
			t.Errorf("%s = %v, want effective", f, rec[f])
		}
	}
	if rec["control"] != "ctl-sys-1" {
		t.Errorf("control = %v, want the resolved sys_id", rec["control"])
	}
	if res, _ := rec["actual_results"].(string); !strings.Contains(res, "snyk-scan") ||
		!strings.Contains(res, "c14feed8-dae0-49fc-9322-ebf995b003e7") {
		t.Errorf("actual_results must name the attestation and trail: %q", res)
	}
}

func TestGRCSinkNonCompliantVerdict(t *testing.T) {
	inst := &grcInstance{controlHits: 1}
	srv := httptest.NewServer(inst.handler(t))
	defer srv.Close()

	if err := newGRCSink(t, srv, true, oneControl).Deliver(context.Background(), grcEvent(t, false)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if inst.created[0]["design_effectiveness"] != "ineffective" {
		t.Errorf("a non-compliant verdict must file as ineffective, got %v",
			inst.created[0]["design_effectiveness"])
	}
}

// The outbox dispatcher retries, and a verdict can be re-emitted for the same
// trail. Without the marker check that would accumulate duplicate control tests
// against a real audit record.
func TestGRCSinkIdempotentOnRedelivery(t *testing.T) {
	inst := &grcInstance{controlHits: 1}
	srv := httptest.NewServer(inst.handler(t))
	defer srv.Close()

	sink, ev := newGRCSink(t, srv, true, oneControl), grcEvent(t, true)
	for i := 0; i < 3; i++ {
		if err := sink.Deliver(context.Background(), ev); err != nil {
			t.Fatalf("Deliver %d: %v", i, err)
		}
	}
	if len(inst.created) != 1 {
		t.Fatalf("redelivery created %d records; must stay at 1", len(inst.created))
	}
}

// Seeding the catalogue is a governance decision. A verdict for a control that
// does not exist in ServiceNow is dropped, not auto-created, and is not an
// error — otherwise a partially-seeded instance would fail every event and the
// dispatcher would stall the whole outbox.
func TestGRCSinkSkipsControlsMissingFromCatalogue(t *testing.T) {
	inst := &grcInstance{controlHits: 0}
	srv := httptest.NewServer(inst.handler(t))
	defer srv.Close()

	if err := newGRCSink(t, srv, true, oneControl).Deliver(context.Background(), grcEvent(t, true)); err != nil {
		t.Fatalf("an unseeded control must be skipped, not fail: %v", err)
	}
	if len(inst.created) != 0 {
		t.Fatalf("wrote %d record(s) for a control absent from the catalogue", len(inst.created))
	}
}

// No control maps to the attestation, or another sink's event type arrives:
// both must be silent no-ops that never open a connection.
func TestGRCSinkIgnoresUnrelatedEventsAndUnmappedAttestations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("must not call ServiceNow: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	if err := newGRCSink(t, srv, true, nil).Deliver(context.Background(), grcEvent(t, true)); err != nil {
		t.Fatalf("unmapped attestation: %v", err)
	}
	other := grcEvent(t, true)
	other.Type = "snapshot.reported"
	if err := newGRCSink(t, srv, true, oneControl).Deliver(context.Background(), other); err != nil {
		t.Fatalf("unrelated event: %v", err)
	}
}

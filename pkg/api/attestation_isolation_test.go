package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	_ "github.com/lib/pq"
)

func postAttestation(t *testing.T, srv *Server, org uuid.UUID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/attestations", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(principalCtx(org))
	rec := httptest.NewRecorder()
	srv.handleReportAttestation(rec, req)
	return rec
}

// /api/v1/attestations is where compliance evidence is written. trail_id is
// caller-supplied, so an unguarded handler lets one tenant write evidence into
// another tenant's chain.
func TestReportAttestationCannotTargetAnotherTenantsTrail(t *testing.T) {
	pool := trailProbeDB(t)
	mine, theirTrail := twoTenantTrails(t, pool)
	srv := NewServer(pool, nil, nil)

	rec := postAttestation(t, srv, mine,
		`{"trail_id":"`+theirTrail.String()+`","name":"forged","type_name":"security-scan","payload":"{\"ok\":true}"}`)
	t.Logf("status=%d body=%.100s", rec.Code, rec.Body.String())

	var n int
	if err := pool.QueryRow(`SELECT count(*) FROM attestations WHERE trail_id=$1 AND name='forged'`,
		theirTrail).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("LEAK: forged an attestation onto another tenant's trail (status %d)", rec.Code)
	}
}

// The same write, reached WITHOUT naming a trail at all — just their artifact
// digest. sha256 is the artifacts PRIMARY KEY, so digests are global across
// tenants and resolving one unscoped hands back another tenant's trail.
func TestReportAttestationCannotReachAnotherTenantsTrailViaDigest(t *testing.T) {
	pool := trailProbeDB(t)
	mine, theirTrail := twoTenantTrails(t, pool)
	digest := strings.Repeat("ef", 32)
	var theirOrg uuid.UUID
	if err := pool.QueryRow(`SELECT f.org_id FROM trails t JOIN flows f ON f.id=t.flow_id WHERE t.id=$1`,
		theirTrail).Scan(&theirOrg); err != nil {
		t.Fatalf("org: %v", err)
	}
	mustExec(t, pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type)
	                   VALUES ($1,$2,$3,'their-img','container')`, digest, theirOrg, theirTrail)

	srv := NewServer(pool, nil, nil)
	rec := postAttestation(t, srv, mine,
		`{"artifact_sha256":"`+digest+`","name":"forged-via-digest","type_name":"security-scan","payload":"{\"ok\":true}"}`)
	t.Logf("status=%d body=%.100s", rec.Code, rec.Body.String())

	var n int
	if err := pool.QueryRow(`SELECT count(*) FROM attestations WHERE trail_id=$1 AND name='forged-via-digest'`,
		theirTrail).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("LEAK: reached another tenant's trail through their digest (status %d)", rec.Code)
	}
}

// Reporting a runtime image whose digest ANOTHER tenant registered must not
// inherit their provenance. Before the fix this returned compliant:true with no
// shadow changes — a green verdict for an image this org never built.
func TestSnapshotDoesNotInheritAnotherTenantsProvenance(t *testing.T) {
	pool := trailProbeDB(t)
	mine, theirTrail := twoTenantTrails(t, pool)
	digest := strings.Repeat("cd", 32)
	var theirOrg uuid.UUID
	if err := pool.QueryRow(`SELECT f.org_id FROM trails t JOIN flows f ON f.id=t.flow_id WHERE t.id=$1`,
		theirTrail).Scan(&theirOrg); err != nil {
		t.Fatalf("org: %v", err)
	}
	mustExec(t, pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type)
	                   VALUES ($1,$2,$3,'their-image','container')`, digest, theirOrg, theirTrail)

	myEnv := uuid.New()
	mustExec(t, pool, `INSERT INTO environments (id,org_id,name,type) VALUES ($1,$2,'prod','k8s')`, myEnv, mine)

	srv := NewServer(pool, nil, nil)
	body := `{"environment_id":"` + myEnv.String() + `","artifacts":[{"sha256":"` + digest + `","service_name":"svc"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/environments/snapshot", strings.NewReader(body))
	req = req.WithContext(principalCtx(mine))
	rec := httptest.NewRecorder()
	srv.handleReportSnapshot(rec, req)
	got := rec.Body.String()
	t.Logf("status=%d body=%s", rec.Code, got)

	// An image we neither built nor allowlisted is unexplained: it must be
	// reported as a shadow change, not silently blessed.
	if strings.Contains(got, `"compliant":true`) {
		t.Fatalf("LEAK: inherited another tenant's provenance — green verdict for an unbuilt image: %s", got)
	}
	var linkedToTheirs int
	if err := pool.QueryRow(`SELECT count(*) FROM snapshot_artifacts sa
	                         JOIN environment_snapshots s ON s.id = sa.snapshot_id
	                         WHERE s.environment_id=$1 AND sa.artifact_sha256=$2`,
		myEnv, digest).Scan(&linkedToTheirs); err != nil {
		t.Fatalf("count: %v", err)
	}
	if linkedToTheirs != 0 {
		t.Fatalf("LEAK: linked our snapshot to another tenant's artifact row")
	}
}

// The legitimate path must survive all of the above.
func TestReportAttestationStillWorksOnYourOwnTrail(t *testing.T) {
	pool := trailProbeDB(t)
	mine := uuid.New()
	mustExec(t, pool, `INSERT INTO organizations (id,name) VALUES ($1,$2)`, mine, "mine-"+mine.String()[:8])
	flow, trail := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO flows (id,org_id,name) VALUES ($1,$2,'my-svc')`, flow, mine)
	mustExec(t, pool, `INSERT INTO trails (id,flow_id,name) VALUES ($1,$2,'my-build')`, trail, flow)
	digest := strings.Repeat("12", 32)
	mustExec(t, pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type)
	                   VALUES ($1,$2,$3,'my-image','container')`, digest, mine, trail)
	t.Cleanup(func() { pool.Exec(`DELETE FROM organizations WHERE id=$1`, mine) })

	srv := NewServer(pool, nil, nil)
	if rec := postAttestation(t, srv, mine,
		`{"trail_id":"`+trail.String()+`","name":"unit-tests","type_name":"test","payload":"{\"ok\":true}"}`); rec.Code != http.StatusCreated {
		t.Fatalf("own-trail attestation should be 201, got %d: %s", rec.Code, rec.Body.String())
	}
	// And resolving through our OWN digest must still work (fides attest sbom
	// omits --trail and relies on this).
	if rec := postAttestation(t, srv, mine,
		`{"artifact_sha256":"`+digest+`","name":"sbom","type_name":"sbom","payload":"{\"ok\":true}"}`); rec.Code != http.StatusCreated {
		t.Fatalf("own-digest attestation should be 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

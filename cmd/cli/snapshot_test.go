package main

import "testing"

func TestDockerSnapshotArtifacts(t *testing.T) {
	ps := "abc123\tweb\ndef456\tdb\n\nghi789\tbroken\n"
	inspect := func(id string) (string, error) {
		switch id {
		case "abc123":
			return "sha256:deadbeef\n", nil
		case "def456":
			return "sha256:cafebabe", nil
		default:
			return "", errFake
		}
	}
	got := dockerSnapshotArtifacts(ps, inspect)
	if len(got) != 2 {
		t.Fatalf("got %d artifacts, want 2 (broken container skipped): %+v", len(got), got)
	}
	if got[0]["sha256"] != "deadbeef" || got[0]["service_name"] != "web" {
		t.Errorf("artifact[0] = %+v, want sha256=deadbeef service_name=web (sha256: prefix stripped)", got[0])
	}
	if got[1]["sha256"] != "cafebabe" || got[1]["service_name"] != "db" {
		t.Errorf("artifact[1] = %+v, want sha256=cafebabe service_name=db", got[1])
	}
}

type fakeErr struct{}

func (fakeErr) Error() string { return "no such container" }

var errFake = fakeErr{}

package main

import (
	"strings"
	"testing"
)

func TestAvgCoverage(t *testing.T) {
	m := dashModel{cov: covResp{Controls: []covControl{
		{Control: "a", Coverage: 1.0},
		{Control: "b", Coverage: 0.0},
		{Control: "c", Coverage: 0.5},
	}}}
	if got := m.avgCoverage(); got != 0.5 {
		t.Fatalf("avgCoverage = %v, want 0.5", got)
	}
	if got := (dashModel{}).avgCoverage(); got != 0 {
		t.Fatalf("empty avgCoverage = %v, want 0", got)
	}
}

func TestCoverageBarFill(t *testing.T) {
	// 50% of a 10-wide bar => 5 filled, 5 empty; clamps out-of-range input.
	cases := []struct {
		pct                   float64
		wantFull, wantEmpty   int
	}{
		{0.5, 5, 5},
		{0.0, 0, 10},
		{1.0, 10, 0},
		{1.5, 10, 0},  // clamp high
		{-0.5, 0, 10}, // clamp low
	}
	for _, c := range cases {
		out := coverageBar("ctrl", c.pct, 10)
		if f := strings.Count(out, "█"); f != c.wantFull {
			t.Errorf("pct=%v full=%d want %d", c.pct, f, c.wantFull)
		}
		if e := strings.Count(out, "░"); e != c.wantEmpty {
			t.Errorf("pct=%v empty=%d want %d", c.pct, e, c.wantEmpty)
		}
	}
}

func TestStatVal(t *testing.T) {
	if got := statVal(true, nil, "7"); got != "7" {
		t.Errorf("loaded => %q, want 7", got)
	}
	if got := statVal(false, nil, "7"); got != "…" {
		t.Errorf("unloaded => %q, want …", got)
	}
	if got := statVal(true, errTest{}, "7"); got != "—" {
		t.Errorf("error => %q, want —", got)
	}
}

func TestBoundedDetailCaps(t *testing.T) {
	e := envView{
		Drifts:        []string{"d1", "d2", "d3"},
		ShadowChanges: []string{"s1", "s2", "s3"},
	}
	got := boundedDetail(e) // 6 entries, cap 4 => 4 + "… and 2 more"
	if len(got) != 5 {
		t.Fatalf("boundedDetail len = %d, want 5", len(got))
	}
	if got[0] != "drift: d1" { // drifts come before shadows
		t.Fatalf("first detail = %q, want 'drift: d1'", got[0])
	}
	if last := got[4]; !strings.Contains(last, "2 more") {
		t.Fatalf("last line = %q, want overflow marker", last)
	}
	// Under the cap: no overflow marker.
	if n := len(boundedDetail(envView{Drifts: []string{"only"}})); n != 1 {
		t.Fatalf("single-drift len = %d, want 1", n)
	}
}

func TestEnvLineStatus(t *testing.T) {
	if s := envLine(envView{Name: "prod", Type: "k8s"}); !strings.Contains(s, "compliant") {
		t.Errorf("clean env => %q, want compliant", s)
	}
	drift := envLine(envView{Name: "stg", Type: "k8s", Drifts: []string{"x"}, ShadowChanges: []string{"y", "z"}})
	if !strings.Contains(drift, "1 drift") || !strings.Contains(drift, "2 shadow") {
		t.Errorf("drift env => %q, want '1 drift, 2 shadow'", drift)
	}
}

type errTest struct{}

func (errTest) Error() string { return "boom" }

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

type errTest struct{}

func (errTest) Error() string { return "boom" }

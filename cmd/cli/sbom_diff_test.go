package main

import (
	"testing"

	"fides/pkg/evidence"
)

func comp(name, version string) evidence.Component {
	return evidence.Component{Name: name, Version: version}
}

func TestDiffSBOM(t *testing.T) {
	oldC := []evidence.Component{comp("a", "1.0"), comp("b", "2.0"), comp("c", "3.0")}
	newC := []evidence.Component{comp("a", "1.0"), comp("b", "2.1"), comp("d", "4.0")}

	d := diffSBOM(oldC, newC)

	if len(d.Added) != 1 || d.Added[0].Name != "d" {
		t.Errorf("added = %+v, want [d]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Name != "c" {
		t.Errorf("removed = %+v, want [c]", d.Removed)
	}
	if len(d.Changed) != 1 || d.Changed[0].Name != "b" || d.Changed[0].From != "2.0" || d.Changed[0].To != "2.1" {
		t.Errorf("changed = %+v, want [b 2.0->2.1]", d.Changed)
	}
}

func TestDiffSBOMIdentical(t *testing.T) {
	c := []evidence.Component{comp("x", "1"), comp("y", "2")}
	d := diffSBOM(c, c)
	if n := len(d.Added) + len(d.Removed) + len(d.Changed); n != 0 {
		t.Errorf("identical SBOMs should show no changes, got %d", n)
	}
}

// A version bump is one "changed", not an add+remove.
func TestDiffSBOMVersionBumpIsChange(t *testing.T) {
	d := diffSBOM([]evidence.Component{comp("pkg", "1.0")}, []evidence.Component{comp("pkg", "1.1")})
	if len(d.Added) != 0 || len(d.Removed) != 0 || len(d.Changed) != 1 {
		t.Errorf("version bump should be a single change, got added=%d removed=%d changed=%d",
			len(d.Added), len(d.Removed), len(d.Changed))
	}
}

func TestDiffSBOMNameCaseInsensitive(t *testing.T) {
	d := diffSBOM([]evidence.Component{comp("Foo", "1")}, []evidence.Component{comp("foo", "1")})
	if len(d.Added)+len(d.Removed)+len(d.Changed) != 0 {
		t.Errorf("name match should be case-insensitive, got %+v", d)
	}
}

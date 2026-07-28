package main

import (
	"reflect"
	"testing"
)

func set(cves ...string) map[string]bool {
	m := map[string]bool{}
	for _, c := range cves {
		m[c] = true
	}
	return m
}

func TestDiffCVEs(t *testing.T) {
	base := set("CVE-2021-0001", "CVE-2021-0002")
	cur := set("CVE-2021-0002", "CVE-2022-9999")

	added, fixed := diffCVEs(base, cur)

	if !reflect.DeepEqual(added, []string{"CVE-2022-9999"}) {
		t.Errorf("added = %v, want [CVE-2022-9999]", added)
	}
	if !reflect.DeepEqual(fixed, []string{"CVE-2021-0001"}) {
		t.Errorf("fixed = %v, want [CVE-2021-0001]", fixed)
	}
}

func TestDiffCVEsNoChange(t *testing.T) {
	s := set("CVE-2021-0001")
	added, fixed := diffCVEs(s, s)
	if len(added) != 0 || len(fixed) != 0 {
		t.Errorf("identical sets should have no delta, got added=%v fixed=%v", added, fixed)
	}
}

// The CVE regex must pull identifiers out of finding strings like
// "CRITICAL: CVE-2021-44228".
func TestCVERegex(t *testing.T) {
	got := cliCVERe.FindAllString("CRITICAL: CVE-2021-44228 in log4j; HIGH: CVE-2022-1234", -1)
	want := []string{"CVE-2021-44228", "CVE-2022-1234"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("regex = %v, want %v", got, want)
	}
}

package evidence

import (
	"reflect"
	"testing"
)

// The SBOM summary must expose a unique, sorted license set and an unlicensed
// count so a policy rule can gate on licenses via JQ.
func TestParseSBOMLicenseSummary(t *testing.T) {
	bom := []byte(`{
		"bomFormat":"CycloneDX",
		"components":[
			{"name":"a","version":"1","licenses":[{"license":{"id":"MIT"}}]},
			{"name":"b","version":"1","licenses":[{"license":{"id":"Apache-2.0"}}]},
			{"name":"c","version":"1","licenses":[{"license":{"id":"MIT"}}]},
			{"name":"d","version":"1"}
		]
	}`)
	r, err := ParseSBOM(bom)
	if err != nil {
		t.Fatalf("ParseSBOM: %v", err)
	}
	licenses, _ := r.Summary["licenses"].([]string)
	want := []string{"Apache-2.0", "MIT"} // unique + sorted
	if !reflect.DeepEqual(licenses, want) {
		t.Errorf("licenses = %v, want %v", licenses, want)
	}
	if r.Summary["unlicensed"] != 1 {
		t.Errorf("unlicensed = %v, want 1", r.Summary["unlicensed"])
	}
	if r.Summary["components"] != 4 {
		t.Errorf("components = %v, want 4", r.Summary["components"])
	}
}

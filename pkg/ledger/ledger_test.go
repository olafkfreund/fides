package ledger

import "testing"

// build constructs a valid chain from payloads.
func build(trail string, payloads []string) []Entry {
	var entries []Entry
	prev := ""
	for i, p := range payloads {
		ch := ContentHash(trail, "att", "type", p, true, prev)
		entries = append(entries, Entry{TrailID: trail, Name: "att", TypeName: "type", Payload: p, IsCompliant: true, ContentHash: ch, PrevHash: prev})
		prev = ch
		_ = i
	}
	return entries
}

func TestVerifyValidChain(t *testing.T) {
	v := Verify(build("t1", []string{"a", "b", "c"}))
	if !v.Valid || v.Count != 3 || v.BrokenAt != -1 {
		t.Fatalf("expected valid chain of 3, got %+v", v)
	}
}

func TestVerifyDetectsTamperedPayload(t *testing.T) {
	e := build("t1", []string{"a", "b", "c"})
	e[1].Payload = "b-tampered" // mutate content without recomputing the hash
	v := Verify(e)
	if v.Valid || v.BrokenAt != 1 {
		t.Fatalf("expected break at index 1, got %+v", v)
	}
}

func TestVerifyDetectsDeletion(t *testing.T) {
	e := build("t1", []string{"a", "b", "c"})
	e = append(e[:1], e[2:]...) // delete the middle entry; entry c's prev now dangles
	v := Verify(e)
	if v.Valid || v.BrokenAt != 1 {
		t.Fatalf("expected break at index 1 after deletion, got %+v", v)
	}
}

func TestVerifyDetectsReorder(t *testing.T) {
	e := build("t1", []string{"a", "b", "c"})
	e[1], e[2] = e[2], e[1]
	v := Verify(e)
	if v.Valid {
		t.Fatalf("reordered chain must be invalid")
	}
}

func TestVerifySkipsLegacyUnhashed(t *testing.T) {
	// A leading legacy (empty-hash) entry must not break a subsequent valid chain.
	e := []Entry{{TrailID: "t", ContentHash: ""}}
	e = append(e, build("t", []string{"a", "b"})...)
	v := Verify(e)
	if !v.Valid || v.Count != 2 {
		t.Fatalf("legacy entries should be skipped, got %+v", v)
	}
}

func TestContentHashDeterministicAndChained(t *testing.T) {
	a := ContentHash("t", "n", "ty", "p", true, "")
	if a != ContentHash("t", "n", "ty", "p", true, "") {
		t.Fatalf("hash must be deterministic")
	}
	if a == ContentHash("t", "n", "ty", "p", true, "prev") {
		t.Fatalf("prev_hash must affect the hash (chaining)")
	}
}

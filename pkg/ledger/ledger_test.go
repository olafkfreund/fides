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

func TestCanonicalJSONV2Numbers(t *testing.T) {
	input := `{"z": -0.00, "n": [9007199254740993, 9007199254740992, -1.2300e-7, 1.234567890123456789, 1.00e+9223372036854775808]}`
	want := `{"n":[9007199254740993,9007199254740992,-1.23e-7,1.234567890123456789,1e9223372036854775808],"z":0}`
	if got := CanonicalJSONV2(input); got != want || CanonicalJSONV2(got) != got {
		t.Fatalf("canonical JSON = %s, want %s", got, want)
	}
	if got := CanonicalJSONV2(`{"n":1} {"n":2}`); got != `{"n":1} {"n":2}` {
		t.Fatalf("invalid JSON was changed to %s", got)
	}
}

func TestVerifyMixedCommitmentFixture(t *testing.T) {
	const legacyHash = "932e4f4d8bbf2a8cd2a46c66451600a214289707a162041cfbf2bc767d52f348"
	const v2Hash = "3c8a3fff3d4df8185323170962d9c214f5244246b306e9dd0434c29db72c9d5f"
	const evidence = `{"size":9007199254740993}`
	legacy := Entry{TrailID: "trail", Name: "att", TypeName: "type", IsCompliant: true,
		Payload: CanonicalJSON(`{"n":9007199254740993}`), ContentHash: legacyHash}
	v2 := Entry{TrailID: "trail", Name: "att", TypeName: "type", IsCompliant: true,
		Payload: `{"n": 9007199254740993.00}`, Version: 2, Evidence: evidence, PrevHash: legacyHash, ContentHash: v2Hash}
	for _, version := range []int{0, 1} {
		legacy.Version = version
		got := Verify([]Entry{{TrailID: "trail"}, legacy, v2})
		want := Verdict{Valid: true, Count: 2, BrokenAt: -1, UnhashedCount: 1, LegacyCount: 1, EvidenceCount: 1}
		if got != want {
			t.Fatalf("legacy version %d: verdict = %+v, want %+v", version, got, want)
		}
	}
	if got := ContentHashV2("trail", "att", "type", `{"n":9.007199254740993e15}`, true, legacyHash, evidence); got != v2Hash {
		t.Fatalf("v2 hash = %q, want %q", got, v2Hash)
	}
	for _, tc := range []struct {
		name   string
		change func(*Entry)
	}{
		{"payload precision", func(e *Entry) { e.Payload = `{"n":9007199254740992}` }},
		{"evidence precision", func(e *Entry) { e.Evidence = `{"size":9007199254740992}` }},
		{"missing evidence", func(e *Entry) { e.Evidence = "" }},
		{"malformed evidence", func(e *Entry) { e.Evidence = "{" }},
		{"null evidence", func(e *Entry) { e.Evidence = "null" }},
		{"noncanonical evidence", func(e *Entry) { e.Evidence = `{"size": 9007199254740993}` }},
		{"hash from legacy domain", func(e *Entry) {
			e.ContentHash = ContentHash(e.TrailID, e.Name, e.TypeName, e.Payload, e.IsCompliant, e.PrevHash)
		}},
		{"missing hash", func(e *Entry) { e.ContentHash = "" }},
		{"wrong previous hash", func(e *Entry) { e.PrevHash = "wrong" }},
		{"unknown version", func(e *Entry) { e.Version, e.ContentHash = 3, "" }},
		{"downgraded version", func(e *Entry) { e.Version = 1 }},
		{"downgraded to unhashed", func(e *Entry) { e.Version, e.ContentHash = 0, "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := v2
			tc.change(&entry)
			if got := Verify([]Entry{legacy, entry}); got.Valid || got.BrokenAt != 1 || got.LegacyCount != 1 || got.EvidenceCount != 0 {
				t.Fatalf("expected failure at the versioned entry, got %+v", got)
			}
		})
	}
}

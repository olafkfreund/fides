// Package ledger provides a per-trail, append-only hash chain over attestations
// so any post-hoc tampering, deletion, or reordering is detectable. Each
// attestation's content_hash covers its content AND the previous entry's hash,
// linking the chain (like a lightweight blockchain / Merkle list).
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
)

// CanonicalJSON normalizes a JSON string (object keys sorted, insignificant
// whitespace removed) so the hash is stable across the round-trip through
// Postgres JSONB storage. Non-JSON input is returned unchanged. Both the insert
// path and the verify path must canonicalize the payload identically.
func CanonicalJSON(s string) string {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return s
	}
	return string(b)
}

// ContentHash computes the chained hash for one attestation. prevHash is the
// content_hash of the previous attestation in the same trail ("" for the first).
func ContentHash(trailID, name, typeName, payload string, isCompliant bool, prevHash string) string {
	h := sha256.New()
	// Length-prefixed fields make the encoding unambiguous (no separator
	// collision between field values).
	for _, f := range []string{trailID, name, typeName, payload, strconv.FormatBool(isCompliant), prevHash} {
		h.Write([]byte(strconv.Itoa(len(f))))
		h.Write([]byte{':'})
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Entry is one link in a trail's chain, in chain order.
type Entry struct {
	TrailID     string
	Name        string
	TypeName    string
	Payload     string
	IsCompliant bool
	ContentHash string
	PrevHash    string
}

// Verdict is the result of verifying a chain.
type Verdict struct {
	Valid    bool   `json:"valid"`
	Count    int    `json:"count"`
	BrokenAt int    `json:"broken_at"` // -1 if valid; else 0-based index of the first bad entry
	Reason   string `json:"reason,omitempty"`
}

// Verify walks the chain in order, checking each entry's prev linkage and that
// its recomputed hash matches the stored content_hash. Entries with an empty
// ContentHash (legacy/unhashed) are skipped without breaking the chain.
func Verify(entries []Entry) Verdict {
	prev := ""
	checked := 0
	for i, e := range entries {
		if strings.TrimSpace(e.ContentHash) == "" {
			continue // legacy attestation recorded before chaining
		}
		if e.PrevHash != prev {
			return Verdict{Valid: false, Count: len(entries), BrokenAt: i, Reason: "prev_hash does not match the previous entry (deletion/reorder)"}
		}
		want := ContentHash(e.TrailID, e.Name, e.TypeName, e.Payload, e.IsCompliant, e.PrevHash)
		if want != e.ContentHash {
			return Verdict{Valid: false, Count: len(entries), BrokenAt: i, Reason: "content_hash does not match recomputed hash (tampering)"}
		}
		prev = e.ContentHash
		checked++
	}
	return Verdict{Valid: true, Count: checked, BrokenAt: -1}
}

// Package ledger provides a per-trail, append-only hash chain over attestations
// so any post-hoc tampering, deletion, or reordering is detectable. Each
// attestation's content_hash covers its content AND the previous entry's hash,
// linking the chain (like a lightweight blockchain / Merkle list).
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
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

// CanonicalJSONV2 normalizes JSON without rounding numbers. Equivalent decimal
// spellings, including those returned by Postgres JSONB, have the same output.
// Non-JSON input is returned unchanged.
func CanonicalJSONV2(s string) string {
	if canonical := canonicalJSONV2(s); canonical != "" {
		return canonical
	}
	return s
}

func canonicalJSONV2(s string) string {
	if !json.Valid([]byte(s)) {
		return ""
	}
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return ""
	}
	b, err := json.Marshal(normalizeNumbers(v))
	if err != nil {
		return ""
	}
	return string(b)
}

func normalizeNumbers(v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, item := range v {
			v[k] = normalizeNumbers(item)
		}
	case []any:
		for i, item := range v {
			v[i] = normalizeNumbers(item)
		}
	case json.Number:
		return normalizeNumber(v)
	}
	return v
}

func normalizeNumber(n json.Number) json.Number {
	s := n.String()
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "-", s[1:]
	}
	var exponent big.Int
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		exponent.SetString(s[i+1:], 10) // The JSON decoder already validated the exponent.
		s = s[:i]
	}
	whole, fraction, _ := strings.Cut(s, ".")
	digits := strings.TrimLeft(whole+fraction, "0")
	if digits == "" {
		return "0"
	}
	// Scale the exponent to a coefficient with one digit before the point.
	exponent.Add(&exponent, big.NewInt(int64(len(digits)-len(fraction)-1)))
	digits = strings.TrimRight(digits, "0")
	if exponent.IsInt64() && exponent.Int64() >= -6 && exponent.Int64() <= 20 {
		point := exponent.Int64() + 1
		if point <= 0 {
			return json.Number(sign + "0." + strings.Repeat("0", int(-point)) + digits)
		}
		if point >= int64(len(digits)) {
			return json.Number(sign + digits + strings.Repeat("0", int(point)-len(digits)))
		}
		return json.Number(sign + digits[:point] + "." + digits[point:])
	}
	if len(digits) > 1 {
		digits = digits[:1] + "." + digits[1:]
	}
	return json.Number(sign + digits + "e" + exponent.String())
}

// ContentHash computes the chained hash for one attestation. prevHash is the
// content_hash of the previous attestation in the same trail ("" for the first).
func ContentHash(trailID, name, typeName, payload string, isCompliant bool, prevHash string) string {
	return hashFields(trailID, name, typeName, payload, strconv.FormatBool(isCompliant), prevHash)
}

// ContentHashV2 canonicalizes the payload with CanonicalJSONV2 and binds it to
// the evidence in a separate hash domain. It returns an empty hash if evidence
// is not a canonical JSON object.
func ContentHashV2(trailID, name, typeName, payload string, isCompliant bool, prevHash, evidence string) string {
	if !strings.HasPrefix(evidence, "{") || canonicalJSONV2(evidence) != evidence {
		return ""
	}
	return hashFields("fides:attestation:v2", trailID, name, typeName, CanonicalJSONV2(payload), strconv.FormatBool(isCompliant), prevHash, evidence)
}

func hashFields(fields ...string) string {
	h := sha256.New()
	// Length-prefixed fields make the encoding unambiguous (no separator
	// collision between field values).
	for _, f := range fields {
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
	Payload     string // Historically canonicalized for versions 0 and 1, raw JSON for version 2.
	IsCompliant bool
	ContentHash string
	PrevHash    string
	Version     int
	Evidence    string // Canonical JSON from CanonicalJSONV2.
}

// Verdict is the result of verifying a chain.
type Verdict struct {
	Valid         bool   `json:"valid"`
	Count         int    `json:"count"`
	BrokenAt      int    `json:"broken_at"` // -1 if valid; else 0-based index of the first bad entry
	Reason        string `json:"reason,omitempty"`
	UnhashedCount int    `json:"unhashed_count"`
	LegacyCount   int    `json:"legacy_count"`
	EvidenceCount int    `json:"evidence_count"`
}

// Verify walks the chain in order, checking each entry's prev linkage and that
// its recomputed hash matches the stored content_hash. Only legacy entries may
// be skipped as unhashed. Coverage counts describe the prefix visited so far.
func Verify(entries []Entry) Verdict {
	prev := ""
	v := Verdict{Valid: true, BrokenAt: -1}
	fail := func(index int, reason string) Verdict {
		v.Valid, v.Count, v.BrokenAt, v.Reason = false, len(entries), index, reason
		return v
	}
	for i, e := range entries {
		var want string
		switch e.Version {
		case 0, 1:
			if e.Evidence != "" {
				return fail(i, "legacy entry contains evidence without a version 2 commitment")
			}
			if strings.TrimSpace(e.ContentHash) == "" {
				v.UnhashedCount++
				continue
			}
			want = ContentHash(e.TrailID, e.Name, e.TypeName, e.Payload, e.IsCompliant, e.PrevHash)
		case 2:
			want = ContentHashV2(e.TrailID, e.Name, e.TypeName, e.Payload, e.IsCompliant, e.PrevHash, e.Evidence)
			if want == "" || strings.TrimSpace(e.ContentHash) == "" {
				return fail(i, "version 2 requires a content hash and canonical evidence")
			}
		default:
			return fail(i, "unknown content hash version")
		}
		if e.PrevHash != prev {
			return fail(i, "prev_hash does not match the previous entry (deletion/reorder)")
		}
		if want != e.ContentHash {
			return fail(i, "content_hash does not match recomputed hash (tampering)")
		}
		prev = e.ContentHash
		v.Count++
		if e.Version == 2 {
			v.EvidenceCount++
		} else {
			v.LegacyCount++
		}
	}
	return v
}

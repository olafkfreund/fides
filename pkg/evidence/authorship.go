package evidence

import (
	"regexp"
	"strings"
)

// Authorship captures who — or what — produced a change, parsed from git commit
// trailers. It powers the code.authorship attestation: AI-authored changes must
// carry a human reviewer to be compliant, so the change gate can require human
// review of agent-generated code (issue #295).
type Authorship struct {
	Commit         string   `json:"commit,omitempty"`
	AuthorKind     string   `json:"author_kind"` // "human" | "ai_agent"
	AgentSessionID string   `json:"agent_session_id,omitempty"`
	Model          string   `json:"model,omitempty"`
	Tool           string   `json:"tool,omitempty"`
	HumanReviewer  string   `json:"human_reviewer,omitempty"`
	CoAuthors      []string `json:"co_authors,omitempty"`
}

// trailerRe matches "Key: value" git trailer lines (key is letters/hyphens).
var trailerRe = regexp.MustCompile(`(?im)^([A-Za-z][A-Za-z-]*):[ \t]*(.+?)[ \t]*$`)

// aiSignals are case-insensitive substrings in a Co-Authored-By trailer that
// mark an AI-agent co-author.
var aiSignals = []string{"claude", "anthropic.com", "copilot", "cursor", "gpt", "gemini"}

// ParseAuthorship extracts authorship from a git commit message (subject + body
// + trailers). author_kind is "ai_agent" when an agent-session trailer (e.g.
// "Claude-Session:") or an AI co-author is present, otherwise "human".
func ParseAuthorship(commitMessage string) Authorship {
	a := Authorship{AuthorKind: "human"}
	for _, m := range trailerRe.FindAllStringSubmatch(commitMessage, -1) {
		key, val := strings.ToLower(m[1]), strings.TrimSpace(m[2])
		switch {
		case key == "co-authored-by":
			a.CoAuthors = append(a.CoAuthors, val)
			if isAISignal(val) {
				a.AuthorKind = "ai_agent"
				if a.Model == "" {
					a.Model = coAuthorName(val)
				}
			}
		case key == "reviewed-by":
			if a.HumanReviewer == "" {
				a.HumanReviewer = val
			}
		case strings.HasSuffix(key, "-session"):
			// An agent-session trailer, e.g. "Claude-Session:" / "Agent-Session:".
			a.AuthorKind = "ai_agent"
			a.AgentSessionID = val
			if a.Tool == "" {
				a.Tool = strings.TrimSuffix(key, "-session")
			}
		}
	}
	return a
}

func isAISignal(s string) bool {
	ls := strings.ToLower(s)
	for _, sig := range aiSignals {
		if strings.Contains(ls, sig) {
			return true
		}
	}
	return false
}

// coAuthorName returns the name portion of a "Name <email>" co-author string.
func coAuthorName(s string) string {
	if i := strings.IndexByte(s, '<'); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// Compliant reports whether the change satisfies the AI-authorship control.
// It is an allow-list and fails closed: a human-authored change passes, an
// AI-authored change passes only with a human reviewer, and anything else — an
// unknown or missing author_kind (e.g. a hand-crafted payload posted straight to
// the attestation endpoint) — is treated as non-compliant so it cannot bypass
// the gate.
func (a Authorship) Compliant() bool {
	switch a.AuthorKind {
	case "human":
		return true
	case "ai_agent":
		return a.HumanReviewer != ""
	default:
		return false
	}
}

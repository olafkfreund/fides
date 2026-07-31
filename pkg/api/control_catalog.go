package api

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// The Fides control catalog: an authored, versioned reference of standard SDLC
// controls — each with a preventive/detective type, lifecycle area, MUST/SHOULD
// requirements, the risks it mitigates, how Fides evidences it, and per-clause
// framework references with a rationale note. This is the browseable governance
// layer that sits on top of the enforcement engine (change-gate, attestations,
// drift). Static reference data, embedded at build time.
//
//go:embed control_catalog.json
var controlCatalogJSON []byte

type catalogFrameworkRef struct {
	Framework string `json:"framework"`
	Clause    string `json:"clause"`
	Note      string `json:"note"`
}

type catalogControl struct {
	Code          string                `json:"code"`
	Title         string                `json:"title"`
	Type          string                `json:"type"`  // preventive | detective
	Area          string                `json:"area"`  // build | release | runtime | change | lifecycle
	Level         int                   `json:"level"` // criticality tier at which it applies (1..3)
	Summary       string                `json:"summary"`
	Requirements  []string              `json:"requirements"`
	Mitigates     []string              `json:"mitigates"`
	FidesEvidence []string              `json:"fides_evidence"`
	FrameworkRefs []catalogFrameworkRef `json:"framework_refs"`
}

type controlCatalog struct {
	Version  string           `json:"version"`
	Controls []catalogControl `json:"controls"`
}

// loadControlCatalog parses the embedded catalog. It panics on a malformed
// catalog so a broken edit fails the build/boot, not a request (a test also
// guards the parse + shape).
func loadControlCatalog() controlCatalog {
	var c controlCatalog
	if err := json.Unmarshal(controlCatalogJSON, &c); err != nil {
		panic("control_catalog.json is invalid: " + err.Error())
	}
	return c
}

var parsedControlCatalog = loadControlCatalog()

// handleControlCatalog serves the catalog, optionally filtered by
// ?framework=SOC2, ?area=build, ?type=preventive (case-insensitive).
func (s *Server) handleControlCatalog(w http.ResponseWriter, r *http.Request) {
	fw := strings.ToLower(r.URL.Query().Get("framework"))
	area := strings.ToLower(r.URL.Query().Get("area"))
	typ := strings.ToLower(r.URL.Query().Get("type"))
	tier := 0 // ?tier=N -> only controls whose level <= N (tier-appropriate set)
	if v := r.URL.Query().Get("tier"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			tier = n
		}
	}

	out := controlCatalog{Version: parsedControlCatalog.Version, Controls: []catalogControl{}}
	for _, c := range parsedControlCatalog.Controls {
		if tier > 0 && c.Level > tier {
			continue
		}
		if area != "" && strings.ToLower(c.Area) != area {
			continue
		}
		if typ != "" && strings.ToLower(c.Type) != typ {
			continue
		}
		if fw != "" {
			matched := false
			for _, ref := range c.FrameworkRefs {
				if strings.ToLower(ref.Framework) == fw {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		out.Controls = append(out.Controls, c)
	}
	writeJSON(w, out)
}

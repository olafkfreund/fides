package api

import "net/http"

// The "Secure SDLC" view: the control catalog grouped into the three lifecycle
// phases (Build / Process / Runtime), generated from the catalog so it stays in
// sync — the authored "this is our secure SDLC" document as live data, not prose.
var sdlcPhases = []struct {
	Name  string
	Blurb string
	Areas []string
}{
	{"Secure Build", "How artifacts are produced: provenance, dependencies, and a controlled toolchain.", []string{"build"}},
	{"Secure Process", "How a change is reviewed, gated, and recorded before it ships.", []string{"release", "change"}},
	{"Secure Runtime", "What actually runs and how drift from the approved state is detected.", []string{"runtime", "lifecycle"}},
}

type sdlcPhaseView struct {
	Name       string           `json:"name"`
	Blurb      string           `json:"blurb"`
	Preventive int              `json:"preventive"`
	Detective  int              `json:"detective"`
	Controls   []catalogControl `json:"controls"`
}

// handleSDLC returns the catalog controls grouped by SDLC phase, with a
// preventive/detective count per phase (readiness at a glance).
func (s *Server) handleSDLC(w http.ResponseWriter, r *http.Request) {
	out := struct {
		Version string          `json:"version"`
		Phases  []sdlcPhaseView `json:"phases"`
	}{Version: parsedControlCatalog.Version}

	for _, ph := range sdlcPhases {
		pv := sdlcPhaseView{Name: ph.Name, Blurb: ph.Blurb, Controls: []catalogControl{}}
		for _, c := range parsedControlCatalog.Controls {
			for _, a := range ph.Areas {
				if c.Area == a {
					pv.Controls = append(pv.Controls, c)
					if c.Type == "preventive" {
						pv.Preventive++
					} else {
						pv.Detective++
					}
					break
				}
			}
		}
		out.Phases = append(out.Phases, pv)
	}
	writeJSON(w, out)
}

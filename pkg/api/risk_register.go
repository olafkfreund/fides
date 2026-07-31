package api

import (
	_ "embed"
	"encoding/json"
	"net/http"
)

// The Fides risk register: an authored list of the risks the SDLC controls
// exist to reduce. Each control in the catalog declares which risks it
// mitigates; this register is the other half of that bidirectional map. The
// control links are DERIVED from the catalog at serve time, so the two can't
// drift. Risks with no mapped control surface as coverage gaps — that is the
// register doing its job.
//
//go:embed risk_register.json
var riskRegisterJSON []byte

type riskEntry struct {
	Key           string   `json:"key"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	AttackVectors []string `json:"attack_vectors"`
	Consequences  []string `json:"consequences"`
}

type riskRegister struct {
	Version string      `json:"version"`
	Risks   []riskEntry `json:"risks"`
}

type mitigatingControl struct {
	Code  string `json:"code"`
	Title string `json:"title"`
	Type  string `json:"type"`
}

type riskView struct {
	riskEntry
	MitigatedBy []mitigatingControl `json:"mitigated_by"`
}

func loadRiskRegister() riskRegister {
	var reg riskRegister
	if err := json.Unmarshal(riskRegisterJSON, &reg); err != nil {
		panic("risk_register.json is invalid: " + err.Error())
	}
	return reg
}

var parsedRiskRegister = loadRiskRegister()

// controlsMitigating returns the catalog controls that declare they mitigate
// the given risk key.
func controlsMitigating(riskKey string) []mitigatingControl {
	out := []mitigatingControl{}
	for _, c := range parsedControlCatalog.Controls {
		for _, m := range c.Mitigates {
			if m == riskKey {
				out = append(out, mitigatingControl{Code: c.Code, Title: c.Title, Type: c.Type})
				break
			}
		}
	}
	return out
}

// handleRiskRegister serves the risk register, each risk annotated with the
// catalog controls that mitigate it (derived, so it never drifts).
func (s *Server) handleRiskRegister(w http.ResponseWriter, r *http.Request) {
	out := struct {
		Version string     `json:"version"`
		Risks   []riskView `json:"risks"`
	}{Version: parsedRiskRegister.Version, Risks: []riskView{}}
	for _, risk := range parsedRiskRegister.Risks {
		out.Risks = append(out.Risks, riskView{
			riskEntry:   risk,
			MitigatedBy: controlsMitigating(risk.Key),
		})
	}
	writeJSON(w, out)
}

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"fides/pkg/ai"
	"fides/pkg/auth"
)

func (s *Server) handleListAIAssessments(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Scope to the caller's tenant via attestation -> trail -> flow -> org.
	page, ok := newListPage(w, r, orgID, timeKey("la.created_at"), uuidKey("la.id"), true)
	if !ok {
		return
	}
	query := `SELECT la.id, att.name, la.model_provider, la.model_name, la.assessment_raw, la.compliance_score, la.created_at /* page keys */
	          FROM llm_assessments la
	          JOIN attestations att ON la.attestation_id = att.id
	          JOIN trails tr ON att.trail_id = tr.id
	          JOIN flows f ON tr.flow_id = f.id
	          WHERE f.org_id = $1`
	rows, err := s.queryPage(r, page, query, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	type AssessmentView struct {
		ID              string    `json:"id"`
		AttestationName string    `json:"attestationName"`
		ModelProvider   string    `json:"modelProvider"`
		ModelName       string    `json:"modelName"`
		AssessmentRaw   string    `json:"assessmentRaw"`
		ComplianceScore int       `json:"complianceScore"`
		CreatedAt       time.Time `json:"createdAt"`
	}

	list := []*AssessmentView{}
	for rows.Next() {
		var av AssessmentView
		if err := rows.Scan(&av.ID, &av.AttestationName, &av.ModelProvider, &av.ModelName, &av.AssessmentRaw, &av.ComplianceScore, &av.CreatedAt); err != nil {
			internalError(w, err)
			return
		}
		list = append(list, &av)
	}
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}

	page.write(w, list)
}

type generatePolicyReq struct {
	Framework   string `json:"framework"`
	Description string `json:"description"`
}

func (s *Server) handleAIGeneratePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req generatePolicyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	description := "LLM Generated Policy"
	controls := []map[string]any{{
		"name":             "vulnerability-check",
		"attestation_type": "snyk-scan",
		"jq_expressions":   []string{".vulnerabilities.critical == 0"},
	}}
	if s.LLM == nil {
		controls = append(controls, map[string]any{
			"name":             "unit-test-verification",
			"attestation_type": "junit",
			"jq_expressions":   []string{".failures == 0", ".errors == 0"},
		})
	} else {
		rawResponse, err := s.LLM.GeneratePolicy(r.Context(), req.Framework, req.Description)
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(rawResponse))
			return
		}
		description = "LLM Fallback Policy"
	}

	writeJSON(w, map[string]any{
		"name":        req.Framework + "-compliance-policy",
		"description": fmt.Sprintf("%s for %s compliance: %s", description, req.Framework, req.Description),
		"rules":       map[string]any{"controls": controls},
	})
}

// handleAILintPolicy reviews a policy's jq-rules JSON for syntax errors and best
// practices and returns a corrected version. With an LLM configured it asks the
// model to fix and explain; without one it falls back to a deterministic JSON
// validity check + pretty-print so the button is always useful.
func (s *Server) handleAILintPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Rules string `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if strings.TrimSpace(req.Rules) == "" {
		http.Error(w, "rules are required", http.StatusBadRequest)
		return
	}

	// Deterministic baseline used both as the no-LLM fallback and to detect change.
	var parsed any
	validJSON := json.Unmarshal([]byte(req.Rules), &parsed) == nil

	if s.LLM == nil {
		if !validJSON {
			writeJSON(w, map[string]any{"fixed": req.Rules, "changed": false,
				"notes": "Invalid JSON, and the AI reviewer is not configured. Fix the syntax (matching braces/brackets, quoted keys) and try again."})
			return
		}
		pretty, _ := json.MarshalIndent(parsed, "", "  ")
		writeJSON(w, map[string]any{"fixed": string(pretty), "changed": string(pretty) != req.Rules,
			"notes": "AI reviewer not configured — validated and formatted the JSON. No best-practice rewrite performed."})
		return
	}

	prompt := "You are reviewing a Fides compliance policy expressed as JSON containing jq rules. " +
		"The expected shape is {\"controls\":[{\"name\":\"...\",\"attestation_type\":\"...\",\"jq_expressions\":[\"...\"]}]} " +
		"(a bare {\"jq\":[...]} form is also valid). Check for JSON syntax errors and jq best practices: " +
		"valid structure, well-formed jq expressions, no duplicate/redundant rules, sensible names. " +
		"Respond with ONLY a JSON object, no markdown fences: " +
		"{\"fixed\": \"<the corrected policy as a JSON string>\", \"notes\": \"<short summary of what you changed, or why it's already fine>\"}.\n\nPolicy:\n" + req.Rules

	resp, err := s.LLM.Chat(r.Context(), nil, prompt)
	if err != nil {
		internalError(w, err)
		return
	}
	// Strip accidental markdown fences, then try to parse the model's {fixed,notes}.
	clean := strings.TrimSpace(resp)
	clean = strings.TrimPrefix(clean, "```json")
	clean = strings.TrimPrefix(clean, "```")
	clean = strings.TrimSuffix(clean, "```")
	clean = strings.TrimSpace(clean)
	var out struct {
		Fixed string `json:"fixed"`
		Notes string `json:"notes"`
	}
	if json.Unmarshal([]byte(clean), &out) == nil && strings.TrimSpace(out.Fixed) != "" {
		writeJSON(w, map[string]any{"fixed": out.Fixed, "notes": out.Notes, "changed": out.Fixed != req.Rules})
		return
	}
	// Model didn't return the expected envelope — surface its text as notes and
	// keep the user's input unchanged.
	writeJSON(w, map[string]any{"fixed": req.Rules, "changed": false, "notes": strings.TrimSpace(resp)})
}

type aiChatReq struct {
	Message string           `json:"message"`
	History []ai.ChatMessage `json:"history"`
}

type aiChatResp struct {
	Response string `json:"response"`
}

func (s *Server) handleAIChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req aiChatReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	ctx := r.Context()
	userMsg := req.Message
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var answer string
	var executionOutput string

	var flowName, flowDesc string
	if n, _ := fmt.Sscanf(userMsg, "create flow %s description %s", &flowName, &flowDesc); n >= 1 {
		if !requireMutationRole(w, r, auth.RoleAdmin) {
			return
		}
		flowID := uuid.New()
		query := `INSERT INTO flows (id, org_id, name, description, tags, created_at, updated_at) VALUES ($1, $2, $3, $4, '{}'::jsonb, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
		_, err := s.q(ctx).ExecContext(ctx, query, flowID, orgID, flowName, flowDesc)
		if err != nil {
			executionOutput = fmt.Sprintf("\n*(Failed to create flow: %v)*", err)
		} else {
			executionOutput = fmt.Sprintf("\n*(Flow '%s' successfully created with ID: %s)*", flowName, flowID)
		}
	} else if n, _ := fmt.Sscanf(userMsg, "create flow %s", &flowName); n == 1 {
		if !requireMutationRole(w, r, auth.RoleAdmin) {
			return
		}
		flowID := uuid.New()
		query := `INSERT INTO flows (id, org_id, name, description, tags, created_at, updated_at) VALUES ($1, $2, $3, 'Created via LLM Assistant', '{}'::jsonb, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
		_, err := s.q(ctx).ExecContext(ctx, query, flowID, orgID, flowName)
		if err != nil {
			executionOutput = fmt.Sprintf("\n*(Failed to create flow: %v)*", err)
		} else {
			executionOutput = fmt.Sprintf("\n*(Flow '%s' successfully created with ID: %s)*", flowName, flowID)
		}
	}

	// Deterministic commands are answered directly (fast, no LLM). Only freeform
	// questions hit the LLM, and with a timeout so a slow/unreachable model
	// returns a friendly message instead of hanging until the gateway 504s.
	lower := strings.ToLower(strings.TrimSpace(userMsg))
	switch {
	case flowName != "":
		answer = fmt.Sprintf("I've created a new compliance pipeline flow named **%s** for tracking your software components.", flowName)
	case lower == "list flows" || lower == "show flows":
		rows, err := s.q(ctx).QueryContext(ctx, "SELECT name, COALESCE(description, '') FROM flows WHERE org_id = $1", orgID)
		if err != nil {
			internalError(w, err)
			return
		}
		defer rows.Close()
		answer = "Here are the currently configured compliance flows in Fides:\n\n"
		for rows.Next() {
			var name, desc string
			if err := rows.Scan(&name, &desc); err != nil {
				continue
			}
			answer += fmt.Sprintf("- **%s**: %s\n", name, desc)
		}
		// A failed iteration must not read as a short result.
		if err := rows.Err(); err != nil {
			internalError(w, err)
			return
		}
	case lower == "find failing trails" || lower == "failing builds":
		query := `SELECT t.name, f.name, att.name, att.type_name
		          FROM attestations att
		          JOIN trails t ON att.trail_id = t.id
		          JOIN flows f ON t.flow_id = f.id
		          WHERE att.is_compliant = false AND f.org_id = $1`
		rows, err := s.q(ctx).QueryContext(ctx, query, orgID)
		if err != nil {
			internalError(w, err)
			return
		}
		defer rows.Close()
		answer = "### Non-Compliant Trails Alert\nI scanned the trails database and found the following non-compliant build items:\n\n"
		found := false
		for rows.Next() {
			var tName, fName, attName, typeName string
			if err := rows.Scan(&tName, &fName, &attName, &typeName); err != nil {
				continue
			}
			answer += fmt.Sprintf("- **Flow `%s` / Build `%s`**: Failed control `%s` (Type: `%s`)\n", fName, tName, attName, typeName)
			found = true
		}
		// A failed iteration must not read as a short result.
		if err := rows.Err(); err != nil {
			internalError(w, err)
			return
		}
		if !found {
			answer = "Great news! All recorded build trails are fully compliant against current policies."
		}
	case s.LLM != nil:
		lctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		a, err := s.LLM.Chat(lctx, req.History, userMsg)
		if err != nil {
			answer = "The assistant model didn't respond in time, or the LLM isn't reachable. You can still use commands like `list flows` or `find failing trails`, or check **Settings → Infrastructure → LLM Configuration**.\n\n_" + err.Error() + "_"
		} else {
			answer = a
		}
	default:
		answer = "Hello! I am **Fides**, your compliance & audit conversational assistant. I can help you configure flows and trails, search failing builds, audit artifacts, and verify SOC 2 or ISO 27001 readiness.\n\nTry asking me:\n- `create flow frontend-service` (Creates a pipeline flow)\n- `list flows` (Displays registered pipelines)\n- `find failing trails` (Audits failing CI/CD builds)"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(aiChatResp{
		Response: answer + executionOutput,
	})
}

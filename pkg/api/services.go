package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type saveServiceReq struct {
	Service      string `json:"service"`
	Owner        string `json:"owner"`
	OnCall       string `json:"on_call"`
	AuditContact string `json:"audit_contact"`
	Tier         int    `json:"tier"` // 1..3 criticality
}

// handleSaveService upserts a service's ownership + criticality tier (org-scoped,
// unique by name). The tier drives which catalog controls apply (level <= tier).
func (s *Server) handleSaveService(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req saveServiceReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if strings.TrimSpace(req.Service) == "" {
		http.Error(w, "service is required", http.StatusBadRequest)
		return
	}
	tier := req.Tier
	if tier < 1 {
		tier = 1
	} else if tier > 3 {
		tier = 3
	}
	var id uuid.UUID
	err := s.q(r.Context()).QueryRowContext(r.Context(),
		`INSERT INTO service_owners (id, org_id, service, owner, on_call, audit_contact, tier, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		 ON CONFLICT (org_id, service) DO UPDATE SET
		   owner = EXCLUDED.owner, on_call = EXCLUDED.on_call,
		   audit_contact = EXCLUDED.audit_contact, tier = EXCLUDED.tier, updated_at = now()
		 RETURNING id`,
		uuid.New(), orgID, req.Service, req.Owner, req.OnCall, req.AuditContact, tier).Scan(&id)
	if err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"id": id, "service": req.Service, "owner": req.Owner, "on_call": req.OnCall,
		"audit_contact": req.AuditContact, "tier": tier,
	})
}

// handleListServices lists the org's services with owners + tier.
func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT service, COALESCE(owner,''), COALESCE(on_call,''), COALESCE(audit_contact,''), tier, updated_at
		 FROM service_owners WHERE org_id = $1 ORDER BY service`, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var svc, owner, onCall, audit string
		var tier int
		var updated time.Time
		if err := rows.Scan(&svc, &owner, &onCall, &audit, &tier, &updated); err != nil {
			internalError(w, err)
			return
		}
		list = append(list, map[string]any{
			"service": svc, "owner": owner, "on_call": onCall, "audit_contact": audit,
			"tier": tier, "updated_at": updated,
		})
	}
	// A failed iteration must not read as a short result.
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}
	writeJSON(w, list)
}

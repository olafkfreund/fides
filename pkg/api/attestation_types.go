package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"fides/pkg/models"
)

type createAttestationTypeReq struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Schema      string   `json:"schema"`
	JQRules     []string `json:"jq_rules"`
}

type patchAttestationTypeReq struct {
	Name        *string         `json:"name"`
	Description *string         `json:"description"`
	Schema      json.RawMessage `json:"schema"`
	JQRules     *[]string       `json:"jq_rules"`
}

const attestationTypeColumns = `id, org_id, name, COALESCE(description, ''), COALESCE(schema::text, ''), jq_rules, created_at`

func scanAttestationType(row interface{ Scan(...any) error }) (models.AttestationType, error) {
	var typ models.AttestationType
	var created sql.NullTime
	err := row.Scan(&typ.ID, &typ.OrgID, &typ.Name, &typ.Description, &typ.Schema, pq.Array(&typ.JQRules), &created)
	typ.CreatedAt = created.Time
	return typ, err
}

func attestationTypeError(w http.ResponseWriter, err error) {
	var pgErr *pq.Error
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.Error(w, "attestation type not found", http.StatusNotFound)
	case errors.As(err, &pgErr) && pgErr.Code == "23505":
		http.Error(w, "attestation type name already exists", http.StatusConflict)
	case pgErr != nil && pgErr.Code.Class() == "22":
		http.Error(w, "attestation type cannot be stored", http.StatusBadRequest)
	default:
		internalError(w, err)
	}
}

func (s *Server) handleCreateAttestationType(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req createAttestationTypeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	if !s.checkAttestationSchema(w, r, req.Schema) {
		return
	}
	typ := models.AttestationType{
		ID: uuid.New(), OrgID: orgID, Name: req.Name, Description: req.Description,
		Schema: req.Schema, JQRules: req.JQRules, CreatedAt: time.Now(),
	}
	_, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO attestation_types (id, org_id, name, description, schema, jq_rules, created_at)
		 VALUES ($1, $2, $3, $4, NULLIF($5, '')::jsonb, $6, $7)`,
		typ.ID, orgID, typ.Name, typ.Description, typ.Schema, pq.Array(typ.JQRules), typ.CreatedAt)
	if err != nil {
		attestationTypeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(typ)
}

func (s *Server) handleListAttestationTypes(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	page, ok := newListPage(w, r, orgID, textKey("name"), uuidKey("id"), false)
	if !ok {
		return
	}
	rows, err := s.queryPage(r, page,
		`SELECT `+attestationTypeColumns+` /* page keys */ FROM attestation_types WHERE org_id = $1`, orgID)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()
	types := []models.AttestationType{}
	for rows.Next() {
		typ, err := scanAttestationType(rows)
		if err != nil {
			internalError(w, err)
			return
		}
		types = append(types, typ)
	}
	if err := rows.Err(); err != nil {
		internalError(w, err)
		return
	}
	page.write(w, types)
}

func attestationTypeScope(w http.ResponseWriter, r *http.Request) (id, orgID uuid.UUID, ok bool) {
	orgID, ok = principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return id, orgID, false
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid attestation type id", http.StatusBadRequest)
		return id, orgID, false
	}
	return id, orgID, true
}

func (s *Server) handleGetAttestationType(w http.ResponseWriter, r *http.Request) {
	id, orgID, ok := attestationTypeScope(w, r)
	if !ok {
		return
	}
	typ, err := scanAttestationType(s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT `+attestationTypeColumns+` FROM attestation_types WHERE id = $1 AND org_id = $2`, id, orgID))
	if err != nil {
		attestationTypeError(w, err)
		return
	}
	writeJSON(w, typ)
}

func (s *Server) handlePatchAttestationType(w http.ResponseWriter, r *http.Request) {
	id, orgID, ok := attestationTypeScope(w, r)
	if !ok {
		return
	}
	var req patchAttestationTypeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	var schema *string
	if req.Schema != nil {
		var definition string
		if err := json.Unmarshal(req.Schema, &definition); err != nil {
			badRequest(w, err)
			return
		}
		if !s.checkAttestationSchema(w, r, definition) {
			return
		}
		schema = &definition
	}
	var rules pq.StringArray
	if req.JQRules != nil {
		rules = *req.JQRules
	}
	typ, err := scanAttestationType(s.q(r.Context()).QueryRowContext(r.Context(),
		`UPDATE attestation_types SET name = COALESCE($3, name), description = COALESCE($4, description),
		   schema = CASE WHEN $5::text IS NULL THEN schema ELSE NULLIF($5, '')::jsonb END,
		   jq_rules = COALESCE($6, jq_rules)
		 WHERE id = $1 AND org_id = $2 RETURNING `+attestationTypeColumns,
		id, orgID, req.Name, req.Description, schema, rules))
	if err != nil {
		attestationTypeError(w, err)
		return
	}
	writeJSON(w, typ)
}

func (s *Server) handleDeleteAttestationType(w http.ResponseWriter, r *http.Request) {
	id, orgID, ok := attestationTypeScope(w, r)
	if !ok {
		return
	}
	err := s.q(r.Context()).QueryRowContext(r.Context(),
		`DELETE FROM attestation_types WHERE id = $1 AND org_id = $2 RETURNING id`, id, orgID).Scan(&id)
	if err != nil {
		attestationTypeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

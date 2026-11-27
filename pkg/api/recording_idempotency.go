package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"fides/pkg/auth"
	"fides/pkg/db"

	"github.com/google/uuid"
)

type recording struct {
	tx          *sql.Tx
	orgID       uuid.UUID
	operationID uuid.UUID
	keyed       bool
	endpoint    string
	fingerprint [sha256.Size]byte
}

// Call after checking ownership. A nil result means the response has been sent.
func (s *Server) beginRecording(w http.ResponseWriter, r *http.Request, payload any, uploads bool) (*recording, *http.Request) {
	op := &recording{}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) == 0 && !uploads {
		return op, r
	}
	if len(keys) != 0 {
		if !requireMutationRole(w, r, auth.RoleWriter) {
			return nil, r
		}
		if len(keys) == 1 && len(keys[0]) == 36 {
			id, err := uuid.Parse(keys[0])
			op.operationID, op.keyed = id, err == nil
		}
		if !op.keyed {
			http.Error(w, "Idempotency-Key must be a UUID", http.StatusBadRequest)
			return nil, r
		}
		data, err := json.Marshal(payload)
		if err != nil {
			internalError(w, err)
			return nil, r
		}
		op.fingerprint = sha256.Sum256(data)
		op.orgID, _ = principalOrg(r)
		op.endpoint = r.URL.Path
	}

	ctx := r.Context()
	txCtx := ctx
	if uploads && op.keyed {
		// Keep the transaction lock until an in-flight storage call has returned.
		txCtx = context.WithoutCancel(ctx)
	}
	tx, err := db.BeginTx(txCtx, s.DB, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		internalError(w, err)
		return nil, r
	}
	op.tx = tx
	keep := false
	defer func() {
		if !keep {
			op.rollback()
		}
	}()
	if op.keyed {
		if _, scoped := db.QuerierFromContext(ctx); !scoped {
			if _, err := tx.ExecContext(ctx, "SELECT set_config('app.current_org', $1, true)", op.orgID.String()); err != nil {
				internalError(w, err)
				return nil, r
			}
		}
		lockKey := "recording:" + op.orgID.String() + ":" + op.operationID.String()
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
			internalError(w, err)
			return nil, r
		}

		var endpoint string
		var fingerprint, response []byte
		err := tx.QueryRowContext(ctx, `SELECT endpoint, fingerprint, response
			FROM recording_operations WHERE org_id = $1 AND operation_id = $2`,
			op.orgID, op.operationID).Scan(&endpoint, &fingerprint, &response)
		switch {
		case err == nil:
			op.rollback()
			if endpoint != op.endpoint || !bytes.Equal(fingerprint, op.fingerprint[:]) {
				http.Error(w, "Idempotency-Key was already used for a different request", http.StatusConflict)
			} else {
				writeRecordingResponse(w, response)
			}
			return nil, r
		case !errors.Is(err, sql.ErrNoRows):
			internalError(w, err)
			return nil, r
		}
	}

	keep = true
	return op, r.WithContext(db.WithQuerier(ctx, tx))
}

func (op *recording) rollback() {
	if op.tx != nil {
		_ = op.tx.Rollback()
	}
}

func (op *recording) created(w http.ResponseWriter, ctx context.Context, value any) bool {
	response, err := json.Marshal(value)
	if err != nil {
		internalError(w, err)
		return false
	}
	response = append(response, '\n')
	if op.keyed {
		if _, err := op.tx.ExecContext(ctx, `INSERT INTO recording_operations
			(org_id, operation_id, endpoint, fingerprint, response) VALUES ($1,$2,$3,$4,$5)`,
			op.orgID, op.operationID, op.endpoint, op.fingerprint[:], response); err != nil {
			internalError(w, err)
			return false
		}
	}
	if op.tx != nil {
		if err := ctx.Err(); err != nil {
			internalError(w, err)
			return false
		}
		if err := op.tx.Commit(); err != nil {
			internalError(w, err)
			return false
		}
	}
	writeRecordingResponse(w, response)
	return true
}

func writeRecordingResponse(w http.ResponseWriter, response []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(response)
}

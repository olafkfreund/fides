package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"fides/pkg/models"
)

const (
	maxAttestationSchemaBytes = 64 << 10
	maxSchemaPayloadBytes     = 1 << 20
	maxSchemaJSONDepth        = 64
	maxSchemaErrors           = 8
	maxSchemaErrorPathBytes   = 256
	schemaWorkerDeadline      = 2 * time.Second
	schemaWorkerMode          = "FIDES_ATTESTATION_SCHEMA_WORKER"
)

var schemaWorkerSlots = make(chan struct{}, 2)

type attestationSchemaJob struct {
	Schema          string
	Payload         *string
	PayloadTooLarge bool
}

type attestationSchemaResult struct {
	SchemaError string
	Reasons     []models.AttestationValidationError
}

// The validator has no cancellation API. A deadline on the child process
// bounds compilation and validation even when a schema expands exponentially.
func runAttestationSchema(ctx context.Context, schema string, payload *string) (attestationSchemaResult, error) {
	if len(schema) > maxAttestationSchemaBytes {
		return attestationSchemaResult{SchemaError: "JSON Schema exceeds the size limit"}, nil
	}
	job := attestationSchemaJob{Schema: schema, Payload: payload}
	if payload != nil && len(*payload) > maxSchemaPayloadBytes {
		job.Payload = nil
		job.PayloadTooLarge = true
	}
	waitCtx, stopWaiting := context.WithTimeout(ctx, schemaWorkerDeadline)
	defer stopWaiting()
	select {
	case schemaWorkerSlots <- struct{}{}:
		defer func() { <-schemaWorkerSlots }()
	case <-waitCtx.Done():
		return attestationSchemaResult{}, fmt.Errorf("waiting for JSON Schema validator: %w", waitCtx.Err())
	}

	executable, err := os.Executable()
	if err != nil {
		return attestationSchemaResult{}, err
	}
	input, err := json.Marshal(job)
	if err != nil {
		return attestationSchemaResult{}, err
	}
	workerCtx, cancel := context.WithTimeout(ctx, schemaWorkerDeadline)
	defer cancel()
	cmd := exec.CommandContext(workerCtx, executable, "--attestation-schema-worker") // #nosec G204 -- executable is this process; argument is fixed.
	cmd.Env = []string{schemaWorkerMode + "=1", "GOMAXPROCS=1", "GORACE=atexit_sleep_ms=0"}
	cmd.Stdin = bytes.NewReader(input)
	var output bytes.Buffer
	cmd.Stdout = &output
	err = cmd.Run()
	if ctx.Err() != nil {
		return attestationSchemaResult{}, ctx.Err()
	}
	stage, result, _ := bytes.Cut(output.Bytes(), []byte{'\n'})
	if bytes.HasPrefix(result, []byte("compiled\n")) {
		stage = []byte("compiled")
		result = result[len("compiled\n"):]
	}
	if err != nil {
		var exit *exec.ExitError
		if workerCtx.Err() == nil && !errors.As(err, &exit) {
			return attestationSchemaResult{}, err
		}
		if string(stage) == "compiled" {
			return attestationSchemaResult{Reasons: schemaReason("schema_work_limit", "JSON Schema validation exceeded its work limit")}, nil
		}
		if string(stage) == "compiling" || workerCtx.Err() != nil {
			return attestationSchemaResult{SchemaError: "JSON Schema compilation exceeded its work limit"}, nil
		}
		return attestationSchemaResult{}, err
	}
	var out attestationSchemaResult
	return out, json.Unmarshal(result, &out)
}

func init() {
	if len(os.Args) != 2 || os.Args[1] != "--attestation-schema-worker" || os.Getenv(schemaWorkerMode) != "1" {
		return
	}
	if err := limitSchemaWorkerResources(); err != nil {
		os.Exit(1)
	}
	debug.SetMemoryLimit(64 << 20)
	debug.SetMaxStack(16 << 20)
	var job attestationSchemaJob
	if err := json.NewDecoder(os.Stdin).Decode(&job); err != nil {
		os.Exit(1)
	}
	if err := writeAttestationSchemaResult(job); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func writeAttestationSchemaResult(job attestationSchemaJob) error {
	numberExpansionBudget := maxAttestationSchemaBytes
	definition, err := parseSchemaJSON(job.Schema, &numberExpansionBudget)
	if err != nil {
		fmt.Fprintln(os.Stdout, "rejected")
		return json.NewEncoder(os.Stdout).Encode(attestationSchemaResult{SchemaError: err.Error()})
	}

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(offlineSchemaLoader{})
	const resource = "https://schemas.fides.invalid/attestation"
	fmt.Fprintln(os.Stdout, "compiling")
	err = compiler.AddResource(resource, definition)
	var schema *jsonschema.Schema
	if err == nil {
		schema, err = compiler.Compile(resource)
	}
	if err != nil {
		return json.NewEncoder(os.Stdout).Encode(attestationSchemaResult{SchemaError: "Invalid JSON Schema or reference to an unavailable schema resource"})
	}
	var result attestationSchemaResult
	if job.PayloadTooLarge {
		result.Reasons = schemaReason("schema_work_limit", "Payload exceeds the JSON Schema validation size limit")
	} else if job.Payload != nil {
		// Mark the transition so a hard stop can distinguish compile and validation limits.
		fmt.Fprintln(os.Stdout, "compiled")
		payload, err := parseSchemaJSON(*job.Payload, nil)
		if err != nil {
			result.Reasons = schemaReason("schema_payload_invalid", err.Error())
		} else if err := schema.Validate(payload); err != nil {
			result.Reasons = schemaValidationReasons(err)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

type offlineSchemaLoader struct{}

func (offlineSchemaLoader) Load(string) (any, error) {
	return nil, errors.New("external JSON Schema resources are disabled")
}

func parseSchemaJSON(raw string, numberExpansionBudget *int) (any, error) {
	value, err := jsonschema.UnmarshalJSON(strings.NewReader(raw))
	if err != nil {
		return nil, errors.New("invalid JSON")
	}
	if err := checkSchemaJSONLimits(value, 0, numberExpansionBudget); err != nil {
		return nil, err
	}
	return value, nil
}

func checkSchemaJSONLimits(value any, depth int, numberExpansionBudget *int) error {
	if depth > maxSchemaJSONDepth {
		return errors.New("JSON exceeds the validation depth limit")
	}
	switch value := value.(type) {
	case []any:
		for _, child := range value {
			if err := checkSchemaJSONLimits(child, depth+1, numberExpansionBudget); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, child := range value {
			if err := checkSchemaJSONLimits(child, depth+1, numberExpansionBudget); err != nil {
				return err
			}
		}
	case json.Number:
		// PostgreSQL expands exponents when it renders JSONB. Bound that work
		// before checking that the stored schema fits the same byte limit.
		notation := value.String()
		if i := strings.IndexAny(notation, "eE"); numberExpansionBudget != nil && i >= 0 {
			exp, err := strconv.ParseInt(notation[i+1:], 10, 32)
			if err != nil || exp > int64(*numberExpansionBudget) || -exp > int64(*numberExpansionBudget) {
				return errors.New("JSON Schema numbers exceed the storage size limit")
			}
			*numberExpansionBudget -= max(int(exp), -int(exp))
		}
	}
	return nil
}

func schemaReason(code, message string) []models.AttestationValidationError {
	return []models.AttestationValidationError{{Code: code, Message: message}}
}

func schemaValidationReasons(err error) []models.AttestationValidationError {
	reasons := schemaReason("schema_validation_failed", "Payload does not satisfy the JSON Schema")
	var invalid *jsonschema.ValidationError
	if !errors.As(err, &invalid) {
		return reasons
	}
	replacer := strings.NewReplacer("~", "~0", "/", "~1")
	var paths []string
	var visit func(*jsonschema.ValidationError)
	visit = func(e *jsonschema.ValidationError) {
		if len(e.Causes) > 0 {
			for _, cause := range e.Causes {
				visit(cause)
			}
			return
		}
		var b strings.Builder
		for _, part := range e.InstanceLocation {
			if len(part)+b.Len()+1 > maxSchemaErrorPathBytes {
				b.Reset()
				break
			}
			b.WriteByte('/')
			b.WriteString(replacer.Replace(part))
		}
		path := b.String()
		if len(path) > maxSchemaErrorPathBytes {
			path = ""
		}
		i, found := slices.BinarySearch(paths, path)
		if !found && i < maxSchemaErrors {
			paths = slices.Insert(paths, i, path)
			if len(paths) > maxSchemaErrors {
				paths = paths[:maxSchemaErrors]
			}
		}
	}
	visit(invalid)
	out := make([]models.AttestationValidationError, 0, len(paths))
	for _, path := range paths {
		reason := reasons[0]
		reason.Path = path
		out = append(out, reason)
	}
	return out
}

func (s *Server) checkAttestationSchema(w http.ResponseWriter, r *http.Request, definition string) bool {
	if definition == "" {
		return true
	}
	result, err := runAttestationSchema(r.Context(), definition, nil)
	if err != nil {
		internalError(w, err)
		return false
	}
	if result.SchemaError != "" {
		http.Error(w, result.SchemaError, http.StatusBadRequest)
		return false
	}
	var storedSize int
	if err := s.q(r.Context()).QueryRowContext(r.Context(), `SELECT octet_length($1::jsonb::text)`, definition).Scan(&storedSize); err != nil {
		attestationTypeError(w, err)
		return false
	}
	if storedSize > maxAttestationSchemaBytes {
		http.Error(w, "Stored JSON Schema exceeds the size limit", http.StatusBadRequest)
		return false
	}
	return true
}

type attestationTypeCheck struct {
	compliant   bool
	reasons     []models.AttestationValidationError
	failedRules []string
}

func (s *Server) evaluateAttestationTypeCompliance(ctx context.Context, orgID uuid.UUID, typeName, payload string) (attestationTypeCheck, error) {
	var rules []string
	var schema sql.NullString
	err := s.q(ctx).QueryRowContext(ctx,
		`SELECT CASE WHEN octet_length(schema::text) > $3 THEN 'null' ELSE schema::text END, jq_rules
		 FROM attestation_types WHERE org_id = $1 AND name = $2`, orgID, typeName, maxAttestationSchemaBytes).Scan(&schema, pq.Array(&rules))
	if errors.Is(err, sql.ErrNoRows) {
		return attestationTypeCheck{compliant: true}, nil
	}
	if err != nil {
		return attestationTypeCheck{}, err
	}
	return s.checkAttestationType(ctx, schema, payload, rules)
}

func (s *Server) checkAttestationType(ctx context.Context, schema sql.NullString, payload string, rules []string) (attestationTypeCheck, error) {
	if schema.Valid {
		result, err := runAttestationSchema(ctx, schema.String, &payload)
		if err != nil {
			return attestationTypeCheck{}, err
		}
		if result.SchemaError != "" {
			return attestationTypeCheck{reasons: schemaReason("schema_configuration_invalid", "Attestation type has an invalid JSON Schema")}, nil
		}
		if len(result.Reasons) != 0 {
			return attestationTypeCheck{reasons: result.Reasons}, nil
		}
	}
	if len(rules) == 0 {
		return attestationTypeCheck{compliant: true}, nil
	}
	ok, failed, err := s.PolicyEngine.EvaluateAttestation(ctx, payload, rules)
	if !ok {
		log.Printf("Compliance check failed for rules: %v", failed)
	}
	return attestationTypeCheck{compliant: ok, failedRules: failed}, err
}

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestAttestationTypeLifecycle(t *testing.T) {
	const id = "d46a8b50-f5a0-414b-83dc-4d60a0cc6302"
	const configuredSchema = `{"type":"object","properties":{"score":{"minimum":1e2}}}`
	const storedSchema = `{"properties": {"score": {"minimum": 100}}, "type": "object"}`
	const itemPath = attestationTypesPath + "/" + id

	remote := attestationTypeResponse{}
	checkPayload := func(r *http.Request, want map[string]any) {
		t.Helper()
		var got map[string]any
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s payload = %v, %v, want %v", r.Method, got, err, want)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+attestationTypesPath, func(w http.ResponseWriter, r *http.Request) {
		checkPayload(r, map[string]any{"name": "release", "description": "", "schema": configuredSchema, "jq_rules": []any{".passed"}})
		remote = attestationTypeResponse{ID: id, Name: "release", Schema: storedSchema, JQRules: []string{".passed"}}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(remote)
	})
	mux.HandleFunc("GET "+itemPath, func(w http.ResponseWriter, _ *http.Request) {
		if remote.ID == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(remote)
	})
	mux.HandleFunc("PATCH "+itemPath, func(w http.ResponseWriter, r *http.Request) {
		if remote.Description == "" {
			checkPayload(r, map[string]any{"description": "Release evidence"})
			remote.Description = "Release evidence"
		} else {
			checkPayload(r, map[string]any{"schema": "", "jq_rules": []any{}})
			remote.Schema = ""
			remote.JQRules = nil
		}
		json.NewEncoder(w).Encode(remote)
	})
	mux.HandleFunc("DELETE "+itemPath, func(w http.ResponseWriter, _ *http.Request) {
		if remote.ID == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		remote = attestationTypeResponse{}
		w.WriteHeader(http.StatusNoContent)
	})
	var remoteMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tenant-token" {
			http.Error(w, "incorrect API token", http.StatusUnauthorized)
			return
		}
		remoteMu.Lock()
		defer remoteMu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	defer server.Close()

	ctx := context.Background()
	res := &attestationTypeResource{}
	res.Configure(ctx, resource.ConfigureRequest{ProviderData: NewClient(server.URL, "tenant-token")}, &resource.ConfigureResponse{})
	var schemaResp resource.SchemaResponse
	res.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	empty := tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)}
	assertOK := func(diags diag.Diagnostics) {
		t.Helper()
		if diags.HasError() {
			t.Fatal(diags)
		}
	}
	plan := func(model attestationTypeModel) tfsdk.Plan {
		state := empty
		assertOK(state.Set(ctx, model))
		return tfsdk.Plan{Schema: state.Schema, Raw: state.Raw}
	}
	model := func(state tfsdk.State) attestationTypeModel {
		var got attestationTypeModel
		assertOK(state.Get(ctx, &got))
		return got
	}
	read := func(state tfsdk.State) tfsdk.State {
		resp := resource.ReadResponse{State: state}
		res.Read(ctx, resource.ReadRequest{State: state}, &resp)
		assertOK(resp.Diagnostics)
		return resp.State
	}
	update := func(state tfsdk.State, requested attestationTypeModel) tfsdk.State {
		resp := resource.UpdateResponse{State: state}
		res.Update(ctx, resource.UpdateRequest{State: state, Plan: plan(requested)}, &resp)
		assertOK(resp.Diagnostics)
		return resp.State
	}

	rules, diags := types.ListValueFrom(ctx, types.StringType, []string{".passed"})
	assertOK(diags)
	desired := attestationTypeModel{
		ID: types.StringUnknown(), Name: types.StringValue("release"), Schema: types.StringValue(configuredSchema), JQRules: rules,
	}
	created := resource.CreateResponse{State: empty}
	res.Create(ctx, resource.CreateRequest{Plan: plan(desired)}, &created)
	assertOK(created.Diagnostics)
	state := read(created.State)
	got := model(state)
	if got.ID.ValueString() != id || got.Schema.ValueString() != configuredSchema || !got.JQRules.Equal(rules) {
		t.Fatalf("unexpected refreshed state: %+v", got)
	}

	imported := resource.ImportStateResponse{State: empty}
	res.ImportState(ctx, resource.ImportStateRequest{ID: id}, &imported)
	assertOK(imported.Diagnostics)
	if got := model(read(imported.State)); got.Name.ValueString() != "release" || got.Schema.ValueString() != storedSchema || !got.JQRules.Equal(rules) {
		t.Fatalf("unexpected imported state: %+v", got)
	}

	got.Description = types.StringValue("Release evidence")
	state = read(update(state, got))
	if got := model(state); got.Description.ValueString() != "Release evidence" || got.Schema.ValueString() != configuredSchema {
		t.Fatalf("description update failed to preserve schema: %+v", got)
	}
	got.Schema = types.StringNull()
	got.JQRules = types.ListNull(types.StringType)
	state = read(update(state, got))
	if got := model(state); !got.Schema.IsNull() || !got.JQRules.IsNull() {
		t.Fatalf("clear did not persist: %+v", got)
	}

	for range 2 {
		deleted := resource.DeleteResponse{State: state}
		res.Delete(ctx, resource.DeleteRequest{State: state}, &deleted)
		assertOK(deleted.Diagnostics)
	}
	if !read(state).Raw.IsNull() {
		t.Fatal("refresh retained a deleted attestation type")
	}
}

func TestAttestationTypeSchemaComparisonPreservesPrecision(t *testing.T) {
	if sameJSONSchema(`{"minimum":9007199254740992}`, `{"minimum":9007199254740993}`) {
		t.Fatal("different numeric constraints compared equal")
	}
	if sameJSONSchema(`{"type":"object"}`, `{"type":"array"}`) {
		t.Fatal("changed schema compared equal")
	}
}

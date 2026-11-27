package provider

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const attestationTypesPath = "/api/v1/attestation-types"

type attestationTypeResource struct {
	client *Client
}

func NewAttestationTypeResource() resource.Resource { return &attestationTypeResource{} }

type attestationTypeModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Schema      types.String `tfsdk:"schema"`
	JQRules     types.List   `tfsdk:"jq_rules"`
}

type attestationTypeResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Schema      string   `json:"schema"`
	JQRules     []string `json:"jq_rules"`
}

func (r *attestationTypeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_attestation_type"
}

func (r *attestationTypeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A tenant-scoped Fides attestation type definition.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name":        schema.StringAttribute{Required: true},
			"description": schema.StringAttribute{Optional: true},
			"schema":      schema.StringAttribute{Optional: true, Description: "JSON Schema as a string. Removing it clears schema validation."},
			"jq_rules":    schema.ListAttribute{Optional: true, ElementType: types.StringType},
		},
	}
}

func (r *attestationTypeResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = req.ProviderData.(*Client)
	}
}

func (r *attestationTypeResource) endpoint(id types.String) string {
	return r.client.Endpoint + attestationTypesPath + "/" + url.PathEscape(id.ValueString())
}

func (r *attestationTypeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan attestationTypeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	var rules []string
	if !resp.Diagnostics.HasError() && !plan.JQRules.IsNull() {
		resp.Diagnostics.Append(plan.JQRules.ElementsAs(ctx, &rules, false)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}
	payload := map[string]any{"name": plan.Name.ValueString(), "description": plan.Description.ValueString(), "jq_rules": rules}
	if !plan.Schema.IsNull() {
		payload["schema"] = plan.Schema.ValueString()
	}
	out, _, err := r.client.do(http.MethodPost, r.client.Endpoint+attestationTypesPath, payload)
	var created attestationTypeResponse
	if err == nil {
		err = json.Unmarshal(out, &created)
	}
	if err != nil {
		resp.Diagnostics.AddError("Create attestation type failed", err.Error())
		return
	}
	if created.ID == "" {
		resp.Diagnostics.AddError("Create attestation type failed", "The API response omitted the attestation type ID.")
		return
	}
	plan.ID = types.StringValue(created.ID)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *attestationTypeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state attestationTypeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, _, err := r.client.do(http.MethodGet, r.endpoint(state.ID), nil)
	if attestationTypeNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	var got attestationTypeResponse
	if err == nil {
		err = json.Unmarshal(out, &got)
	}
	if err != nil {
		resp.Diagnostics.AddError("Read attestation type failed", err.Error())
		return
	}
	state.Name = types.StringValue(got.Name)
	if got.Description != state.Description.ValueString() {
		state.Description = types.StringNull()
		if got.Description != "" {
			state.Description = types.StringValue(got.Description)
		}
	}
	if !sameJSONSchema(got.Schema, state.Schema.ValueString()) {
		state.Schema = types.StringNull()
		if got.Schema != "" {
			state.Schema = types.StringValue(got.Schema)
		}
	}
	if len(got.JQRules) > 0 {
		rules, diags := types.ListValueFrom(ctx, types.StringType, got.JQRules)
		resp.Diagnostics.Append(diags...)
		state.JQRules = rules
	} else if len(state.JQRules.Elements()) > 0 {
		state.JQRules = types.ListNull(types.StringType)
	}
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	}
}

func (r *attestationTypeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state attestationTypeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	payload := map[string]any{}
	if !plan.Name.Equal(state.Name) {
		payload["name"] = plan.Name.ValueString()
	}
	if !plan.Description.Equal(state.Description) {
		payload["description"] = plan.Description.ValueString()
	}
	if !plan.Schema.Equal(state.Schema) {
		payload["schema"] = plan.Schema.ValueString()
	}
	if !plan.JQRules.Equal(state.JQRules) {
		rules := []string{}
		if !plan.JQRules.IsNull() {
			resp.Diagnostics.Append(plan.JQRules.ElementsAs(ctx, &rules, false)...)
		}
		payload["jq_rules"] = rules
	}
	if resp.Diagnostics.HasError() {
		return
	}
	if len(payload) > 0 {
		if _, _, err := r.client.do(http.MethodPatch, r.endpoint(state.ID), payload); err != nil {
			resp.Diagnostics.AddError("Update attestation type failed", err.Error())
			return
		}
	}
	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *attestationTypeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state attestationTypeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if _, _, err := r.client.do(http.MethodDelete, r.endpoint(state.ID), nil); err != nil && !attestationTypeNotFound(err) {
		resp.Diagnostics.AddError("Delete attestation type failed", err.Error())
	}
}

func (r *attestationTypeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func attestationTypeNotFound(err error) bool {
	var apiErr *apiError
	return errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound
}

// JSONB can change key order, whitespace and number spelling on a refresh.
func sameJSONSchema(left, right string) bool {
	if left == right {
		return true
	}
	if !json.Valid([]byte(left)) || !json.Valid([]byte(right)) {
		return false
	}
	var a, b any
	l := json.NewDecoder(strings.NewReader(left))
	l.UseNumber()
	r := json.NewDecoder(strings.NewReader(right))
	r.UseNumber()
	return l.Decode(&a) == nil && r.Decode(&b) == nil && equalJSONValue(a, b)
}

func equalJSONValue(left, right any) bool {
	switch left := left.(type) {
	case map[string]any:
		right, ok := right.(map[string]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for key, value := range left {
			other, exists := right[key]
			if !exists || !equalJSONValue(value, other) {
				return false
			}
		}
		return true
	case []any:
		right, ok := right.([]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for i := range left {
			if !equalJSONValue(left[i], right[i]) {
				return false
			}
		}
		return true
	case json.Number:
		right, ok := right.(json.Number)
		if !ok {
			return false
		}
		if left == right {
			return true
		}
		a, aOK := new(big.Rat).SetString(left.String())
		b, bOK := new(big.Rat).SetString(right.String())
		return aOK && bOK && a.Cmp(b) == 0
	default:
		return left == right
	}
}

var _ resource.ResourceWithConfigure = &attestationTypeResource{}
var _ resource.ResourceWithImportState = &attestationTypeResource{}

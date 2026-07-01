package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// controlResource manages a Fides governance control (fides_control).
type controlResource struct {
	client *Client
}

func NewControlResource() resource.Resource { return &controlResource{} }

type controlModel struct {
	ID            types.String `tfsdk:"id"`
	Key           types.String `tfsdk:"key"`
	Name          types.String `tfsdk:"name"`
	Description   types.String `tfsdk:"description"`
	Framework     types.String `tfsdk:"framework"`
	RequiredTypes types.List   `tfsdk:"required_types"`
}

func (r *controlResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_control"
}

func (r *controlResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A Fides governance control mapping to attestation types.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"key":         schema.StringAttribute{Required: true, Description: "Unique control key, e.g. SOC2-CC6.1."},
			"name":        schema.StringAttribute{Required: true},
			"description": schema.StringAttribute{Optional: true, Computed: true},
			"framework":   schema.StringAttribute{Optional: true, Computed: true},
			"required_types": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Attestation type names that satisfy this control.",
			},
		},
	}
}

func (r *controlResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = req.ProviderData.(*Client)
	}
}

func (r *controlResource) modelToControl(ctx context.Context, m controlModel) Control {
	var reqTypes []string
	if !m.RequiredTypes.IsNull() && !m.RequiredTypes.IsUnknown() {
		m.RequiredTypes.ElementsAs(ctx, &reqTypes, false)
	}
	return Control{
		Key: m.Key.ValueString(), Name: m.Name.ValueString(),
		Description: m.Description.ValueString(), Framework: m.Framework.ValueString(),
		RequiredTypes: reqTypes,
	}
}

func (r *controlResource) refresh(ctx context.Context, key string, m *controlModel, diags interface {
	AddError(string, string)
}) bool {
	got, err := r.client.GetControlByKey(key)
	if err != nil {
		diags.AddError("Read control failed", err.Error())
		return false
	}
	if got == nil {
		return false // gone
	}
	m.ID = types.StringValue(got.ID)
	m.Key = types.StringValue(got.Key)
	m.Name = types.StringValue(got.Name)
	m.Description = types.StringValue(got.Description)
	m.Framework = types.StringValue(got.Framework)
	lv, d := types.ListValueFrom(ctx, types.StringType, got.RequiredTypes)
	if d.HasError() {
		return false
	}
	m.RequiredTypes = lv
	return true
}

func (r *controlResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan controlModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpsertControl(r.modelToControl(ctx, plan)); err != nil {
		resp.Diagnostics.AddError("Create control failed", err.Error())
		return
	}
	if !r.refresh(ctx, plan.Key.ValueString(), &plan, &resp.Diagnostics) {
		resp.Diagnostics.AddError("Create control failed", "control not found after create")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *controlResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state controlModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.refresh(ctx, state.Key.ValueString(), &state, &resp.Diagnostics) {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *controlResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan controlModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpsertControl(r.modelToControl(ctx, plan)); err != nil {
		resp.Diagnostics.AddError("Update control failed", err.Error())
		return
	}
	if !r.refresh(ctx, plan.Key.ValueString(), &plan, &resp.Diagnostics) {
		resp.Diagnostics.AddError("Update control failed", "control not found after update")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *controlResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state controlModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.ArchiveControl(state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Delete (archive) control failed", err.Error())
	}
}

func (r *controlResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by control key.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key"), req.ID)...)
}

var _ resource.Resource = &controlResource{}
var _ resource.ResourceWithConfigure = &controlResource{}
var _ resource.ResourceWithImportState = &controlResource{}

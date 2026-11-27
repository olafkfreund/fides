package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const environmentsPath = "/api/v1/environments"

type environmentResource struct {
	client *Client
}

func NewEnvironmentResource() resource.Resource { return &environmentResource{} }

type environmentModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Type        types.String `tfsdk:"type"`
	Description types.String `tfsdk:"description"`
}

type environmentFields struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

func (r *environmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_environment"
}

func (r *environmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A Fides runtime environment. Destroy archives the environment and retains its evidence.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Environment UUID, used for imports.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{Required: true},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "Runtime type, such as docker, k8s, ecs, lambda, cloud-run, azure-apps, s3, or server.",
			},
			"description": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
		},
	}
}

func (r *environmentResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = req.ProviderData.(*Client)
	}
}

func (r *environmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.request(ctx, http.MethodPost, environmentsPath+"?create_only=true", plan.fields(), &plan); err != nil {
		resp.Diagnostics.AddError("Create environment failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *environmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state environmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.request(ctx, http.MethodGet, state.apiPath(), nil, &state)
	if environmentNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Read environment failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *environmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.request(ctx, http.MethodPatch, plan.apiPath(), plan.fields(), &plan); err != nil {
		resp.Diagnostics.AddError("Update environment failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *environmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state environmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, _, err := r.client.doContext(ctx, http.MethodPost, r.client.Endpoint+state.apiPath()+"/archive", nil)
	if err != nil && !environmentNotFound(err) {
		resp.Diagnostics.AddError("Archive environment failed", err.Error())
	}
}

func (r *environmentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (m environmentModel) fields() environmentFields {
	return environmentFields{m.Name.ValueString(), m.Type.ValueString(), m.Description.ValueString()}
}

func (m environmentModel) apiPath() string {
	return environmentsPath + "/" + url.PathEscape(m.ID.ValueString())
}

func (r *environmentResource) request(ctx context.Context, method, path string, body any, model *environmentModel) error {
	out, _, err := r.client.doContext(ctx, method, r.client.Endpoint+path, body)
	if err != nil {
		return err
	}
	var result struct {
		environmentFields
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return err
	}
	if result.ID == "" {
		return errors.New("Fides API response is missing the environment UUID")
	}
	*model = environmentModel{
		ID:          types.StringValue(result.ID),
		Name:        types.StringValue(result.Name),
		Type:        types.StringValue(result.Type),
		Description: types.StringValue(result.Description),
	}
	return nil
}

func environmentNotFound(err error) bool {
	var apiErr *apiError
	return errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound
}

var _ resource.ResourceWithConfigure = &environmentResource{}
var _ resource.ResourceWithImportState = &environmentResource{}

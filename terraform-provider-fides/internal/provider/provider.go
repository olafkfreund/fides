package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// fidesProvider manages Fides resources (governance controls, ...) via the API.
type fidesProvider struct{}

func New() provider.Provider { return &fidesProvider{} }

type providerModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	APIToken types.String `tfsdk:"api_token"`
}

func (p *fidesProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "fides"
}

func (p *fidesProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "Fides server URL. Defaults to the FIDES_SERVER_URL environment variable.",
			},
			"api_token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "API token (static token or service-account key). Defaults to FIDES_API_TOKEN.",
			},
		},
	}
}

func (p *fidesProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	endpoint := cfg.Endpoint.ValueString()
	if endpoint == "" {
		endpoint = os.Getenv("FIDES_SERVER_URL")
	}
	token := cfg.APIToken.ValueString()
	if token == "" {
		token = os.Getenv("FIDES_API_TOKEN")
	}
	if endpoint == "" {
		resp.Diagnostics.AddError("Missing Fides endpoint", "Set the provider `endpoint` or the FIDES_SERVER_URL environment variable.")
		return
	}
	client := NewClient(endpoint, token)
	resp.ResourceData = client
}

func (p *fidesProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewControlResource}
}

func (p *fidesProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &edlResource{}

func NewEDLResource() resource.Resource {
	return &edlResource{}
}

type edlResource struct {
	backend api.XSOARBackend
}

type edlModel struct {
	Enabled   types.Bool   `tfsdk:"enabled"`
	Username  types.String `tfsdk:"username"`
	Password  types.String `tfsdk:"password"`
	URLIP     types.String `tfsdk:"url_ip"`
	URLDomain types.String `tfsdk:"url_domain"`
}

func (r *edlResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_edl"
}

func (r *edlResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages External Dynamic List (EDL) configuration in XSIAM. " +
			"EDL allows sharing threat intelligence with external systems via HTTP. " +
			"This is a singleton resource. " +
			"Requires webapp session authentication (session_token or cortex-login). " +
			"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Description: "Whether the EDL service is enabled.",
				Required:    true,
			},
			"username": schema.StringAttribute{
				Description: "Username for EDL HTTP basic authentication.",
				Required:    true,
			},
			"password": schema.StringAttribute{
				Description: "Password for EDL HTTP basic authentication.",
				Optional:    true,
				Sensitive:   true,
				Computed:    true,
			},
			"url_ip": schema.StringAttribute{
				Description: "Auto-generated EDL URL for IP indicators.",
				Computed:    true,
			},
			"url_domain": schema.StringAttribute{
				Description: "Auto-generated EDL URL for domain indicators.",
				Computed:    true,
			},
		},
	}
}

func (r *edlResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	pd, ok := req.ProviderData.(*providerdata.ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *providerdata.ProviderData, got: %T", req.ProviderData),
		)
		return
	}
	r.backend = pd.Backend
}

func (r *edlResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan edlModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	config := map[string]interface{}{
		"enabled":  plan.Enabled.ValueBool(),
		"username": plan.Username.ValueString(),
	}
	if !plan.Password.IsNull() && !plan.Password.IsUnknown() {
		config["password"] = plan.Password.ValueString()
	}

	result, err := r.backend.UpdateEDLConfig(config)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating EDL Config", err.Error())
		return
	}

	setEDLState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *edlResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state edlModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.backend.GetEDLConfig()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading EDL Config", err.Error())
		return
	}

	setEDLState(&state, result)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *edlResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan edlModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	config := map[string]interface{}{
		"enabled":  plan.Enabled.ValueBool(),
		"username": plan.Username.ValueString(),
	}
	if !plan.Password.IsNull() && !plan.Password.IsUnknown() {
		config["password"] = plan.Password.ValueString()
	}

	result, err := r.backend.UpdateEDLConfig(config)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating EDL Config", err.Error())
		return
	}

	setEDLState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *edlResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Singleton: disable on delete
	_, err := r.backend.UpdateEDLConfig(map[string]interface{}{
		"enabled": false,
	})
	if err != nil {
		resp.Diagnostics.AddError("Error Disabling EDL Config", err.Error())
	}
}

func setEDLState(model *edlModel, config *api.EDLConfig) {
	model.Enabled = types.BoolValue(config.Enabled)
	model.Username = types.StringValue(config.Username)
	if config.Password != "" {
		model.Password = types.StringValue(config.Password)
	}
	model.URLIP = types.StringValue(config.URLIP)
	model.URLDomain = types.StringValue(config.URLDomain)
}

package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &collectorProfileResource{}

func NewCollectorProfileResource() resource.Resource {
	return &collectorProfileResource{}
}

type collectorProfileResource struct {
	backend api.XSOARBackend
}

type collectorProfileModel struct {
	ProfileID   types.Int64  `tfsdk:"profile_id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Platform    types.String `tfsdk:"platform"`
	ProfileType types.String `tfsdk:"profile_type"`
	IsDefault   types.Bool   `tfsdk:"is_default"`
	Modules     types.String `tfsdk:"modules"`
}

func (r *collectorProfileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_collector_profile"
}

func (r *collectorProfileResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an XDR collector profile in XSIAM. " +
			"Profiles define collector configuration (modules, settings). " +
			"Create-only: no update or delete API. All fields require replacement. " +
			"Deletion removes the profile from Terraform state only. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"profile_id": schema.Int64Attribute{
				Description: "The unique numeric identifier of the profile.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the profile.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "A description of the profile.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"platform": schema.StringAttribute{
				Description: "The platform. Valid values: AGENT_OS_WINDOWS, AGENT_OS_LINUX.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"profile_type": schema.StringAttribute{
				Description: "The profile type.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("STANDARD"),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"is_default": schema.BoolAttribute{
				Description: "Whether this is the default profile.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"modules": schema.StringAttribute{
				Description: "Base64-encoded YAML modules configuration.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *collectorProfileResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *collectorProfileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan collectorProfileModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	description := ""
	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		description = plan.Description.ValueString()
	}
	profileData := map[string]interface{}{
		"PROFILE_NAME":        plan.Name.ValueString(),
		"PROFILE_PLATFORM":    plan.Platform.ValueString(),
		"PROFILE_TYPE":        plan.ProfileType.ValueString(),
		"PROFILE_DESCRIPTION": description,
		"PROFILE_IS_DEFAULT":  plan.IsDefault.ValueBool(),
		"PROFILE_MODULES": map[string]interface{}{
			"filebeat": map[string]interface{}{
				"yaml": map[string]interface{}{
					"value": plan.Modules.ValueString(),
				},
			},
		},
	}

	result, err := r.backend.CreateCollectorProfile(profileData)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Collector Profile", err.Error())
		return
	}

	setCollectorProfileState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *collectorProfileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state collectorProfileModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	profileID := int(state.ProfileID.ValueInt64())
	profiles, err := r.backend.ListCollectorProfiles()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Collector Profile", err.Error())
		return
	}

	var found *api.CollectorProfile
	for _, p := range profiles {
		if p.ProfileID == profileID {
			found = &p
			break
		}
	}
	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setCollectorProfileState(&state, found)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *collectorProfileResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update Not Supported",
		"Collector profiles cannot be updated. All fields require replacement.")
}

func (r *collectorProfileResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No delete API; remove from state only
}

func setCollectorProfileState(model *collectorProfileModel, profile *api.CollectorProfile) {
	model.ProfileID = types.Int64Value(int64(profile.ProfileID))
	model.Name = types.StringValue(profile.Name)
	model.Platform = types.StringValue(profile.Platform)
	model.ProfileType = types.StringValue(profile.ProfileType)
	model.IsDefault = types.BoolValue(profile.IsDefault)
	if profile.Description != "" {
		model.Description = types.StringValue(profile.Description)
	} else {
		model.Description = types.StringNull()
	}
	if profile.Modules != "" {
		model.Modules = types.StringValue(profile.Modules)
	}
}

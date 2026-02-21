package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &collectorDistributionResource{}

func NewCollectorDistributionResource() resource.Resource {
	return &collectorDistributionResource{}
}

type collectorDistributionResource struct {
	backend api.XSOARBackend
}

type collectorDistributionModel struct {
	DistributionID types.String `tfsdk:"distribution_id"`
	Name           types.String `tfsdk:"name"`
	Description    types.String `tfsdk:"description"`
	AgentVersion   types.String `tfsdk:"agent_version"`
	Platform       types.String `tfsdk:"platform"`
	PackageType    types.String `tfsdk:"package_type"`
	CreatedBy      types.String `tfsdk:"created_by"`
}

func (r *collectorDistributionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_collector_distribution"
}

func (r *collectorDistributionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an XDR collector distribution package in XSIAM. " +
			"Distributions are installer packages for deploying collectors. " +
			"No update API; all fields require replacement on change. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"distribution_id": schema.StringAttribute{
				Description: "The unique UUID of the distribution.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the distribution.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "A description of the distribution.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"agent_version": schema.StringAttribute{
				Description: "The collector agent version.",
				Required:    true,
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
			"package_type": schema.StringAttribute{
				Description: "The package type.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("SCOUTER_INSTALLER"),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"created_by": schema.StringAttribute{
				Description: "User who created the distribution.",
				Computed:    true,
			},
		},
	}
}

func (r *collectorDistributionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *collectorDistributionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan collectorDistributionModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	distData := map[string]interface{}{
		"name":          plan.Name.ValueString(),
		"agent_version": plan.AgentVersion.ValueString(),
		"platform":      plan.Platform.ValueString(),
		"package_type":  plan.PackageType.ValueString(),
	}
	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		distData["description"] = plan.Description.ValueString()
	}

	result, err := r.backend.CreateCollectorDistribution(distData)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Collector Distribution", err.Error())
		return
	}

	setCollectorDistributionState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *collectorDistributionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state collectorDistributionModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	distID := state.DistributionID.ValueString()
	dists, err := r.backend.ListCollectorDistributions()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Collector Distribution", err.Error())
		return
	}

	var found *api.CollectorDistribution
	for _, d := range dists {
		if d.DistributionID == distID {
			found = &d
			break
		}
	}
	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setCollectorDistributionState(&state, found)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *collectorDistributionResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update Not Supported",
		"Collector distributions cannot be updated. All fields require replacement.")
}

func (r *collectorDistributionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state collectorDistributionModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	distID := state.DistributionID.ValueString()
	err := r.backend.DeleteCollectorDistribution(distID)
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting Collector Distribution", err.Error())
	}
}

func setCollectorDistributionState(model *collectorDistributionModel, dist *api.CollectorDistribution) {
	model.DistributionID = types.StringValue(dist.DistributionID)
	model.Name = types.StringValue(dist.Name)
	model.AgentVersion = types.StringValue(dist.AgentVersion)
	model.Platform = types.StringValue(dist.Platform)
	model.PackageType = types.StringValue(dist.PackageType)
	if dist.Description != "" {
		model.Description = types.StringValue(dist.Description)
	} else {
		model.Description = types.StringNull()
	}
	if dist.CreatedBy != "" {
		model.CreatedBy = types.StringValue(dist.CreatedBy)
	} else {
		model.CreatedBy = types.StringNull()
	}
}

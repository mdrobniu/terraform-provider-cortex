package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &hostResource{}
	_ resource.ResourceWithImportState = &hostResource{}
)

// NewHostResource is a factory function for the resource.
func NewHostResource() resource.Resource {
	return &hostResource{}
}

// hostResource manages a host/engine in XSOAR (API-only, no SSH installation).
type hostResource struct {
	backend api.XSOARBackend
}

// hostResourceModel maps the resource schema data.
type hostResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	HAGroupName types.String `tfsdk:"ha_group_name"`
	HAGroupID   types.String `tfsdk:"ha_group_id"`
	Status      types.String `tfsdk:"status"`
}

func (r *hostResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_host"
}

func (r *hostResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a host/engine in XSOAR. This resource registers and tracks hosts that already " +
			"exist in the XSOAR instance (API-only, no SSH installation is performed by this provider).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the host.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the host/engine.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ha_group_name": schema.StringAttribute{
				Description: "The name of the HA group this host belongs to.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"ha_group_id": schema.StringAttribute{
				Description: "The ID of the HA group this host belongs to.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"status": schema.StringAttribute{
				Description: "The current status of the host.",
				Computed:    true,
			},
		},
	}
}

func (r *hostResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *hostResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan hostResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := plan.Name.ValueString()

	// This resource only registers/reads hosts that already exist.
	// Verify the host exists by reading it.
	host, err := r.backend.GetHost(name)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Host",
			fmt.Sprintf("Host %q does not exist or could not be read: %s. "+
				"This resource manages existing hosts only; it does not perform SSH installation.", name, err),
		)
		return
	}

	plan.ID = types.StringValue(host.ID)
	plan.Name = types.StringValue(host.Name)
	plan.HAGroupID = types.StringValue(host.HAGroupID)
	plan.HAGroupName = types.StringValue(host.HAGroupName)
	plan.Status = types.StringValue(host.Status)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *hostResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state hostResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := state.Name.ValueString()

	host, err := r.backend.GetHost(name)
	if err != nil {
		// Host no longer exists; remove from state.
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(host.ID)
	state.Name = types.StringValue(host.Name)
	state.HAGroupID = types.StringValue(host.HAGroupID)
	state.HAGroupName = types.StringValue(host.HAGroupName)
	state.Status = types.StringValue(host.Status)

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *hostResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan hostResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Most fields are computed. Re-read the host to refresh state.
	name := plan.Name.ValueString()

	host, err := r.backend.GetHost(name)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Host",
			fmt.Sprintf("Could not read host %q: %s", name, err),
		)
		return
	}

	plan.ID = types.StringValue(host.ID)
	plan.Name = types.StringValue(host.Name)
	plan.HAGroupID = types.StringValue(host.HAGroupID)
	plan.HAGroupName = types.StringValue(host.HAGroupName)
	plan.Status = types.StringValue(host.Status)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *hostResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state hostResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.backend.DeleteHost(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Host",
			fmt.Sprintf("Could not delete host %q: %s", state.Name.ValueString(), err),
		)
		return
	}
}

func (r *hostResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import ID is the host name.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

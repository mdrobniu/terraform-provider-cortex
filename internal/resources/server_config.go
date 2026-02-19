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
	_ resource.Resource                = &serverConfigResource{}
	_ resource.ResourceWithImportState = &serverConfigResource{}
)

// NewServerConfigResource is a factory function for the resource.
func NewServerConfigResource() resource.Resource {
	return &serverConfigResource{}
}

// serverConfigResource manages an individual key-value pair in XSOAR server config.
type serverConfigResource struct {
	backend api.XSOARBackend
}

// serverConfigResourceModel maps the resource schema data.
type serverConfigResourceModel struct {
	ID    types.String `tfsdk:"id"`
	Key   types.String `tfsdk:"key"`
	Value types.String `tfsdk:"value"`
}

func (r *serverConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_server_config"
}

func (r *serverConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an individual key-value pair in the XSOAR server configuration.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The identifier of the config entry (same as key).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"key": schema.StringAttribute{
				Description: "The server configuration key name.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"value": schema.StringAttribute{
				Description: "The value for the configuration key.",
				Required:    true,
			},
		},
	}
}

func (r *serverConfigResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *serverConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serverConfigResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	key := plan.Key.ValueString()
	value := plan.Value.ValueString()

	// Get current config to obtain the version number.
	_, version, err := r.backend.GetServerConfig()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Server Config", fmt.Sprintf("Could not read server config: %s", err))
		return
	}

	// Update the specific key.
	configUpdate := map[string]string{
		key: value,
	}
	err = r.backend.UpdateServerConfig(configUpdate, version)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Server Config Entry", fmt.Sprintf("Could not set config key %q: %s", key, err))
		return
	}

	plan.ID = types.StringValue(key)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *serverConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state serverConfigResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	key := state.Key.ValueString()

	configMap, _, err := r.backend.GetServerConfig()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Server Config", fmt.Sprintf("Could not read server config: %s", err))
		return
	}

	if val, ok := configMap[key]; ok {
		state.Value = types.StringValue(fmt.Sprintf("%v", val))
	} else {
		// Key does not exist in the config; remove from state.
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(key)

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *serverConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan serverConfigResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	key := plan.Key.ValueString()
	value := plan.Value.ValueString()

	// Get current config to obtain the version number.
	_, version, err := r.backend.GetServerConfig()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Server Config", fmt.Sprintf("Could not read server config: %s", err))
		return
	}

	configUpdate := map[string]string{
		key: value,
	}
	err = r.backend.UpdateServerConfig(configUpdate, version)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating Server Config Entry", fmt.Sprintf("Could not update config key %q: %s", key, err))
		return
	}

	plan.ID = types.StringValue(key)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *serverConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state serverConfigResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	key := state.Key.ValueString()

	// XSOAR config keys cannot truly be deleted; set to empty string.
	_, version, err := r.backend.GetServerConfig()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Server Config", fmt.Sprintf("Could not read server config: %s", err))
		return
	}

	configUpdate := map[string]string{
		key: "",
	}
	err = r.backend.UpdateServerConfig(configUpdate, version)
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting Server Config Entry", fmt.Sprintf("Could not clear config key %q: %s", key, err))
		return
	}
}

func (r *serverConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID is the config key name.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("key"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

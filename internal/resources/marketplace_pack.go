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
	_ resource.Resource                = &marketplacePackResource{}
	_ resource.ResourceWithImportState = &marketplacePackResource{}
)

// NewMarketplacePackResource is a factory function for the resource.
func NewMarketplacePackResource() resource.Resource {
	return &marketplacePackResource{}
}

// marketplacePackResource manages the installation of a marketplace pack.
type marketplacePackResource struct {
	backend api.XSOARBackend
}

// marketplacePackResourceModel maps the resource schema data.
type marketplacePackResourceModel struct {
	ID      types.String `tfsdk:"id"`
	PackID  types.String `tfsdk:"pack_id"`
	Version types.String `tfsdk:"version"`
	Name    types.String `tfsdk:"name"`
}

func (r *marketplacePackResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_marketplace_pack"
}

func (r *marketplacePackResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Installs and manages a marketplace pack on the XSOAR instance.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The identifier of the installed pack (same as pack_id).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"pack_id": schema.StringAttribute{
				Description: "The marketplace pack ID (e.g., 'Base', 'CommonScripts').",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"version": schema.StringAttribute{
				Description: "The version to install. If not specified, the latest version is installed.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The display name of the installed pack.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *marketplacePackResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *marketplacePackResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan marketplacePackResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	packID := plan.PackID.ValueString()
	version := plan.Version.ValueString()

	pack := api.Pack{
		ID:             packID,
		CurrentVersion: version,
	}

	err := r.backend.InstallPacks([]api.Pack{pack})
	if err != nil {
		resp.Diagnostics.AddError("Error Installing Marketplace Pack", fmt.Sprintf("Could not install pack %q: %s", packID, err))
		return
	}

	// Read back the installed pack to get the actual version and name.
	installedPack, err := r.findInstalledPack(packID)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Installed Pack", fmt.Sprintf("Pack %q was installed but could not be read back: %s", packID, err))
		return
	}

	plan.ID = types.StringValue(installedPack.ID)
	plan.Version = types.StringValue(installedPack.CurrentVersion)
	plan.Name = types.StringValue(installedPack.Name)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *marketplacePackResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state marketplacePackResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	packID := state.PackID.ValueString()

	installedPack, err := r.findInstalledPack(packID)
	if err != nil {
		// Pack is no longer installed; remove from state.
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(installedPack.ID)
	state.Version = types.StringValue(installedPack.CurrentVersion)
	state.Name = types.StringValue(installedPack.Name)

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *marketplacePackResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan marketplacePackResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	packID := plan.PackID.ValueString()
	version := plan.Version.ValueString()

	// Re-install with the new version.
	pack := api.Pack{
		ID:             packID,
		CurrentVersion: version,
	}

	err := r.backend.InstallPacks([]api.Pack{pack})
	if err != nil {
		resp.Diagnostics.AddError("Error Updating Marketplace Pack", fmt.Sprintf("Could not update pack %q to version %q: %s", packID, version, err))
		return
	}

	// Read back the installed pack.
	installedPack, err := r.findInstalledPack(packID)
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Installed Pack", fmt.Sprintf("Pack %q was updated but could not be read back: %s", packID, err))
		return
	}

	plan.ID = types.StringValue(installedPack.ID)
	plan.Version = types.StringValue(installedPack.CurrentVersion)
	plan.Name = types.StringValue(installedPack.Name)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *marketplacePackResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state marketplacePackResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	packID := state.PackID.ValueString()

	err := r.backend.UninstallPack(packID)
	if err != nil {
		resp.Diagnostics.AddError("Error Uninstalling Marketplace Pack", fmt.Sprintf("Could not uninstall pack %q: %s", packID, err))
		return
	}
}

func (r *marketplacePackResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID is the pack_id.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("pack_id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// findInstalledPack searches the list of installed packs for a matching pack ID.
func (r *marketplacePackResource) findInstalledPack(packID string) (*api.Pack, error) {
	packs, err := r.backend.ListInstalledPacks()
	if err != nil {
		return nil, fmt.Errorf("listing installed packs: %w", err)
	}
	for _, p := range packs {
		if p.ID == packID {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("pack %q not found in installed packs", packID)
}

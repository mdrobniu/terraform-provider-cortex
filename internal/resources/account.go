package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &accountResource{}
	_ resource.ResourceWithImportState = &accountResource{}
)

// NewAccountResource is a factory function for the resource.
func NewAccountResource() resource.Resource {
	return &accountResource{}
}

// accountResource manages a multi-tenant account in XSOAR.
type accountResource struct {
	backend api.XSOARBackend
}

// accountResourceModel maps the resource schema data.
type accountResourceModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	HostGroupName     types.String `tfsdk:"host_group_name"`
	HostGroupID       types.String `tfsdk:"host_group_id"`
	AccountRoles      types.List   `tfsdk:"account_roles"`
	PropagationLabels types.List   `tfsdk:"propagation_labels"`
}

func (r *accountResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_account"
}

func (r *accountResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	defaultRoles, diags := types.ListValueFrom(ctx, types.StringType, []string{"Administrator"})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Schema = schema.Schema{
		Description: "Manages a multi-tenant account in XSOAR.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the account.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The display name of the account (without the acc_ prefix).",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"host_group_name": schema.StringAttribute{
				Description: "The name of the host group (HA group) for the account.",
				Required:    true,
			},
			"host_group_id": schema.StringAttribute{
				Description: "The resolved ID of the host group (HA group).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"account_roles": schema.ListAttribute{
				Description: "The roles assigned to the account. Defaults to [\"Administrator\"].",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Default:     listdefault.StaticValue(defaultRoles),
			},
			"propagation_labels": schema.ListAttribute{
				Description: "The propagation labels for the account.",
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *accountResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// resolveHostGroupID resolves a host group name to its ID by listing HA groups.
func (r *accountResource) resolveHostGroupID(name string) (string, error) {
	groups, err := r.backend.ListHAGroups()
	if err != nil {
		return "", fmt.Errorf("listing HA groups: %w", err)
	}
	for _, g := range groups {
		if g.Name == name {
			return g.ID, nil
		}
	}
	return "", fmt.Errorf("HA group %q not found", name)
}

// resolveHostGroupName resolves a host group ID to its name by listing HA groups.
func (r *accountResource) resolveHostGroupName(id string) (string, error) {
	groups, err := r.backend.ListHAGroups()
	if err != nil {
		return "", fmt.Errorf("listing HA groups: %w", err)
	}
	for _, g := range groups {
		if g.ID == id {
			return g.Name, nil
		}
	}
	return "", fmt.Errorf("HA group with ID %q not found", id)
}

func (r *accountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan accountResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := plan.Name.ValueString()
	hostGroupName := plan.HostGroupName.ValueString()

	// Resolve host_group_name to ID.
	hostGroupID, err := r.resolveHostGroupID(hostGroupName)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Resolving Host Group",
			fmt.Sprintf("Could not resolve host group name %q to ID: %s", hostGroupName, err),
		)
		return
	}

	// Extract roles from plan.
	var roles []string
	diags = plan.AccountRoles.ElementsAs(ctx, &roles, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract propagation labels from plan.
	var propagationLabels []string
	if !plan.PropagationLabels.IsNull() && !plan.PropagationLabels.IsUnknown() {
		diags = plan.PropagationLabels.ElementsAs(ctx, &propagationLabels, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	accountData := map[string]interface{}{
		"name":        name,
		"hostGroupId": hostGroupID,
		"roles":       roles,
	}
	if len(propagationLabels) > 0 {
		accountData["propagationLabels"] = propagationLabels
	}

	account, err := r.backend.CreateAccount(accountData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Account",
			fmt.Sprintf("Could not create account %q: %s", name, err),
		)
		return
	}

	plan.ID = types.StringValue(account.ID)
	plan.HostGroupID = types.StringValue(hostGroupID)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *accountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state accountResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := state.Name.ValueString()

	account, err := r.backend.GetAccount(name)
	if err != nil {
		// Account no longer exists; remove from state.
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(account.ID)
	state.Name = types.StringValue(account.DisplayName)

	// Resolve host group name from ID.
	if account.HostGroupID != "" {
		state.HostGroupID = types.StringValue(account.HostGroupID)
		hostGroupName, err := r.resolveHostGroupName(account.HostGroupID)
		if err == nil {
			state.HostGroupName = types.StringValue(hostGroupName)
		}
	}

	if account.Roles != nil {
		rolesList, diag := types.ListValueFrom(ctx, types.StringType, account.Roles)
		resp.Diagnostics.Append(diag...)
		state.AccountRoles = rolesList
	}

	if account.PropagationLabels != nil {
		propList, diag := types.ListValueFrom(ctx, types.StringType, account.PropagationLabels)
		resp.Diagnostics.Append(diag...)
		state.PropagationLabels = propList
	} else {
		state.PropagationLabels = types.ListNull(types.StringType)
	}

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *accountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan accountResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := plan.Name.ValueString()
	hostGroupName := plan.HostGroupName.ValueString()

	// Resolve host_group_name to ID.
	hostGroupID, err := r.resolveHostGroupID(hostGroupName)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Resolving Host Group",
			fmt.Sprintf("Could not resolve host group name %q to ID: %s", hostGroupName, err),
		)
		return
	}

	// Extract roles.
	var roles []string
	diags = plan.AccountRoles.ElementsAs(ctx, &roles, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract propagation labels.
	var propagationLabels []string
	if !plan.PropagationLabels.IsNull() && !plan.PropagationLabels.IsUnknown() {
		diags = plan.PropagationLabels.ElementsAs(ctx, &propagationLabels, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	updateData := map[string]interface{}{
		"hostGroupId":       hostGroupID,
		"roles":             roles,
		"propagationLabels": propagationLabels,
	}

	err = r.backend.UpdateAccount(name, updateData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Account",
			fmt.Sprintf("Could not update account %q: %s", name, err),
		)
		return
	}

	plan.HostGroupID = types.StringValue(hostGroupID)

	// Re-read the account to get current state.
	account, err := r.backend.GetAccount(name)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Account After Update",
			fmt.Sprintf("Could not read account %q after update: %s", name, err),
		)
		return
	}

	plan.ID = types.StringValue(account.ID)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *accountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state accountResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := state.Name.ValueString()

	err := r.backend.DeleteAccount(name)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Account",
			fmt.Sprintf("Could not delete account %q: %s", name, err),
		)
		return
	}
}

func (r *accountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import ID is the account display name (without acc_ prefix).
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &roleResource{}
	_ resource.ResourceWithImportState = &roleResource{}
)

// NewRoleResource is a factory function for the resource.
func NewRoleResource() resource.Resource {
	return &roleResource{}
}

// roleResource manages a user role with permissions.
type roleResource struct {
	backend api.XSOARBackend
}

// roleResourceModel maps the resource schema data.
type roleResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Permissions types.String `tfsdk:"permissions"`
	Version     types.Int64  `tfsdk:"version"`
}

func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (r *roleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a user role and its permissions on the XSOAR instance.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The internal identifier of the role.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the role.",
				Required:    true,
			},
			"permissions": schema.StringAttribute{
				Description: "A JSON string representing the permissions map. " +
					"The map keys are permission categories and values are string arrays of granted permissions.",
				Required: true,
			},
			"version": schema.Int64Attribute{
				Description: "The internal version number used for optimistic concurrency control.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *roleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Parse permissions JSON string.
	var permissions interface{}
	if err := json.Unmarshal([]byte(plan.Permissions.ValueString()), &permissions); err != nil {
		resp.Diagnostics.AddError("Invalid Permissions JSON", fmt.Sprintf("Could not parse permissions: %s", err))
		return
	}

	rolePayload := map[string]interface{}{
		"name":        plan.Name.ValueString(),
		"permissions": permissions,
	}

	created, err := r.backend.CreateRole(rolePayload)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Role", fmt.Sprintf("Could not create role %q: %s", plan.Name.ValueString(), err))
		return
	}

	plan.ID = types.StringValue(created.ID)
	plan.Version = types.Int64Value(int64(created.Version))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := state.Name.ValueString()

	role, err := r.findRoleByName(name)
	if err != nil {
		// Role not found; remove from state.
		resp.State.RemoveResource(ctx)
		return
	}

	// Serialize permissions back to JSON.
	permBytes, err := json.Marshal(role.Permissions)
	if err != nil {
		resp.Diagnostics.AddError("Error Serializing Permissions", fmt.Sprintf("Could not serialize permissions for role %q: %s", name, err))
		return
	}

	state.ID = types.StringValue(role.ID)
	state.Name = types.StringValue(role.Name)
	state.Permissions = types.StringValue(string(permBytes))
	state.Version = types.Int64Value(int64(role.Version))

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan roleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state roleResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Parse permissions JSON string.
	var permissions interface{}
	if err := json.Unmarshal([]byte(plan.Permissions.ValueString()), &permissions); err != nil {
		resp.Diagnostics.AddError("Invalid Permissions JSON", fmt.Sprintf("Could not parse permissions: %s", err))
		return
	}

	// Use the existing ID for the update (create-or-update pattern).
	rolePayload := map[string]interface{}{
		"id":          state.ID.ValueString(),
		"name":        plan.Name.ValueString(),
		"permissions": permissions,
		"version":     state.Version.ValueInt64(),
	}

	updated, err := r.backend.CreateRole(rolePayload)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating Role", fmt.Sprintf("Could not update role %q: %s", plan.Name.ValueString(), err))
		return
	}

	plan.ID = types.StringValue(updated.ID)
	plan.Version = types.Int64Value(int64(updated.Version))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.backend.DeleteRole(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting Role", fmt.Sprintf("Could not delete role %q: %s", state.Name.ValueString(), err))
		return
	}
}

func (r *roleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID is the role name.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

// findRoleByName searches the list of roles for a matching role name.
func (r *roleResource) findRoleByName(name string) (*api.Role, error) {
	roles, err := r.backend.ListRoles()
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}
	for _, role := range roles {
		if role.Name == name {
			return &role, nil
		}
	}
	return nil, fmt.Errorf("role %q not found", name)
}

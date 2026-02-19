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
	_ resource.Resource                = &credentialResource{}
	_ resource.ResourceWithImportState = &credentialResource{}
)

// NewCredentialResource is a factory function for the resource.
func NewCredentialResource() resource.Resource {
	return &credentialResource{}
}

// credentialResource manages a stored credential in XSOAR.
type credentialResource struct {
	backend api.XSOARBackend
}

// credentialResourceModel maps the resource schema data.
type credentialResourceModel struct {
	ID       types.String `tfsdk:"id"`
	Name     types.String `tfsdk:"name"`
	User     types.String `tfsdk:"user"`
	Password types.String `tfsdk:"password"`
	Comment  types.String `tfsdk:"comment"`
	Version  types.Int64  `tfsdk:"version"`
}

func (r *credentialResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_credential"
}

func (r *credentialResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a stored credential in XSOAR.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the credential.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the credential.",
				Required:    true,
			},
			"user": schema.StringAttribute{
				Description: "The username for the credential.",
				Required:    true,
			},
			"password": schema.StringAttribute{
				Description: "The password for the credential. This value is sensitive and is not returned by the API on read.",
				Required:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"comment": schema.StringAttribute{
				Description: "An optional comment for the credential.",
				Optional:    true,
			},
			"version": schema.Int64Attribute{
				Description: "The version number of the credential, used for optimistic concurrency control.",
				Computed:    true,
			},
		},
	}
}

func (r *credentialResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *credentialResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan credentialResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	credData := map[string]interface{}{
		"name":     plan.Name.ValueString(),
		"user":     plan.User.ValueString(),
		"password": plan.Password.ValueString(),
		"version":  -1,
	}
	if !plan.Comment.IsNull() && !plan.Comment.IsUnknown() {
		credData["comment"] = plan.Comment.ValueString()
	}

	cred, err := r.backend.CreateCredential(credData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Credential",
			fmt.Sprintf("Could not create credential %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	plan.ID = types.StringValue(cred.ID)
	plan.Version = types.Int64Value(int64(cred.Version))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *credentialResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state credentialResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := state.Name.ValueString()

	cred, err := r.findCredentialByName(name)
	if err != nil {
		// Credential no longer exists; remove from state.
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(cred.ID)
	state.Name = types.StringValue(cred.Name)
	state.User = types.StringValue(cred.User)
	// Password is not returned by the API; preserve the value from state.
	// The UseStateForUnknown plan modifier handles this.
	state.Version = types.Int64Value(int64(cred.Version))

	if cred.Comment != "" {
		state.Comment = types.StringValue(cred.Comment)
	} else if state.Comment.IsNull() {
		// Keep null if it was null before and the API returns empty.
		state.Comment = types.StringNull()
	}

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *credentialResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan credentialResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state credentialResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	credData := map[string]interface{}{
		"id":       state.ID.ValueString(),
		"version":  state.Version.ValueInt64(),
		"name":     plan.Name.ValueString(),
		"user":     plan.User.ValueString(),
		"password": plan.Password.ValueString(),
	}
	if !plan.Comment.IsNull() && !plan.Comment.IsUnknown() {
		credData["comment"] = plan.Comment.ValueString()
	}

	cred, err := r.backend.UpdateCredential(credData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Credential",
			fmt.Sprintf("Could not update credential %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	plan.ID = types.StringValue(cred.ID)
	plan.Version = types.Int64Value(int64(cred.Version))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *credentialResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state credentialResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.backend.DeleteCredential(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Credential",
			fmt.Sprintf("Could not delete credential %q: %s", state.Name.ValueString(), err),
		)
		return
	}
}

func (r *credentialResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import ID is the credential name.
	name := req.ID

	cred, err := r.findCredentialByName(name)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Credential",
			fmt.Sprintf("Could not find credential with name %q: %s", name, err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), cred.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), cred.Name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("user"), cred.User)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("version"), int64(cred.Version))...)
	// Password cannot be imported from the API; it will need to be set in the config.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("password"), "")...)

	if cred.Comment != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("comment"), cred.Comment)...)
	}
}

// findCredentialByName searches credentials by name.
func (r *credentialResource) findCredentialByName(name string) (*api.Credential, error) {
	creds, err := r.backend.ListCredentials()
	if err != nil {
		return nil, fmt.Errorf("listing credentials: %w", err)
	}
	for _, c := range creds {
		if c.Name == name {
			return &c, nil
		}
	}
	return nil, fmt.Errorf("credential %q not found", name)
}

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
	_ resource.Resource                = &apiKeyResource{}
	_ resource.ResourceWithImportState = &apiKeyResource{}
)

// NewAPIKeyResource is a factory function for the resource.
func NewAPIKeyResource() resource.Resource {
	return &apiKeyResource{}
}

// apiKeyResource manages an XSOAR API key.
type apiKeyResource struct {
	backend api.XSOARBackend
}

// apiKeyResourceModel maps the resource schema data.
type apiKeyResourceModel struct {
	ID       types.String `tfsdk:"id"`
	Name     types.String `tfsdk:"name"`
	KeyValue types.String `tfsdk:"key_value"`
}

func (r *apiKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_key"
}

func (r *apiKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an API key on the XSOAR instance.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The internal identifier of the API key.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name (display label) of the API key.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_value": schema.StringAttribute{
				Description: "The actual API key string. Only available after creation.",
				Computed:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *apiKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *apiKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan apiKeyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := plan.Name.ValueString()

	created, err := r.backend.CreateAPIKey(name)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating API Key", fmt.Sprintf("Could not create API key %q: %s", name, err))
		return
	}

	plan.ID = types.StringValue(created.ID)
	plan.KeyValue = types.StringValue(created.Key)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *apiKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state apiKeyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := state.Name.ValueString()

	keyInfo, err := r.findAPIKeyByName(name)
	if err != nil {
		// API key not found; remove from state.
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(keyInfo.ID)
	// The key_value is not returned by the list endpoint; preserve the value from state.
	// state.KeyValue is already set from the existing state.

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *apiKeyResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	// No update is supported. Name changes force replacement via RequiresReplace.
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"API keys cannot be updated. Name changes require replacement.",
	)
}

func (r *apiKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state apiKeyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.backend.DeleteAPIKey(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting API Key", fmt.Sprintf("Could not delete API key %q: %s", state.Name.ValueString(), err))
		return
	}
}

func (r *apiKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID is the key name.
	// Note: key_value cannot be recovered on import; it will be empty.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

// findAPIKeyByName searches the list of API keys for a matching name.
func (r *apiKeyResource) findAPIKeyByName(name string) (*api.APIKeyInfo, error) {
	keys, err := r.backend.ListAPIKeys()
	if err != nil {
		return nil, fmt.Errorf("listing API keys: %w", err)
	}
	for _, k := range keys {
		if k.Name == name {
			return &k, nil
		}
	}
	return nil, fmt.Errorf("API key %q not found", name)
}

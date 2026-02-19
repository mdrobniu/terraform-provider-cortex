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
	_ resource.Resource                = &exclusionListResource{}
	_ resource.ResourceWithImportState = &exclusionListResource{}
)

// NewExclusionListResource is a factory function for the resource.
func NewExclusionListResource() resource.Resource {
	return &exclusionListResource{}
}

// exclusionListResource manages an indicator exclusion list entry in XSOAR.
type exclusionListResource struct {
	backend api.XSOARBackend
}

// exclusionListResourceModel maps the resource schema data.
type exclusionListResourceModel struct {
	ID      types.String `tfsdk:"id"`
	Value   types.String `tfsdk:"value"`
	Type    types.String `tfsdk:"type"`
	Reason  types.String `tfsdk:"reason"`
	Version types.Int64  `tfsdk:"version"`
}

func (r *exclusionListResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_exclusion_list"
}

func (r *exclusionListResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an indicator exclusion list entry in XSOAR.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the exclusion entry.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"value": schema.StringAttribute{
				Description: "The value to exclude (e.g., an IP address, CIDR range, domain, or regex pattern).",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Description: "The exclusion type: \"standard\" for exact match, \"CIDR\" for CIDR ranges, \"regex\" for regex patterns.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"reason": schema.StringAttribute{
				Description: "An optional reason for the exclusion.",
				Optional:    true,
			},
			"version": schema.Int64Attribute{
				Description: "The version number of the exclusion entry, used for optimistic concurrency control.",
				Computed:    true,
			},
		},
	}
}

func (r *exclusionListResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *exclusionListResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan exclusionListResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	entryData := map[string]interface{}{
		"value": plan.Value.ValueString(),
		"type":  plan.Type.ValueString(),
	}
	if !plan.Reason.IsNull() && !plan.Reason.IsUnknown() {
		entryData["reason"] = plan.Reason.ValueString()
	}

	entry, err := r.backend.AddExclusion(entryData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Exclusion Entry",
			fmt.Sprintf("Could not create exclusion for %q: %s", plan.Value.ValueString(), err),
		)
		return
	}

	plan.ID = types.StringValue(entry.ID)
	plan.Version = types.Int64Value(int64(entry.Version))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *exclusionListResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state exclusionListResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	entry, err := r.findExclusionByValue(state.Value.ValueString())
	if err != nil {
		// Exclusion entry no longer exists; remove from state.
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(entry.ID)
	state.Value = types.StringValue(entry.Value)
	state.Type = types.StringValue(entry.Type)
	state.Version = types.Int64Value(int64(entry.Version))

	if entry.Reason != "" {
		state.Reason = types.StringValue(entry.Reason)
	} else if state.Reason.IsNull() {
		state.Reason = types.StringNull()
	} else {
		state.Reason = types.StringNull()
	}

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *exclusionListResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan exclusionListResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state exclusionListResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Since value and type force replacement, only reason can change.
	entryData := map[string]interface{}{
		"id":      state.ID.ValueString(),
		"version": state.Version.ValueInt64(),
		"value":   plan.Value.ValueString(),
		"type":    plan.Type.ValueString(),
	}
	if !plan.Reason.IsNull() && !plan.Reason.IsUnknown() {
		entryData["reason"] = plan.Reason.ValueString()
	}

	entry, err := r.backend.UpdateExclusion(entryData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Exclusion Entry",
			fmt.Sprintf("Could not update exclusion for %q: %s", plan.Value.ValueString(), err),
		)
		return
	}

	plan.ID = types.StringValue(entry.ID)
	plan.Version = types.Int64Value(int64(entry.Version))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *exclusionListResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state exclusionListResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.backend.RemoveExclusion(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Exclusion Entry",
			fmt.Sprintf("Could not delete exclusion for %q: %s", state.Value.ValueString(), err),
		)
		return
	}
}

func (r *exclusionListResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import ID is the exclusion value.
	value := req.ID

	entry, err := r.findExclusionByValue(value)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Exclusion Entry",
			fmt.Sprintf("Could not find exclusion with value %q: %s", value, err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), entry.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("value"), entry.Value)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("type"), entry.Type)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("version"), int64(entry.Version))...)

	if entry.Reason != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("reason"), entry.Reason)...)
	}
}

// findExclusionByValue searches the exclusion list for an entry matching the given value.
func (r *exclusionListResource) findExclusionByValue(value string) (*api.ExclusionEntry, error) {
	entries, err := r.backend.GetExclusionList()
	if err != nil {
		return nil, fmt.Errorf("listing exclusion entries: %w", err)
	}
	for _, e := range entries {
		if e.Value == value {
			return &e, nil
		}
	}
	return nil, fmt.Errorf("exclusion entry with value %q not found", value)
}

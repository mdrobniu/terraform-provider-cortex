package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &haGroupResource{}
	_ resource.ResourceWithImportState = &haGroupResource{}
)

// NewHAGroupResource is a factory function for the resource.
func NewHAGroupResource() resource.Resource {
	return &haGroupResource{}
}

// haGroupResource manages an HA group in XSOAR.
type haGroupResource struct {
	backend api.XSOARBackend
}

// haGroupResourceModel maps the resource schema data.
type haGroupResourceModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	ElasticsearchURL   types.String `tfsdk:"elasticsearch_url"`
	ElasticIndexPrefix types.String `tfsdk:"elastic_index_prefix"`
	AccountIDs         types.List   `tfsdk:"account_ids"`
	HostIDs            types.List   `tfsdk:"host_ids"`
}

func (r *haGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ha_group"
}

func (r *haGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a High Availability (HA) group in XSOAR.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the HA group.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the HA group.",
				Required:    true,
			},
			"elasticsearch_url": schema.StringAttribute{
				Description: "The Elasticsearch URL for the HA group.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"elastic_index_prefix": schema.StringAttribute{
				Description: "The Elasticsearch index prefix for the HA group.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"account_ids": schema.ListAttribute{
				Description: "The list of account IDs associated with this HA group.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"host_ids": schema.ListAttribute{
				Description: "The list of host IDs associated with this HA group.",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *haGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *haGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan haGroupResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupData := map[string]interface{}{
		"name":                 plan.Name.ValueString(),
		"elasticsearchAddress": plan.ElasticsearchURL.ValueString(),
		"elasticIndexPrefix":   plan.ElasticIndexPrefix.ValueString(),
	}

	group, err := r.backend.CreateHAGroup(groupData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating HA Group",
			fmt.Sprintf("Could not create HA group %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	plan.ID = types.StringValue(group.ID)
	plan.Name = types.StringValue(group.Name)

	plan.AccountIDs = stringSliceToList(ctx, group.AccountIDs, &resp.Diagnostics)
	plan.HostIDs = stringSliceToList(ctx, group.HostIDs, &resp.Diagnostics)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *haGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state haGroupResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	group, err := r.backend.GetHAGroup(state.ID.ValueString())
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(group.ID)
	state.Name = types.StringValue(group.Name)
	state.ElasticsearchURL = types.StringValue(group.ElasticsearchURL)
	state.ElasticIndexPrefix = types.StringValue(group.ElasticIndexPrefix)

	state.AccountIDs = stringSliceToList(ctx, group.AccountIDs, &resp.Diagnostics)
	state.HostIDs = stringSliceToList(ctx, group.HostIDs, &resp.Diagnostics)

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *haGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan haGroupResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state haGroupResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create-or-update pattern: include the existing ID to update in place.
	groupData := map[string]interface{}{
		"id":                   state.ID.ValueString(),
		"name":                 plan.Name.ValueString(),
		"elasticsearchAddress": plan.ElasticsearchURL.ValueString(),
		"elasticIndexPrefix":   plan.ElasticIndexPrefix.ValueString(),
	}

	group, err := r.backend.CreateHAGroup(groupData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating HA Group",
			fmt.Sprintf("Could not update HA group %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	plan.ID = types.StringValue(group.ID)
	plan.Name = types.StringValue(group.Name)

	plan.AccountIDs = stringSliceToList(ctx, group.AccountIDs, &resp.Diagnostics)
	plan.HostIDs = stringSliceToList(ctx, group.HostIDs, &resp.Diagnostics)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *haGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state haGroupResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.backend.DeleteHAGroup(state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting HA Group",
			fmt.Sprintf("Could not delete HA group %q: %s", state.Name.ValueString(), err),
		)
		return
	}
}

func (r *haGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import ID is the HA group name. Look up by name to find the ID.
	name := req.ID

	groups, err := r.backend.ListHAGroups()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing HA Group",
			fmt.Sprintf("Could not list HA groups: %s", err),
		)
		return
	}

	var found *api.HAGroup
	for _, g := range groups {
		if g.Name == name {
			found = &g
			break
		}
	}
	if found == nil {
		resp.Diagnostics.AddError(
			"HA Group Not Found",
			fmt.Sprintf("No HA group found with name %q", name),
		)
		return
	}

	// Fetch the full HA group by ID.
	group, err := r.backend.GetHAGroup(found.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading HA Group",
			fmt.Sprintf("Could not read HA group %q: %s", found.ID, err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), group.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), group.Name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("elasticsearch_url"), group.ElasticsearchURL)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("elastic_index_prefix"), group.ElasticIndexPrefix)...)

	accountIDs := stringSliceToList(ctx, group.AccountIDs, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("account_ids"), accountIDs)...)

	hostIDs := stringSliceToList(ctx, group.HostIDs, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("host_ids"), hostIDs)...)
}

// stringSliceToList converts a Go string slice to a types.List, handling nil slices
// by producing an empty list rather than a null list.
func stringSliceToList(ctx context.Context, slice []string, diags *diag.Diagnostics) types.List {
	if slice == nil {
		slice = []string{}
	}
	list, d := types.ListValueFrom(ctx, types.StringType, slice)
	diags.Append(d...)
	return list
}

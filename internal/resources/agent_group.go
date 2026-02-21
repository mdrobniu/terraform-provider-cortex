package resources

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &agentGroupResource{}
	_ resource.ResourceWithImportState = &agentGroupResource{}
)

func NewAgentGroupResource() resource.Resource {
	return &agentGroupResource{}
}

type agentGroupResource struct {
	backend api.XSOARBackend
}

type agentGroupModel struct {
	GroupID     types.Int64  `tfsdk:"group_id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Type        types.String `tfsdk:"type"`
	Filter      types.String `tfsdk:"filter"`
	EndpointCount types.Int64  `tfsdk:"endpoint_count"`
}

func (r *agentGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent_group"
}

func (r *agentGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an endpoint agent group in XSIAM. " +
			"Agent groups organize endpoints into dynamic or static collections for policy assignment. " +
			"Requires webapp session authentication (session_token or cortex-login). " +
			"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
		Attributes: map[string]schema.Attribute{
			"group_id": schema.Int64Attribute{
				Description: "The unique numeric identifier of the agent group, assigned by XSIAM.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the agent group.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "A description of the agent group.",
				Optional:    true,
				Computed:    true,
			},
			"type": schema.StringAttribute{
				Description: "The group type. Valid values: DYNAMIC, STATIC. Cannot be changed after creation.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"filter": schema.StringAttribute{
				Description: "JSON filter expression for dynamic groups. Defines the criteria for automatic endpoint membership.",
				Optional:    true,
				Computed:    true,
			},
			"endpoint_count": schema.Int64Attribute{
				Description: "The number of endpoints currently in the group.",
				Computed:    true,
			},
		},
	}
}

func (r *agentGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *agentGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan agentGroupModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupData := map[string]interface{}{
		"name": plan.Name.ValueString(),
		"type": plan.Type.ValueString(),
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		groupData["description"] = plan.Description.ValueString()
	}
	if !plan.Filter.IsNull() && !plan.Filter.IsUnknown() {
		groupData["filter"] = plan.Filter.ValueString()
	}

	result, err := r.backend.CreateAgentGroup(groupData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Agent Group",
			fmt.Sprintf("Could not create agent group %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	setAgentGroupState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *agentGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state agentGroupModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := int(state.GroupID.ValueInt64())
	group, err := r.backend.GetAgentGroup(groupID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setAgentGroupState(&state, group)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *agentGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan agentGroupModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state agentGroupModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := int(state.GroupID.ValueInt64())
	groupData := map[string]interface{}{
		"name": plan.Name.ValueString(),
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		groupData["description"] = plan.Description.ValueString()
	}
	if !plan.Filter.IsNull() && !plan.Filter.IsUnknown() {
		groupData["filter"] = plan.Filter.ValueString()
	}

	result, err := r.backend.UpdateAgentGroup(groupID, groupData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Agent Group",
			fmt.Sprintf("Could not update agent group %d: %s", groupID, err),
		)
		return
	}

	setAgentGroupState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *agentGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state agentGroupModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := int(state.GroupID.ValueInt64())
	err := r.backend.DeleteAgentGroup(groupID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Agent Group",
			fmt.Sprintf("Could not delete agent group %d: %s", groupID, err),
		)
		return
	}
}

func (r *agentGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	groupID, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Agent Group",
			fmt.Sprintf("Invalid group ID %q: must be a numeric ID", req.ID),
		)
		return
	}

	group, err := r.backend.GetAgentGroup(groupID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Agent Group",
			fmt.Sprintf("Could not find agent group %d: %s", groupID, err),
		)
		return
	}

	var state agentGroupModel
	setAgentGroupState(&state, group)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setAgentGroupState(model *agentGroupModel, group *api.AgentGroup) {
	model.GroupID = types.Int64Value(int64(group.GroupID))
	model.Name = types.StringValue(group.Name)
	model.Type = types.StringValue(group.Type)
	model.EndpointCount = types.Int64Value(int64(group.Count))

	if group.Description != "" {
		model.Description = types.StringValue(group.Description)
	} else {
		model.Description = types.StringNull()
	}
	if group.Filter != "" {
		model.Filter = types.StringValue(group.Filter)
	} else {
		model.Filter = types.StringNull()
	}
}

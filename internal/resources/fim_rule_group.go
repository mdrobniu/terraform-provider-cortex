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
	_ resource.Resource                = &fimRuleGroupResource{}
	_ resource.ResourceWithImportState = &fimRuleGroupResource{}
)

func NewFIMRuleGroupResource() resource.Resource {
	return &fimRuleGroupResource{}
}

type fimRuleGroupResource struct {
	backend api.XSOARBackend
}

type fimRuleGroupModel struct {
	GroupID        types.Int64  `tfsdk:"group_id"`
	Name           types.String `tfsdk:"name"`
	Description    types.String `tfsdk:"description"`
	OSType         types.String `tfsdk:"os_type"`
	MonitoringMode types.String `tfsdk:"monitoring_mode"`
}

func (r *fimRuleGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fim_rule_group"
}

func (r *fimRuleGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a File Integrity Monitoring (FIM) rule group in XSIAM. " +
			"FIM rule groups organize file and registry monitoring rules by operating system. " +
			"Webapp API endpoints based on XSIAM V3.4; may differ on other versions. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"group_id": schema.Int64Attribute{
				Description: "The unique numeric identifier of the FIM rule group. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the FIM rule group. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "A description of the FIM rule group. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional:    true,
				Computed:    true,
			},
			"os_type": schema.StringAttribute{
				Description: "Operating system type. Valid values: WINDOWS, LINUX, MACOS. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"monitoring_mode": schema.StringAttribute{
				Description: "The monitoring mode for the rule group. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional:    true,
				Computed:    true,
			},
		},
	}
}

func (r *fimRuleGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *fimRuleGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan fimRuleGroupModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupData := map[string]interface{}{
		"NAME":    plan.Name.ValueString(),
		"OS_TYPE": plan.OSType.ValueString(),
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		groupData["DESCRIPTION"] = plan.Description.ValueString()
	}
	if !plan.MonitoringMode.IsNull() && !plan.MonitoringMode.IsUnknown() {
		groupData["MONITORING_MODE"] = plan.MonitoringMode.ValueString()
	}

	result, err := r.backend.CreateFIMRuleGroup(groupData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating FIM Rule Group",
			fmt.Sprintf("Could not create FIM rule group %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	setFIMRuleGroupState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *fimRuleGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state fimRuleGroupModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := int(state.GroupID.ValueInt64())
	group, err := r.backend.GetFIMRuleGroup(groupID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setFIMRuleGroupState(&state, group)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *fimRuleGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan fimRuleGroupModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state fimRuleGroupModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := int(state.GroupID.ValueInt64())
	groupData := map[string]interface{}{
		"NAME":    plan.Name.ValueString(),
		"OS_TYPE": plan.OSType.ValueString(),
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		groupData["DESCRIPTION"] = plan.Description.ValueString()
	}
	if !plan.MonitoringMode.IsNull() && !plan.MonitoringMode.IsUnknown() {
		groupData["MONITORING_MODE"] = plan.MonitoringMode.ValueString()
	}

	result, err := r.backend.UpdateFIMRuleGroup(groupID, groupData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating FIM Rule Group",
			fmt.Sprintf("Could not update FIM rule group %d: %s", groupID, err),
		)
		return
	}

	setFIMRuleGroupState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *fimRuleGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state fimRuleGroupModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := int(state.GroupID.ValueInt64())
	err := r.backend.DeleteFIMRuleGroup(groupID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting FIM Rule Group",
			fmt.Sprintf("Could not delete FIM rule group %d: %s", groupID, err),
		)
		return
	}
}

func (r *fimRuleGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	groupID, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing FIM Rule Group",
			fmt.Sprintf("Invalid group ID %q: must be a numeric ID", req.ID),
		)
		return
	}

	group, err := r.backend.GetFIMRuleGroup(groupID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing FIM Rule Group",
			fmt.Sprintf("Could not find FIM rule group %d: %s", groupID, err),
		)
		return
	}

	var state fimRuleGroupModel
	setFIMRuleGroupState(&state, group)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setFIMRuleGroupState(model *fimRuleGroupModel, group *api.FIMRuleGroup) {
	model.GroupID = types.Int64Value(int64(group.GroupID))
	model.Name = types.StringValue(group.Name)
	model.OSType = types.StringValue(group.OSType)

	if group.Description != "" {
		model.Description = types.StringValue(group.Description)
	} else {
		model.Description = types.StringNull()
	}
	if group.MonitoringMode != "" {
		model.MonitoringMode = types.StringValue(group.MonitoringMode)
	} else {
		model.MonitoringMode = types.StringNull()
	}
}

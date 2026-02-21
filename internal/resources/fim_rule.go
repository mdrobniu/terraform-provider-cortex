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
	_ resource.Resource                = &fimRuleResource{}
	_ resource.ResourceWithImportState = &fimRuleResource{}
)

func NewFIMRuleResource() resource.Resource {
	return &fimRuleResource{}
}

type fimRuleResource struct {
	backend api.XSOARBackend
}

type fimRuleModel struct {
	RuleID           types.Int64  `tfsdk:"rule_id"`
	Type             types.String `tfsdk:"type"`
	Path             types.String `tfsdk:"path"`
	Description      types.String `tfsdk:"description"`
	GroupID          types.Int64  `tfsdk:"group_id"`
	MonitorAllEvents types.Bool   `tfsdk:"monitor_all_events"`
}

func (r *fimRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fim_rule"
}

func (r *fimRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a File Integrity Monitoring (FIM) rule in XSIAM. " +
			"FIM rules define specific file paths or registry keys to monitor for changes. " +
			"Webapp API endpoints based on XSIAM V3.4; may differ on other versions. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"rule_id": schema.Int64Attribute{
				Description: "The unique numeric identifier of the FIM rule. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Computed:    true,
			},
			"type": schema.StringAttribute{
				Description: "Type of FIM rule. Valid values: FILE, REGISTRY. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"path": schema.StringAttribute{
				Description: "The file path or registry key to monitor. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "A description of the FIM rule. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional:    true,
				Computed:    true,
			},
			"group_id": schema.Int64Attribute{
				Description: "The FIM rule group ID this rule belongs to. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required:    true,
			},
			"monitor_all_events": schema.BoolAttribute{
				Description: "Whether to monitor all file system events. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional:    true,
				Computed:    true,
			},
		},
	}
}

func (r *fimRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *fimRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan fimRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleData := map[string]interface{}{
		"TYPE":     plan.Type.ValueString(),
		"PATH":     plan.Path.ValueString(),
		"GROUP_ID": plan.GroupID.ValueInt64(),
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		ruleData["DESCRIPTION"] = plan.Description.ValueString()
	}
	if !plan.MonitorAllEvents.IsNull() && !plan.MonitorAllEvents.IsUnknown() {
		ruleData["MONITOR_ALL_EVENTS"] = plan.MonitorAllEvents.ValueBool()
	}

	result, err := r.backend.CreateFIMRule(ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating FIM Rule",
			fmt.Sprintf("Could not create FIM rule for path %q: %s", plan.Path.ValueString(), err),
		)
		return
	}

	setFIMRuleState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *fimRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state fimRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	rule, err := r.backend.GetFIMRule(ruleID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setFIMRuleState(&state, rule)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *fimRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan fimRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state fimRuleModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	ruleData := map[string]interface{}{
		"TYPE":     plan.Type.ValueString(),
		"PATH":     plan.Path.ValueString(),
		"GROUP_ID": plan.GroupID.ValueInt64(),
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		ruleData["DESCRIPTION"] = plan.Description.ValueString()
	}
	if !plan.MonitorAllEvents.IsNull() && !plan.MonitorAllEvents.IsUnknown() {
		ruleData["MONITOR_ALL_EVENTS"] = plan.MonitorAllEvents.ValueBool()
	}

	result, err := r.backend.UpdateFIMRule(ruleID, ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating FIM Rule",
			fmt.Sprintf("Could not update FIM rule %d: %s", ruleID, err),
		)
		return
	}

	setFIMRuleState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *fimRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state fimRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	err := r.backend.DeleteFIMRule(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting FIM Rule",
			fmt.Sprintf("Could not delete FIM rule %d: %s", ruleID, err),
		)
		return
	}
}

func (r *fimRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ruleID, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing FIM Rule",
			fmt.Sprintf("Invalid rule ID %q: must be a numeric ID", req.ID),
		)
		return
	}

	rule, err := r.backend.GetFIMRule(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing FIM Rule",
			fmt.Sprintf("Could not find FIM rule %d: %s", ruleID, err),
		)
		return
	}

	var state fimRuleModel
	setFIMRuleState(&state, rule)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setFIMRuleState(model *fimRuleModel, rule *api.FIMRule) {
	model.RuleID = types.Int64Value(int64(rule.RuleID))
	model.Type = types.StringValue(rule.Type)
	model.Path = types.StringValue(rule.Path)
	model.GroupID = types.Int64Value(int64(rule.GroupID))
	model.MonitorAllEvents = types.BoolValue(rule.MonitorAllEvents)

	if rule.Description != "" {
		model.Description = types.StringValue(rule.Description)
	} else {
		model.Description = types.StringNull()
	}
}

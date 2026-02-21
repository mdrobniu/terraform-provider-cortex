package resources

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &timRuleResource{}
	_ resource.ResourceWithImportState = &timRuleResource{}
)

func NewTIMRuleResource() resource.Resource {
	return &timRuleResource{}
}

type timRuleResource struct {
	backend api.XSOARBackend
}

type timRuleModel struct {
	RuleID      types.Int64  `tfsdk:"rule_id"`
	Name        types.String `tfsdk:"name"`
	Type        types.String `tfsdk:"type"`
	Severity    types.String `tfsdk:"severity"`
	Status      types.String `tfsdk:"status"`
	Description types.String `tfsdk:"description"`
	Target      types.String `tfsdk:"target"`
}

func (r *timRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tim_rule"
}

func (r *timRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Threat Intelligence Management (TIM) rule in XSIAM. " +
			"TIM rules define detection logic for threat indicators. " +
			"Webapp API endpoints based on XSIAM V3.4; may differ on other versions. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"rule_id": schema.Int64Attribute{
				Description: "The unique numeric identifier of the TIM rule. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Computed: true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the TIM rule. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required: true,
			},
			"type": schema.StringAttribute{
				Description: "The rule type. Valid values: DETECTION. Defaults to DETECTION. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required: true,
			},
			"severity": schema.StringAttribute{
				Description: "Severity level. Valid values: SEV_010_INFO, SEV_020_LOW, SEV_030_MEDIUM, SEV_040_HIGH, SEV_050_CRITICAL. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required: true,
			},
			"status": schema.StringAttribute{
				Description: "Rule status. Valid values: ENABLED, DISABLED. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("DISABLED"),
			},
			"description": schema.StringAttribute{
				Description: "A description of the TIM rule. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional: true,
				Computed: true,
			},
			"target": schema.StringAttribute{
				Description: "Target filter or indicator values as JSON. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional: true,
				Computed: true,
			},
		},
	}
}

func (r *timRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *timRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan timRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleData := map[string]interface{}{
		"NAME":     plan.Name.ValueString(),
		"TYPE":     plan.Type.ValueString(),
		"SEVERITY": plan.Severity.ValueString(),
		"STATUS":   plan.Status.ValueString(),
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		ruleData["DESCRIPTION"] = plan.Description.ValueString()
	}
	if !plan.Target.IsNull() && !plan.Target.IsUnknown() {
		ruleData["TARGET"] = plan.Target.ValueString()
	}

	result, err := r.backend.CreateTIMRule(ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating TIM Rule",
			fmt.Sprintf("Could not create TIM rule %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	setTIMRuleState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *timRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state timRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	rule, err := r.backend.GetTIMRule(ruleID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setTIMRuleState(&state, rule)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *timRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan timRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state timRuleModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	ruleData := map[string]interface{}{
		"NAME":     plan.Name.ValueString(),
		"TYPE":     plan.Type.ValueString(),
		"SEVERITY": plan.Severity.ValueString(),
		"STATUS":   plan.Status.ValueString(),
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		ruleData["DESCRIPTION"] = plan.Description.ValueString()
	}
	if !plan.Target.IsNull() && !plan.Target.IsUnknown() {
		ruleData["TARGET"] = plan.Target.ValueString()
	}

	result, err := r.backend.UpdateTIMRule(ruleID, ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating TIM Rule",
			fmt.Sprintf("Could not update TIM rule %d: %s", ruleID, err),
		)
		return
	}

	setTIMRuleState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *timRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state timRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	err := r.backend.DeleteTIMRule(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting TIM Rule",
			fmt.Sprintf("Could not delete TIM rule %d: %s", ruleID, err),
		)
		return
	}
}

func (r *timRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ruleID, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing TIM Rule",
			fmt.Sprintf("Invalid rule ID %q: must be a numeric ID", req.ID),
		)
		return
	}

	rule, err := r.backend.GetTIMRule(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing TIM Rule",
			fmt.Sprintf("Could not find TIM rule %d: %s", ruleID, err),
		)
		return
	}

	var state timRuleModel
	setTIMRuleState(&state, rule)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setTIMRuleState(model *timRuleModel, rule *api.TIMRule) {
	model.RuleID = types.Int64Value(int64(rule.RuleID))
	model.Name = types.StringValue(rule.Name)
	model.Type = types.StringValue(rule.Type)
	model.Severity = types.StringValue(rule.Severity)
	model.Status = types.StringValue(rule.Status)

	if rule.Description != "" {
		model.Description = types.StringValue(rule.Description)
	} else {
		model.Description = types.StringNull()
	}
	if rule.Target != "" {
		model.Target = types.StringValue(rule.Target)
	} else {
		model.Target = types.StringNull()
	}
}

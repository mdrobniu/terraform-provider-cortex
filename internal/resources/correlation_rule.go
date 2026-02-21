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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &correlationRuleResource{}
	_ resource.ResourceWithImportState = &correlationRuleResource{}
)

func NewCorrelationRuleResource() resource.Resource {
	return &correlationRuleResource{}
}

type correlationRuleResource struct {
	backend api.XSOARBackend
}

type correlationRuleModel struct {
	RuleID          types.Int64  `tfsdk:"rule_id"`
	Name            types.String `tfsdk:"name"`
	Description     types.String `tfsdk:"description"`
	Severity        types.String `tfsdk:"severity"`
	Status          types.String `tfsdk:"status"`
	XQLQuery        types.String `tfsdk:"xql_query"`
	ExecutionMode   types.String `tfsdk:"execution_mode"`
	SearchWindow    types.String `tfsdk:"search_window"`
	SimpleSchedule  types.String `tfsdk:"simple_schedule"`
	Dataset         types.String `tfsdk:"dataset"`
	Timezone        types.String `tfsdk:"timezone"`
	AlertDomain     types.String `tfsdk:"alert_domain"`
	AlertCategory   types.String `tfsdk:"alert_category"`
	AlertName       types.String `tfsdk:"alert_name"`
	MappingStrategy types.String `tfsdk:"mapping_strategy"`
	Action          types.String `tfsdk:"action"`
}

func (r *correlationRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_correlation_rule"
}

func (r *correlationRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a correlation rule in XSIAM. " +
			"Correlation rules define XQL-based detection logic that generates alerts. " +
			"Not available on XSOAR 8. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"rule_id": schema.Int64Attribute{
				Description: "The unique numeric identifier of the correlation rule.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the correlation rule.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "A description of the correlation rule.",
				Optional:    true,
				Computed:    true,
			},
			"severity": schema.StringAttribute{
				Description: "Severity level. Valid values: SEV_010_INFO, SEV_020_LOW, SEV_030_MEDIUM, SEV_040_HIGH, SEV_050_CRITICAL.",
				Required:    true,
			},
			"status": schema.StringAttribute{
				Description: "Rule status. Valid values: ENABLED, DISABLED.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("DISABLED"),
			},
			"xql_query": schema.StringAttribute{
				Description: "The XQL query that defines the detection logic.",
				Required:    true,
			},
			"execution_mode": schema.StringAttribute{
				Description: "Execution mode. Valid values: SCHEDULED, REALTIME.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("SCHEDULED"),
			},
			"search_window": schema.StringAttribute{
				Description: "Time window for the search (e.g., '1 hours', '30 minutes').",
				Optional:    true,
				Computed:    true,
			},
			"simple_schedule": schema.StringAttribute{
				Description: "Schedule interval (e.g., '10 minutes', '1 hours').",
				Optional:    true,
				Computed:    true,
			},
			"dataset": schema.StringAttribute{
				Description: "Target dataset (e.g., 'alerts').",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("alerts"),
			},
			"timezone": schema.StringAttribute{
				Description: "Timezone for the schedule (e.g., 'UTC', 'America/New_York').",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("UTC"),
			},
			"alert_domain": schema.StringAttribute{
				Description: "Alert domain (e.g., 'DOMAIN_SECURITY').",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("DOMAIN_SECURITY"),
			},
			"alert_category": schema.StringAttribute{
				Description: "Alert category (e.g., 'INFILTRATION', 'MALWARE', 'COMMAND_AND_CONTROL').",
				Optional:    true,
				Computed:    true,
			},
			"alert_name": schema.StringAttribute{
				Description: "Custom alert name. Defaults to the rule name if not set.",
				Optional:    true,
				Computed:    true,
			},
			"mapping_strategy": schema.StringAttribute{
				Description: "Alert field mapping strategy. Valid values: AUTO, MANUAL.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("AUTO"),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"action": schema.StringAttribute{
				Description: "Action to take when the rule triggers. Valid values: ALERTS.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("ALERTS"),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *correlationRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *correlationRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan correlationRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleData := map[string]interface{}{
		"NAME":             plan.Name.ValueString(),
		"SEVERITY":         plan.Severity.ValueString(),
		"STATUS":           plan.Status.ValueString(),
		"XQL_QUERY":        plan.XQLQuery.ValueString(),
		"EXECUTION_MODE":   plan.ExecutionMode.ValueString(),
		"DATASET":          plan.Dataset.ValueString(),
		"TIMEZONE":         plan.Timezone.ValueString(),
		"ALERT_DOMAIN":     plan.AlertDomain.ValueString(),
		"MAPPING_STRATEGY": plan.MappingStrategy.ValueString(),
		"ACTION":           plan.Action.ValueString(),
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		ruleData["DESCRIPTION"] = plan.Description.ValueString()
	}
	if !plan.SearchWindow.IsNull() && !plan.SearchWindow.IsUnknown() {
		ruleData["SEARCH_WINDOW"] = plan.SearchWindow.ValueString()
	}
	if !plan.SimpleSchedule.IsNull() && !plan.SimpleSchedule.IsUnknown() {
		ruleData["SIMPLE_SCHEDULE"] = plan.SimpleSchedule.ValueString()
	}
	if !plan.AlertCategory.IsNull() && !plan.AlertCategory.IsUnknown() {
		ruleData["ALERT_CATEGORY"] = plan.AlertCategory.ValueString()
	}
	if !plan.AlertName.IsNull() && !plan.AlertName.IsUnknown() {
		ruleData["ALERT_NAME"] = plan.AlertName.ValueString()
	} else {
		ruleData["ALERT_NAME"] = plan.Name.ValueString()
	}

	result, err := r.backend.CreateCorrelationRule(ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Correlation Rule",
			fmt.Sprintf("Could not create correlation rule %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	setCorrelationRuleState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *correlationRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state correlationRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	rule, err := r.backend.GetCorrelationRule(ruleID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setCorrelationRuleState(&state, rule)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *correlationRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan correlationRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state correlationRuleModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	ruleData := map[string]interface{}{
		"NAME":             plan.Name.ValueString(),
		"SEVERITY":         plan.Severity.ValueString(),
		"STATUS":           plan.Status.ValueString(),
		"XQL_QUERY":        plan.XQLQuery.ValueString(),
		"EXECUTION_MODE":   plan.ExecutionMode.ValueString(),
		"DATASET":          plan.Dataset.ValueString(),
		"TIMEZONE":         plan.Timezone.ValueString(),
		"ALERT_DOMAIN":     plan.AlertDomain.ValueString(),
		"MAPPING_STRATEGY": plan.MappingStrategy.ValueString(),
		"ACTION":           plan.Action.ValueString(),
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		ruleData["DESCRIPTION"] = plan.Description.ValueString()
	}
	if !plan.SearchWindow.IsNull() && !plan.SearchWindow.IsUnknown() {
		ruleData["SEARCH_WINDOW"] = plan.SearchWindow.ValueString()
	}
	if !plan.SimpleSchedule.IsNull() && !plan.SimpleSchedule.IsUnknown() {
		ruleData["SIMPLE_SCHEDULE"] = plan.SimpleSchedule.ValueString()
	}
	if !plan.AlertCategory.IsNull() && !plan.AlertCategory.IsUnknown() {
		ruleData["ALERT_CATEGORY"] = plan.AlertCategory.ValueString()
	}
	if !plan.AlertName.IsNull() && !plan.AlertName.IsUnknown() {
		ruleData["ALERT_NAME"] = plan.AlertName.ValueString()
	}

	result, err := r.backend.UpdateCorrelationRule(ruleID, ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Correlation Rule",
			fmt.Sprintf("Could not update correlation rule %d: %s", ruleID, err),
		)
		return
	}

	setCorrelationRuleState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *correlationRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state correlationRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	err := r.backend.DeleteCorrelationRule(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Correlation Rule",
			fmt.Sprintf("Could not delete correlation rule %d: %s", ruleID, err),
		)
		return
	}
}

func (r *correlationRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ruleID, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Correlation Rule",
			fmt.Sprintf("Invalid rule ID %q: must be a numeric ID", req.ID),
		)
		return
	}

	rule, err := r.backend.GetCorrelationRule(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Correlation Rule",
			fmt.Sprintf("Could not find correlation rule %d: %s", ruleID, err),
		)
		return
	}

	var state correlationRuleModel
	setCorrelationRuleState(&state, rule)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setCorrelationRuleState(model *correlationRuleModel, rule *api.CorrelationRule) {
	model.RuleID = types.Int64Value(int64(rule.RuleID))
	model.Name = types.StringValue(rule.Name)
	model.Severity = types.StringValue(rule.Severity)
	model.Status = types.StringValue(rule.Status)
	model.XQLQuery = types.StringValue(rule.XQLQuery)
	model.ExecutionMode = types.StringValue(rule.ExecutionMode)
	model.Dataset = types.StringValue(rule.Dataset)
	model.Timezone = types.StringValue(rule.Timezone)
	model.AlertDomain = types.StringValue(rule.AlertDomain)
	model.MappingStrategy = types.StringValue(rule.MappingStrategy)
	model.Action = types.StringValue(rule.Action)

	if rule.Description != "" {
		model.Description = types.StringValue(rule.Description)
	} else {
		model.Description = types.StringNull()
	}
	if rule.SearchWindow != "" {
		model.SearchWindow = types.StringValue(rule.SearchWindow)
	}
	if rule.SimpleSchedule != "" {
		model.SimpleSchedule = types.StringValue(rule.SimpleSchedule)
	}
	if rule.AlertCategory != "" {
		model.AlertCategory = types.StringValue(rule.AlertCategory)
	}
	if rule.AlertName != "" {
		model.AlertName = types.StringValue(rule.AlertName)
	}
}

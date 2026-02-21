package resources

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &iocRuleResource{}
	_ resource.ResourceWithImportState = &iocRuleResource{}
)

func NewIOCRuleResource() resource.Resource {
	return &iocRuleResource{}
}

type iocRuleResource struct {
	backend api.XSOARBackend
}

type iocRuleModel struct {
	RuleID       types.Int64  `tfsdk:"rule_id"`
	Severity     types.String `tfsdk:"severity"`
	Indicator    types.String `tfsdk:"indicator"`
	IOCType      types.String `tfsdk:"ioc_type"`
	Comment      types.String `tfsdk:"comment"`
	Status       types.String `tfsdk:"status"`
	IsDefaultTTL types.Bool   `tfsdk:"is_default_ttl"`
	Reputation   types.String `tfsdk:"reputation"`
	Reliability  types.String `tfsdk:"reliability"`
}

func (r *iocRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ioc_rule"
}

func (r *iocRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an IOC (Indicator of Compromise) rule in XSIAM. " +
			"IOC rules define threat indicators that trigger alerts when matched against endpoint data. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"rule_id": schema.Int64Attribute{
				Description: "The unique numeric identifier of the IOC rule.",
				Computed:    true,
			},
			"severity": schema.StringAttribute{
				Description: "Severity level. Valid values: SEV_010_INFO, SEV_020_LOW, SEV_030_MEDIUM, SEV_040_HIGH, SEV_050_CRITICAL.",
				Required:    true,
			},
			"indicator": schema.StringAttribute{
				Description: "The indicator value (IP address, domain, hash, filename, etc.).",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ioc_type": schema.StringAttribute{
				Description: "Type of IOC. Valid values: IP, DOMAIN_NAME, HASH, PATH, FILENAME, EMAIL_ADDRESS, URL.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"comment": schema.StringAttribute{
				Description: "Comment or description for the IOC rule.",
				Optional:    true,
				Computed:    true,
			},
			"status": schema.StringAttribute{
				Description: "Rule status (read-only, set by the system).",
				Computed:    true,
			},
			"is_default_ttl": schema.BoolAttribute{
				Description: "Whether to use the default TTL for this IOC type.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"reputation": schema.StringAttribute{
				Description: "Reputation score for the indicator.",
				Optional:    true,
				Computed:    true,
			},
			"reliability": schema.StringAttribute{
				Description: "Reliability rating for the indicator.",
				Optional:    true,
				Computed:    true,
			},
		},
	}
}

func (r *iocRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *iocRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan iocRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleData := map[string]interface{}{
		"RULE_SEVERITY":  plan.Severity.ValueString(),
		"RULE_INDICATOR": plan.Indicator.ValueString(),
		"IOC_TYPE":       plan.IOCType.ValueString(),
		"RULE_COMMENT":   plan.Comment.ValueString(),
		"IS_DEFAULT_TTL": plan.IsDefaultTTL.ValueBool(),
	}

	if !plan.Reputation.IsNull() && !plan.Reputation.IsUnknown() && plan.Reputation.ValueString() != "" {
		ruleData["REPUTATION"] = plan.Reputation.ValueString()
	} else {
		ruleData["REPUTATION"] = nil
	}
	if !plan.Reliability.IsNull() && !plan.Reliability.IsUnknown() && plan.Reliability.ValueString() != "" {
		ruleData["RELIABILITY"] = plan.Reliability.ValueString()
	} else {
		ruleData["RELIABILITY"] = nil
	}

	result, err := r.backend.CreateIOCRule(ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating IOC Rule",
			fmt.Sprintf("Could not create IOC rule for indicator %q: %s", plan.Indicator.ValueString(), err),
		)
		return
	}

	setIOCRuleState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *iocRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state iocRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	rule, err := r.backend.GetIOCRule(ruleID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setIOCRuleState(&state, rule)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *iocRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// IOC rules don't have a direct update API; the indicator and type are immutable.
	// For severity/comment changes, we'd need to delete and recreate.
	// For now, we preserve the existing state on update attempts.
	var plan iocRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state iocRuleModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete old rule and create new one
	ruleID := int(state.RuleID.ValueInt64())
	err := r.backend.DeleteIOCRule(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating IOC Rule",
			fmt.Sprintf("Could not delete old IOC rule %d for recreation: %s", ruleID, err),
		)
		return
	}

	ruleData := map[string]interface{}{
		"RULE_SEVERITY":  plan.Severity.ValueString(),
		"RULE_INDICATOR": plan.Indicator.ValueString(),
		"IOC_TYPE":       plan.IOCType.ValueString(),
		"RULE_COMMENT":   plan.Comment.ValueString(),
		"IS_DEFAULT_TTL": plan.IsDefaultTTL.ValueBool(),
	}

	if !plan.Reputation.IsNull() && !plan.Reputation.IsUnknown() && plan.Reputation.ValueString() != "" {
		ruleData["REPUTATION"] = plan.Reputation.ValueString()
	} else {
		ruleData["REPUTATION"] = nil
	}
	if !plan.Reliability.IsNull() && !plan.Reliability.IsUnknown() && plan.Reliability.ValueString() != "" {
		ruleData["RELIABILITY"] = plan.Reliability.ValueString()
	} else {
		ruleData["RELIABILITY"] = nil
	}

	result, err := r.backend.CreateIOCRule(ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating IOC Rule",
			fmt.Sprintf("Could not recreate IOC rule: %s", err),
		)
		return
	}

	setIOCRuleState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *iocRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state iocRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	err := r.backend.DeleteIOCRule(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting IOC Rule",
			fmt.Sprintf("Could not delete IOC rule %d: %s", ruleID, err),
		)
		return
	}
}

func (r *iocRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ruleID, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing IOC Rule",
			fmt.Sprintf("Invalid rule ID %q: must be a numeric ID", req.ID),
		)
		return
	}

	rule, err := r.backend.GetIOCRule(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing IOC Rule",
			fmt.Sprintf("Could not find IOC rule %d: %s", ruleID, err),
		)
		return
	}

	var state iocRuleModel
	setIOCRuleState(&state, rule)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setIOCRuleState(model *iocRuleModel, rule *api.IOCRule) {
	model.RuleID = types.Int64Value(int64(rule.RuleID))
	model.Severity = types.StringValue(rule.Severity)
	model.Indicator = types.StringValue(rule.Indicator)
	model.IOCType = types.StringValue(rule.IOCType)
	model.Status = types.StringValue(rule.Status)
	model.IsDefaultTTL = types.BoolValue(rule.IsDefaultTTL)

	if rule.Comment != "" {
		model.Comment = types.StringValue(rule.Comment)
	} else {
		model.Comment = types.StringValue("")
	}
	if rule.Reputation != "" {
		model.Reputation = types.StringValue(rule.Reputation)
	} else {
		model.Reputation = types.StringNull()
	}
	if rule.Reliability != "" {
		model.Reliability = types.StringValue(rule.Reliability)
	} else {
		model.Reliability = types.StringNull()
	}
}

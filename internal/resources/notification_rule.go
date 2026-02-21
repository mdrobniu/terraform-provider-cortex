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
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &notificationRuleResource{}
	_ resource.ResourceWithImportState = &notificationRuleResource{}
)

func NewNotificationRuleResource() resource.Resource {
	return &notificationRuleResource{}
}

type notificationRuleResource struct {
	backend api.XSOARBackend
}

type notificationRuleModel struct {
	RuleID                types.Int64  `tfsdk:"rule_id"`
	Name                  types.String `tfsdk:"name"`
	Description           types.String `tfsdk:"description"`
	ForwardType           types.String `tfsdk:"forward_type"`
	Filter                types.String `tfsdk:"filter"`
	EmailDistributionList types.List   `tfsdk:"email_distribution_list"`
	EmailAggregation      types.Int64  `tfsdk:"email_aggregation"`
	SyslogEnabled         types.Bool   `tfsdk:"syslog_enabled"`
	Enabled               types.Bool   `tfsdk:"enabled"`
}

func (r *notificationRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_rule"
}

func (r *notificationRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an alert notification/forwarding rule in XSIAM. " +
			"Notification rules define how alerts or audit events are forwarded via email or syslog. " +
			"Webapp API endpoints based on XSIAM V3.4; may differ on other versions. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"rule_id": schema.Int64Attribute{
				Description: "The unique numeric identifier of the notification rule. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the notification rule. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "A description of the notification rule. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional:    true,
				Computed:    true,
			},
			"forward_type": schema.StringAttribute{
				Description: "The type of events to forward. Valid values: Alert, Audit. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required:    true,
			},
			"filter": schema.StringAttribute{
				Description: "JSON alert filter expression. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional:    true,
				Computed:    true,
			},
			"email_distribution_list": schema.ListAttribute{
				Description: "List of email addresses to receive notifications. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"email_aggregation": schema.Int64Attribute{
				Description: "Email aggregation interval in minutes. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional:    true,
				Computed:    true,
			},
			"syslog_enabled": schema.BoolAttribute{
				Description: "Whether syslog forwarding is enabled for this rule. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional:    true,
				Computed:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the notification rule is enabled. Default: true. Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
		},
	}
}

func (r *notificationRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *notificationRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan notificationRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleData := r.buildPayload(ctx, &plan)

	result, err := r.backend.CreateNotificationRule(ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Notification Rule",
			fmt.Sprintf("Could not create notification rule %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	setNotificationRuleState(ctx, &plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *notificationRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state notificationRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	rule, err := r.backend.GetNotificationRule(ruleID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setNotificationRuleState(ctx, &state, rule)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *notificationRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan notificationRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state notificationRuleModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	ruleData := r.buildPayload(ctx, &plan)

	result, err := r.backend.UpdateNotificationRule(ruleID, ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Notification Rule",
			fmt.Sprintf("Could not update notification rule %d: %s", ruleID, err),
		)
		return
	}

	setNotificationRuleState(ctx, &plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *notificationRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state notificationRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	err := r.backend.DeleteNotificationRule(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Notification Rule",
			fmt.Sprintf("Could not delete notification rule %d: %s", ruleID, err),
		)
		return
	}
}

func (r *notificationRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ruleID, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Notification Rule",
			fmt.Sprintf("Invalid rule ID %q: must be a numeric ID", req.ID),
		)
		return
	}

	rule, err := r.backend.GetNotificationRule(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Notification Rule",
			fmt.Sprintf("Could not find notification rule %d: %s", ruleID, err),
		)
		return
	}

	var state notificationRuleModel
	setNotificationRuleState(ctx, &state, rule)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *notificationRuleResource) buildPayload(ctx context.Context, model *notificationRuleModel) map[string]interface{} {
	payload := map[string]interface{}{
		"name":         model.Name.ValueString(),
		"forward_type": model.ForwardType.ValueString(),
		"enabled":      model.Enabled.ValueBool(),
	}

	if !model.Description.IsNull() && !model.Description.IsUnknown() {
		payload["description"] = model.Description.ValueString()
	}
	if !model.Filter.IsNull() && !model.Filter.IsUnknown() {
		payload["filter"] = model.Filter.ValueString()
	}
	if !model.EmailAggregation.IsNull() && !model.EmailAggregation.IsUnknown() {
		payload["email_aggregation"] = model.EmailAggregation.ValueInt64()
	}
	if !model.SyslogEnabled.IsNull() && !model.SyslogEnabled.IsUnknown() {
		payload["syslog_enabled"] = model.SyslogEnabled.ValueBool()
	}

	// Convert email distribution list
	emailList := []string{}
	if !model.EmailDistributionList.IsNull() && !model.EmailDistributionList.IsUnknown() {
		model.EmailDistributionList.ElementsAs(ctx, &emailList, false)
	}
	payload["email_distribution_list"] = emailList

	return payload
}

func setNotificationRuleState(ctx context.Context, model *notificationRuleModel, rule *api.NotificationRule) {
	model.RuleID = types.Int64Value(int64(rule.RuleID))
	model.Name = types.StringValue(rule.Name)
	model.ForwardType = types.StringValue(rule.ForwardType)
	model.Enabled = types.BoolValue(rule.Enabled)
	model.SyslogEnabled = types.BoolValue(rule.SyslogEnabled)

	if rule.Description != "" {
		model.Description = types.StringValue(rule.Description)
	} else {
		model.Description = types.StringNull()
	}
	if rule.Filter != "" {
		model.Filter = types.StringValue(rule.Filter)
	} else {
		model.Filter = types.StringNull()
	}
	if rule.EmailAggregation != 0 {
		model.EmailAggregation = types.Int64Value(int64(rule.EmailAggregation))
	} else {
		model.EmailAggregation = types.Int64Null()
	}

	// Convert email distribution list
	if rule.EmailDistributionList == nil {
		rule.EmailDistributionList = []string{}
	}
	emailList, _ := types.ListValueFrom(ctx, types.StringType, rule.EmailDistributionList)
	model.EmailDistributionList = emailList
}

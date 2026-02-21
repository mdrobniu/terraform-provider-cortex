package resources

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &rulesExceptionResource{}
	_ resource.ResourceWithImportState = &rulesExceptionResource{}
)

func NewRulesExceptionResource() resource.Resource {
	return &rulesExceptionResource{}
}

type rulesExceptionResource struct {
	backend api.XSOARBackend
}

type rulesExceptionModel struct {
	RuleID      types.Int64  `tfsdk:"rule_id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Status      types.String `tfsdk:"status"`
	AlertID     types.String `tfsdk:"alert_id"`
	Filter      types.String `tfsdk:"filter"`
}

func (r *rulesExceptionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rules_exception"
}

func (r *rulesExceptionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a rules exception in XSIAM. " +
			"Rules exceptions define exclusions from detection rule triggers. " +
			"This resource does not support in-place updates; changes force replacement (delete and recreate). " +
			"Webapp API endpoints based on XSIAM V3.4; may differ on other versions. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"rule_id": schema.Int64Attribute{
				Description: "The unique numeric identifier of the rules exception. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Computed: true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the rules exception. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required: true,
			},
			"description": schema.StringAttribute{
				Description: "A description of the rules exception. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional: true,
				Computed: true,
			},
			"status": schema.StringAttribute{
				Description: "Exception status (read-only, set by the system). " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Computed: true,
			},
			"alert_id": schema.StringAttribute{
				Description: "The alert ID this exception applies to. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional: true,
			},
			"filter": schema.StringAttribute{
				Description: "Filter definition as JSON that specifies exception conditions. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional: true,
			},
		},
	}
}

func (r *rulesExceptionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *rulesExceptionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan rulesExceptionModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleData := map[string]interface{}{
		"NAME": plan.Name.ValueString(),
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		ruleData["DESCRIPTION"] = plan.Description.ValueString()
	}
	if !plan.AlertID.IsNull() && !plan.AlertID.IsUnknown() {
		ruleData["ALERT_ID"] = plan.AlertID.ValueString()
	}
	if !plan.Filter.IsNull() && !plan.Filter.IsUnknown() {
		ruleData["FILTER"] = plan.Filter.ValueString()
	}

	result, err := r.backend.CreateRulesException(ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Rules Exception",
			fmt.Sprintf("Could not create rules exception %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	setRulesExceptionState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *rulesExceptionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state rulesExceptionModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	rule, err := r.backend.GetRulesException(ruleID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setRulesExceptionState(&state, rule)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *rulesExceptionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// No update API available. Delete and recreate.
	var plan rulesExceptionModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state rulesExceptionModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete old exception.
	oldRuleID := int(state.RuleID.ValueInt64())
	err := r.backend.DeleteRulesException(oldRuleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Rules Exception",
			fmt.Sprintf("Could not delete old rules exception %d for recreation: %s", oldRuleID, err),
		)
		return
	}

	// Recreate with new values.
	ruleData := map[string]interface{}{
		"NAME": plan.Name.ValueString(),
	}

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		ruleData["DESCRIPTION"] = plan.Description.ValueString()
	}
	if !plan.AlertID.IsNull() && !plan.AlertID.IsUnknown() {
		ruleData["ALERT_ID"] = plan.AlertID.ValueString()
	}
	if !plan.Filter.IsNull() && !plan.Filter.IsUnknown() {
		ruleData["FILTER"] = plan.Filter.ValueString()
	}

	result, err := r.backend.CreateRulesException(ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Rules Exception",
			fmt.Sprintf("Could not recreate rules exception %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	setRulesExceptionState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *rulesExceptionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state rulesExceptionModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	err := r.backend.DeleteRulesException(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Rules Exception",
			fmt.Sprintf("Could not delete rules exception %d: %s", ruleID, err),
		)
		return
	}
}

func (r *rulesExceptionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ruleID, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Rules Exception",
			fmt.Sprintf("Invalid rule ID %q: must be a numeric ID", req.ID),
		)
		return
	}

	rule, err := r.backend.GetRulesException(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Rules Exception",
			fmt.Sprintf("Could not find rules exception %d: %s", ruleID, err),
		)
		return
	}

	var state rulesExceptionModel
	setRulesExceptionState(&state, rule)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setRulesExceptionState(model *rulesExceptionModel, rule *api.RulesException) {
	model.RuleID = types.Int64Value(int64(rule.RuleID))
	model.Name = types.StringValue(rule.Name)
	model.Status = types.StringValue(rule.Status)

	if rule.Description != "" {
		model.Description = types.StringValue(rule.Description)
	} else {
		model.Description = types.StringNull()
	}
	if rule.AlertID != "" {
		model.AlertID = types.StringValue(rule.AlertID)
	}
	if rule.Filter != "" {
		model.Filter = types.StringValue(rule.Filter)
	}
}

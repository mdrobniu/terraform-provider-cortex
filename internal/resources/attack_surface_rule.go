package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &attackSurfaceRuleResource{}
	_ resource.ResourceWithImportState = &attackSurfaceRuleResource{}
)

func NewAttackSurfaceRuleResource() resource.Resource {
	return &attackSurfaceRuleResource{}
}

type attackSurfaceRuleResource struct {
	backend api.XSOARBackend
}

type attackSurfaceRuleModel struct {
	IssueTypeID   types.String `tfsdk:"issue_type_id"`
	IssueTypeName types.String `tfsdk:"issue_type_name"`
	EnabledStatus types.String `tfsdk:"enabled_status"`
	Priority      types.String `tfsdk:"priority"`
	Description   types.String `tfsdk:"description"`
}

func (r *attackSurfaceRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_attack_surface_rule"
}

func (r *attackSurfaceRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an attack surface management rule in XSIAM. " +
			"These are system-defined rules that cannot be created or deleted, only updated. " +
			"Use terraform import to bring existing rules under management. " +
			"Webapp API endpoints based on XSIAM V3.4; may differ on other versions. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"issue_type_id": schema.StringAttribute{
				Description: "The unique identifier of the attack surface rule (system-defined). " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"issue_type_name": schema.StringAttribute{
				Description: "The display name of the attack surface rule (system-defined, read-only). " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Computed: true,
			},
			"enabled_status": schema.StringAttribute{
				Description: "Whether the rule is enabled. Valid values: Enabled, Disabled. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required: true,
			},
			"priority": schema.StringAttribute{
				Description: "Rule priority. Valid values: High, Medium, Low. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Required: true,
			},
			"description": schema.StringAttribute{
				Description: "The description of the attack surface rule (system-defined, read-only). " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Computed: true,
			},
		},
	}
}

func (r *attackSurfaceRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *attackSurfaceRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan attackSurfaceRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// System-defined rules cannot be created. Verify the rule exists by reading it,
	// then update it with the desired settings.
	issueTypeID := plan.IssueTypeID.ValueString()
	rule, err := r.backend.GetAttackSurfaceRule(issueTypeID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Attack Surface Rule",
			fmt.Sprintf("Could not find system-defined attack surface rule %q: %s. "+
				"Attack surface rules are system-defined and must already exist.", issueTypeID, err),
		)
		return
	}

	// Update the rule with the desired settings.
	ruleData := map[string]interface{}{
		"enabled_status": plan.EnabledStatus.ValueString(),
		"priority":       plan.Priority.ValueString(),
	}

	updated, err := r.backend.UpdateAttackSurfaceRule(issueTypeID, ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Attack Surface Rule",
			fmt.Sprintf("Could not update attack surface rule %q: %s", issueTypeID, err),
		)
		return
	}

	// Prefer updated result, fall back to read result for computed fields.
	if updated != nil {
		rule = updated
	}

	setAttackSurfaceRuleState(&plan, rule)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *attackSurfaceRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state attackSurfaceRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	issueTypeID := state.IssueTypeID.ValueString()
	rule, err := r.backend.GetAttackSurfaceRule(issueTypeID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setAttackSurfaceRuleState(&state, rule)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *attackSurfaceRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan attackSurfaceRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	issueTypeID := plan.IssueTypeID.ValueString()
	ruleData := map[string]interface{}{
		"enabled_status": plan.EnabledStatus.ValueString(),
		"priority":       plan.Priority.ValueString(),
	}

	result, err := r.backend.UpdateAttackSurfaceRule(issueTypeID, ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Attack Surface Rule",
			fmt.Sprintf("Could not update attack surface rule %q: %s", issueTypeID, err),
		)
		return
	}

	setAttackSurfaceRuleState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *attackSurfaceRuleResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// System-defined rules cannot be deleted. Remove from state only (no-op).
}

func (r *attackSurfaceRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	issueTypeID := req.ID

	rule, err := r.backend.GetAttackSurfaceRule(issueTypeID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Attack Surface Rule",
			fmt.Sprintf("Could not find attack surface rule %q: %s", issueTypeID, err),
		)
		return
	}

	var state attackSurfaceRuleModel
	setAttackSurfaceRuleState(&state, rule)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setAttackSurfaceRuleState(model *attackSurfaceRuleModel, rule *api.AttackSurfaceRule) {
	model.IssueTypeID = types.StringValue(rule.IssueTypeID)
	model.EnabledStatus = types.StringValue(rule.EnabledStatus)
	model.Priority = types.StringValue(rule.Priority)

	if rule.IssueTypeName != "" {
		model.IssueTypeName = types.StringValue(rule.IssueTypeName)
	} else {
		model.IssueTypeName = types.StringNull()
	}
	if rule.Description != "" {
		model.Description = types.StringValue(rule.Description)
	} else {
		model.Description = types.StringNull()
	}
}

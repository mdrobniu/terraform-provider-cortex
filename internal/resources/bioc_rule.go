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
	_ resource.Resource                = &biocRuleResource{}
	_ resource.ResourceWithImportState = &biocRuleResource{}
)

func NewBIOCRuleResource() resource.Resource {
	return &biocRuleResource{}
}

type biocRuleResource struct {
	backend api.XSOARBackend
}

type biocRuleModel struct {
	RuleID         types.Int64  `tfsdk:"rule_id"`
	Name           types.String `tfsdk:"name"`
	Severity       types.String `tfsdk:"severity"`
	Status         types.String `tfsdk:"status"`
	Category       types.String `tfsdk:"category"`
	Comment        types.String `tfsdk:"comment"`
	Source         types.String `tfsdk:"source"`
	IsXQL          types.Bool   `tfsdk:"is_xql"`
	MitreTactic    types.List   `tfsdk:"mitre_tactic"`
	MitreTechnique types.List   `tfsdk:"mitre_technique"`
	IndicatorText  types.String `tfsdk:"indicator_text"`
}

func (r *biocRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_bioc_rule"
}

func (r *biocRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Behavioral Indicator of Compromise (BIOC) rule in XSIAM. " +
			"BIOC rules define behavioral detection logic for endpoint threats. " +
			"Webapp API endpoints based on XSIAM V3.4; may differ on other versions. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"rule_id": schema.Int64Attribute{
				Description: "The unique numeric identifier of the BIOC rule. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Computed: true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the BIOC rule. " +
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
			"category": schema.StringAttribute{
				Description: "BIOC category (e.g., COLLECTION, MALWARE, COMMAND_AND_CONTROL). " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional: true,
				Computed: true,
			},
			"comment": schema.StringAttribute{
				Description: "Comment or description for the BIOC rule. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional: true,
				Computed: true,
			},
			"source": schema.StringAttribute{
				Description: "The source of the rule (e.g., User, Palo Alto Networks). Read-only. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Computed: true,
			},
			"is_xql": schema.BoolAttribute{
				Description: "Whether the rule uses XQL query syntax. Read-only. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Computed: true,
			},
			"mitre_tactic": schema.ListAttribute{
				Description: "List of MITRE ATT&CK tactics associated with this rule. Read-only. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"mitre_technique": schema.ListAttribute{
				Description: "List of MITRE ATT&CK techniques associated with this rule. Read-only. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"indicator_text": schema.StringAttribute{
				Description: "Complex filter or indicator definition as JSON. " +
					"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
				Optional: true,
				Computed: true,
			},
		},
	}
}

func (r *biocRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *biocRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan biocRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleData := map[string]interface{}{
		"NAME":     plan.Name.ValueString(),
		"SEVERITY": plan.Severity.ValueString(),
		"STATUS":   plan.Status.ValueString(),
	}

	if !plan.Category.IsNull() && !plan.Category.IsUnknown() {
		ruleData["CATEGORY"] = plan.Category.ValueString()
	}
	if !plan.Comment.IsNull() && !plan.Comment.IsUnknown() {
		ruleData["COMMENT"] = plan.Comment.ValueString()
	}
	if !plan.IndicatorText.IsNull() && !plan.IndicatorText.IsUnknown() {
		ruleData["INDICATOR_TEXT"] = plan.IndicatorText.ValueString()
	}

	result, err := r.backend.CreateBIOCRule(ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating BIOC Rule",
			fmt.Sprintf("Could not create BIOC rule %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	setBIOCRuleState(ctx, &plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *biocRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state biocRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	rule, err := r.backend.GetBIOCRule(ruleID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setBIOCRuleState(ctx, &state, rule)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *biocRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan biocRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state biocRuleModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	ruleData := map[string]interface{}{
		"NAME":     plan.Name.ValueString(),
		"SEVERITY": plan.Severity.ValueString(),
		"STATUS":   plan.Status.ValueString(),
	}

	if !plan.Category.IsNull() && !plan.Category.IsUnknown() {
		ruleData["CATEGORY"] = plan.Category.ValueString()
	}
	if !plan.Comment.IsNull() && !plan.Comment.IsUnknown() {
		ruleData["COMMENT"] = plan.Comment.ValueString()
	}
	if !plan.IndicatorText.IsNull() && !plan.IndicatorText.IsUnknown() {
		ruleData["INDICATOR_TEXT"] = plan.IndicatorText.ValueString()
	}

	result, err := r.backend.UpdateBIOCRule(ruleID, ruleData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating BIOC Rule",
			fmt.Sprintf("Could not update BIOC rule %d: %s", ruleID, err),
		)
		return
	}

	setBIOCRuleState(ctx, &plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *biocRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state biocRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleID := int(state.RuleID.ValueInt64())
	err := r.backend.DeleteBIOCRule(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting BIOC Rule",
			fmt.Sprintf("Could not delete BIOC rule %d: %s", ruleID, err),
		)
		return
	}
}

func (r *biocRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	ruleID, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing BIOC Rule",
			fmt.Sprintf("Invalid rule ID %q: must be a numeric ID", req.ID),
		)
		return
	}

	rule, err := r.backend.GetBIOCRule(ruleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing BIOC Rule",
			fmt.Sprintf("Could not find BIOC rule %d: %s", ruleID, err),
		)
		return
	}

	var state biocRuleModel
	setBIOCRuleState(ctx, &state, rule)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setBIOCRuleState(ctx context.Context, model *biocRuleModel, rule *api.BIOCRule) {
	model.RuleID = types.Int64Value(int64(rule.RuleID))
	model.Name = types.StringValue(rule.Name)
	model.Severity = types.StringValue(rule.Severity)
	model.Status = types.StringValue(rule.Status)
	model.Source = types.StringValue(rule.Source)
	model.IsXQL = types.BoolValue(rule.IsXQL)

	if rule.Category != "" {
		model.Category = types.StringValue(rule.Category)
	} else {
		model.Category = types.StringNull()
	}
	if rule.Comment != "" {
		model.Comment = types.StringValue(rule.Comment)
	} else {
		model.Comment = types.StringNull()
	}
	if rule.IndicatorText != "" {
		model.IndicatorText = types.StringValue(rule.IndicatorText)
	} else {
		model.IndicatorText = types.StringNull()
	}

	// Convert []string slices to types.List for computed MITRE fields.
	if rule.MitreTactic == nil {
		rule.MitreTactic = []string{}
	}
	tacticList, _ := types.ListValueFrom(ctx, types.StringType, rule.MitreTactic)
	model.MitreTactic = tacticList

	if rule.MitreTechnique == nil {
		rule.MitreTechnique = []string{}
	}
	techniqueList, _ := types.ListValueFrom(ctx, types.StringType, rule.MitreTechnique)
	model.MitreTechnique = techniqueList
}

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
	_ resource.Resource                = &analyticsDetectorResource{}
	_ resource.ResourceWithImportState = &analyticsDetectorResource{}
)

func NewAnalyticsDetectorResource() resource.Resource {
	return &analyticsDetectorResource{}
}

type analyticsDetectorResource struct {
	backend api.XSOARBackend
}

type analyticsDetectorModel struct {
	GlobalRuleID     types.String `tfsdk:"global_rule_id"`
	Name             types.String `tfsdk:"name"`
	Description      types.String `tfsdk:"description"`
	Severity         types.String `tfsdk:"severity"`
	Status           types.String `tfsdk:"status"`
	OriginalSeverity types.String `tfsdk:"original_severity"`
	Source           types.String `tfsdk:"source"`
	MitreTactic      types.List   `tfsdk:"mitre_tactic"`
	MitreTechnique   types.List   `tfsdk:"mitre_technique"`
}

func (r *analyticsDetectorResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_analytics_detector"
}

func (r *analyticsDetectorResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an analytics detection rule in XSIAM. " +
			"These are system-defined rules (Palo Alto Networks built-in); only severity and status can be changed. " +
			"Webapp API endpoints based on XSIAM V3.4; may differ on other versions. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"global_rule_id": schema.StringAttribute{
				Description: "The global rule identifier (acts as ID).",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the analytics detector.",
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "A description of the analytics detector.",
				Computed:    true,
			},
			"severity": schema.StringAttribute{
				Description: "Severity level. Valid values: SEV_010_INFO, SEV_020_LOW, SEV_030_MEDIUM, SEV_040_HIGH, SEV_050_CRITICAL.",
				Required:    true,
			},
			"status": schema.StringAttribute{
				Description: "Rule status. Valid values: ENABLED, DISABLED.",
				Required:    true,
			},
			"original_severity": schema.StringAttribute{
				Description: "The original severity as defined by Palo Alto Networks.",
				Computed:    true,
			},
			"source": schema.StringAttribute{
				Description: "The source of the rule (e.g., Palo Alto Networks).",
				Computed:    true,
			},
			"mitre_tactic": schema.ListAttribute{
				Description: "List of MITRE ATT&CK tactics associated with the rule.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"mitre_technique": schema.ListAttribute{
				Description: "List of MITRE ATT&CK techniques associated with the rule.",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *analyticsDetectorResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *analyticsDetectorResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan analyticsDetectorModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	globalRuleID := plan.GlobalRuleID.ValueString()

	// Verify the system rule exists
	existing, err := r.backend.GetAnalyticsDetector(globalRuleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Analytics Detector",
			fmt.Sprintf("Could not find system-defined analytics detector %q: %s", globalRuleID, err),
		)
		return
	}

	// Update only severity and status
	detectorData := map[string]interface{}{
		"SEVERITY": plan.Severity.ValueString(),
		"STATUS":   plan.Status.ValueString(),
	}

	result, err := r.backend.UpdateAnalyticsDetector(globalRuleID, detectorData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Analytics Detector",
			fmt.Sprintf("Could not update analytics detector %q: %s", globalRuleID, err),
		)
		return
	}

	// Merge computed fields from existing if update result is partial
	if result.Name == "" {
		result.Name = existing.Name
	}
	if result.Description == "" {
		result.Description = existing.Description
	}
	if result.OriginalSeverity == "" {
		result.OriginalSeverity = existing.OriginalSeverity
	}
	if result.Source == "" {
		result.Source = existing.Source
	}
	if result.MitreTactic == nil {
		result.MitreTactic = existing.MitreTactic
	}
	if result.MitreTechnique == nil {
		result.MitreTechnique = existing.MitreTechnique
	}

	setAnalyticsDetectorState(ctx, &plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *analyticsDetectorResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state analyticsDetectorModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	globalRuleID := state.GlobalRuleID.ValueString()
	detector, err := r.backend.GetAnalyticsDetector(globalRuleID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setAnalyticsDetectorState(ctx, &state, detector)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *analyticsDetectorResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan analyticsDetectorModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	globalRuleID := plan.GlobalRuleID.ValueString()

	detectorData := map[string]interface{}{
		"SEVERITY": plan.Severity.ValueString(),
		"STATUS":   plan.Status.ValueString(),
	}

	result, err := r.backend.UpdateAnalyticsDetector(globalRuleID, detectorData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Analytics Detector",
			fmt.Sprintf("Could not update analytics detector %q: %s", globalRuleID, err),
		)
		return
	}

	// If update result is partial, re-read the full rule
	if result.Name == "" || result.Source == "" {
		full, readErr := r.backend.GetAnalyticsDetector(globalRuleID)
		if readErr == nil {
			if result.Name == "" {
				result.Name = full.Name
			}
			if result.Description == "" {
				result.Description = full.Description
			}
			if result.OriginalSeverity == "" {
				result.OriginalSeverity = full.OriginalSeverity
			}
			if result.Source == "" {
				result.Source = full.Source
			}
			if result.MitreTactic == nil {
				result.MitreTactic = full.MitreTactic
			}
			if result.MitreTechnique == nil {
				result.MitreTechnique = full.MitreTechnique
			}
		}
	}

	setAnalyticsDetectorState(ctx, &plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *analyticsDetectorResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No-op: system-defined rules cannot be deleted.
}

func (r *analyticsDetectorResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	globalRuleID := req.ID

	detector, err := r.backend.GetAnalyticsDetector(globalRuleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Analytics Detector",
			fmt.Sprintf("Could not find analytics detector %q: %s", globalRuleID, err),
		)
		return
	}

	var state analyticsDetectorModel
	setAnalyticsDetectorState(ctx, &state, detector)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setAnalyticsDetectorState(ctx context.Context, model *analyticsDetectorModel, detector *api.AnalyticsDetector) {
	model.GlobalRuleID = types.StringValue(detector.GlobalRuleID)
	model.Name = types.StringValue(detector.Name)
	model.Severity = types.StringValue(detector.Severity)
	model.Status = types.StringValue(detector.Status)
	model.OriginalSeverity = types.StringValue(detector.OriginalSeverity)
	model.Source = types.StringValue(detector.Source)

	if detector.Description != "" {
		model.Description = types.StringValue(detector.Description)
	} else {
		model.Description = types.StringValue("")
	}

	if detector.MitreTactic == nil {
		detector.MitreTactic = []string{}
	}
	mitreTactic, _ := types.ListValueFrom(ctx, types.StringType, detector.MitreTactic)
	model.MitreTactic = mitreTactic

	if detector.MitreTechnique == nil {
		detector.MitreTechnique = []string{}
	}
	mitreTechnique, _ := types.ListValueFrom(ctx, types.StringType, detector.MitreTechnique)
	model.MitreTechnique = mitreTechnique
}

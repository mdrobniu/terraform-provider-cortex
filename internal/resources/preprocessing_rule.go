package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/client"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &PreprocessingRuleResource{}
	_ resource.ResourceWithImportState = &PreprocessingRuleResource{}
)

// NewPreprocessingRuleResource returns a new resource factory function.
func NewPreprocessingRuleResource() resource.Resource {
	return &PreprocessingRuleResource{}
}

// PreprocessingRuleResource manages an XSOAR pre-processing rule.
type PreprocessingRuleResource struct {
	backend api.XSOARBackend
}

// preprocessingRuleModel maps the resource schema data.
type preprocessingRuleModel struct {
	ID         types.String `tfsdk:"id"`
	Name       types.String `tfsdk:"name"`
	Enabled    types.Bool   `tfsdk:"enabled"`
	Action     types.String `tfsdk:"action"`
	ScriptName types.String `tfsdk:"script_name"`
	RulesJSON  types.String `tfsdk:"rules_json"`
	Version    types.Int64  `tfsdk:"version"`
}

func (r *PreprocessingRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_preprocessing_rule"
}

func (r *PreprocessingRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an XSOAR pre-processing rule.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the pre-processing rule.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the pre-processing rule.",
				Required:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the rule is enabled.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"action": schema.StringAttribute{
				Description: "The action to perform (e.g., 'drop', 'run_script', 'link').",
				Required:    true,
			},
			"script_name": schema.StringAttribute{
				Description: "The name of the script to run when action is 'run_script'.",
				Optional:    true,
			},
			"rules_json": schema.StringAttribute{
				Description: "JSON string containing the rule filters configuration.",
				Required:    true,
			},
			"version": schema.Int64Attribute{
				Description: "The current version of the rule (used for optimistic concurrency).",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *PreprocessingRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *PreprocessingRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan preprocessingRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload, d := r.buildPayload(&plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	created, err := r.backend.CreatePreprocessingRule(payload)
	if err != nil {
		resp.Diagnostics.AddError("Error creating preprocessing rule", err.Error())
		return
	}

	plan.ID = types.StringValue(created.ID)

	d = r.readRuleIntoModel(plan.Name.ValueString(), &plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

func (r *PreprocessingRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state preprocessingRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	d := r.readRuleIntoModel(state.Name.ValueString(), &state)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (r *PreprocessingRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan preprocessingRuleModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state preprocessingRuleModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload, d := r.buildPayload(&plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload["id"] = state.ID.ValueString()
	payload["version"] = state.Version.ValueInt64()

	_, err := r.backend.UpdatePreprocessingRule(payload)
	if err != nil {
		resp.Diagnostics.AddError("Error updating preprocessing rule", err.Error())
		return
	}

	plan.ID = state.ID

	d = r.readRuleIntoModel(plan.Name.ValueString(), &plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

func (r *PreprocessingRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state preprocessingRuleModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.backend.DeletePreprocessingRule(state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("Error deleting preprocessing rule", err.Error())
	}
}

func (r *PreprocessingRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := req.ID

	var state preprocessingRuleModel
	state.Name = types.StringValue(name)

	d := r.readRuleIntoModel(name, &state)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// buildPayload constructs the API payload from the plan model.
func (r *PreprocessingRuleResource) buildPayload(plan *preprocessingRuleModel) (map[string]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Parse rules_json into a generic structure
	var rulesData interface{}
	if err := json.Unmarshal([]byte(plan.RulesJSON.ValueString()), &rulesData); err != nil {
		diags.AddError(
			"Invalid rules_json",
			fmt.Sprintf("Failed to parse rules_json as JSON: %s", err.Error()),
		)
		return nil, diags
	}

	payload := map[string]interface{}{
		"name":    plan.Name.ValueString(),
		"enabled": plan.Enabled.ValueBool(),
		"action":  plan.Action.ValueString(),
	}

	if !plan.ScriptName.IsNull() && !plan.ScriptName.IsUnknown() {
		payload["scriptName"] = plan.ScriptName.ValueString()
	}

	// The rules JSON can contain newEventFilters and/or existingEventsFilters
	if rulesMap, ok := rulesData.(map[string]interface{}); ok {
		if nef, exists := rulesMap["newEventFilters"]; exists {
			payload["newEventFilters"] = nef
		}
		if eef, exists := rulesMap["existingEventsFilters"]; exists {
			payload["existingEventsFilters"] = eef
		}
		if lt, exists := rulesMap["linkTo"]; exists {
			payload["linkTo"] = lt
		}
	} else {
		// If the JSON is an array, treat it as newEventFilters
		payload["newEventFilters"] = rulesData
	}

	return payload, diags
}

// readRuleIntoModel searches for a preprocessing rule by name and populates the model.
func (r *PreprocessingRuleResource) readRuleIntoModel(name string, model *preprocessingRuleModel) diag.Diagnostics {
	var diags diag.Diagnostics

	rules, err := r.backend.GetPreprocessingRules()
	if err != nil {
		diags.AddError("Error reading preprocessing rules", err.Error())
		return diags
	}

	var found *api.PreprocessingRule
	for _, rule := range rules {
		if rule.Name == name {
			found = &rule
			break
		}
	}
	if found == nil {
		diags.AddError("Preprocessing Rule Not Found", fmt.Sprintf("Rule %q not found.", name))
		return diags
	}

	model.ID = types.StringValue(found.ID)
	model.Name = types.StringValue(found.Name)
	model.Enabled = types.BoolValue(found.Enabled)
	model.Action = types.StringValue(found.Action)
	model.Version = types.Int64Value(int64(found.Version))

	if found.ScriptName != "" {
		model.ScriptName = types.StringValue(found.ScriptName)
	} else {
		model.ScriptName = types.StringNull()
	}

	// Reconstruct rules_json from the rule's filter fields
	rulesObj := make(map[string]interface{})
	if found.NewEventFilters != nil {
		rulesObj["newEventFilters"] = found.NewEventFilters
	}
	if found.ExistingEventsFilters != nil {
		rulesObj["existingEventsFilters"] = found.ExistingEventsFilters
	}
	if found.LinkTo != "" {
		rulesObj["linkTo"] = found.LinkTo
	}

	rulesBytes, err := json.Marshal(rulesObj)
	if err != nil {
		diags.AddError("Error serializing rules", err.Error())
		return diags
	}
	model.RulesJSON = types.StringValue(string(rulesBytes))

	return diags
}

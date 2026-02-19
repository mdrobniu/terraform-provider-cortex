package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/client"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &IntegrationInstanceResource{}
	_ resource.ResourceWithImportState = &IntegrationInstanceResource{}
)

// NewIntegrationInstanceResource returns a new resource factory function.
func NewIntegrationInstanceResource() resource.Resource {
	return &IntegrationInstanceResource{}
}

// IntegrationInstanceResource manages an XSOAR integration instance.
type IntegrationInstanceResource struct {
	backend api.XSOARBackend
}

// integrationInstanceModel maps the resource schema data.
type integrationInstanceModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	IntegrationName   types.String `tfsdk:"integration_name"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	Config            types.Map    `tfsdk:"config"`
	PropagationLabels types.List   `tfsdk:"propagation_labels"`
	Engine            types.String `tfsdk:"engine"`
	EngineGroup       types.String `tfsdk:"engine_group"`
	IncomingMapperID  types.String `tfsdk:"incoming_mapper_id"`
	OutgoingMapperID  types.String `tfsdk:"outgoing_mapper_id"`
	MappingID         types.String `tfsdk:"mapping_id"`
	LogLevel          types.String `tfsdk:"log_level"`
}

func (r *IntegrationInstanceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_integration_instance"
}

func (r *IntegrationInstanceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an XSOAR integration instance.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the integration instance.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the integration instance.",
				Required:    true,
			},
			"integration_name": schema.StringAttribute{
				Description: "The integration brand name (e.g., 'Cortex XDR - IR'). Changing this forces recreation.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the integration instance is enabled.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"config": schema.MapAttribute{
				Description: "Configuration parameters as a map of display name or parameter name to value.",
				Required:    true,
				ElementType: types.StringType,
			},
			"propagation_labels": schema.ListAttribute{
				Description: "Propagation labels for multi-tenant environments.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"engine": schema.StringAttribute{
				Description: "The engine to run the integration on.",
				Optional:    true,
			},
			"engine_group": schema.StringAttribute{
				Description: "The engine group to run the integration on.",
				Optional:    true,
			},
			"incoming_mapper_id": schema.StringAttribute{
				Description: "The ID of the incoming mapper.",
				Optional:    true,
			},
			"outgoing_mapper_id": schema.StringAttribute{
				Description: "The ID of the outgoing mapper.",
				Optional:    true,
			},
			"mapping_id": schema.StringAttribute{
				Description: "The ID of the mapping.",
				Optional:    true,
			},
			"log_level": schema.StringAttribute{
				Description: "The integration log level (e.g., 'debug', 'info', 'warning', 'error').",
				Optional:    true,
			},
		},
	}
}

func (r *IntegrationInstanceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *IntegrationInstanceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan integrationInstanceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get user config map
	configMap := make(map[string]string)
	diags = plan.Config.ElementsAs(ctx, &configMap, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Find the integration definition by brand name
	integrationDef, d := r.findIntegrationConfig(plan.IntegrationName.ValueString())
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build data parameters array from the integration definition
	dataParams := buildDataParams(integrationDef.Configuration, configMap)

	// Build propagation labels
	propLabels := extractStringList(ctx, plan.PropagationLabels)

	// Build the enabled string
	enabledStr := "true"
	if !plan.Enabled.IsNull() && !plan.Enabled.IsUnknown() && !plan.Enabled.ValueBool() {
		enabledStr = "false"
	}

	// Build module instance map
	moduleInstance := map[string]interface{}{
		"brand":             integrationDef.Name,
		"category":          integrationDef.Category,
		"canSample":         true,
		"configuration":     integrationParamsToMaps(integrationDef.Configuration),
		"data":              dataParams,
		"name":              plan.Name.ValueString(),
		"enabled":           enabledStr,
		"propagationLabels": propLabels,
		"version":           -1,
	}

	setOptionalString(moduleInstance, "engine", plan.Engine)
	setOptionalString(moduleInstance, "engineGroup", plan.EngineGroup)
	setOptionalString(moduleInstance, "incomingMapperId", plan.IncomingMapperID)
	setOptionalString(moduleInstance, "outgoingMapperId", plan.OutgoingMapperID)
	setOptionalString(moduleInstance, "mappingId", plan.MappingID)
	setOptionalString(moduleInstance, "integrationLogLevel", plan.LogLevel)

	created, err := r.backend.CreateIntegrationInstance(moduleInstance)
	if err != nil {
		resp.Diagnostics.AddError("Error creating integration instance", err.Error())
		return
	}

	plan.ID = types.StringValue(created.ID)

	// Read back the full state
	d = r.readInstanceIntoModel(ctx, created.Name, &plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

func (r *IntegrationInstanceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state integrationInstanceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	d := r.readInstanceIntoModel(ctx, state.Name.ValueString(), &state)
	if d.HasError() {
		// Check if 404 -- remove from state
		resp.Diagnostics.Append(d...)
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (r *IntegrationInstanceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan integrationInstanceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state integrationInstanceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get user config map
	configMap := make(map[string]string)
	diags = plan.Config.ElementsAs(ctx, &configMap, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Find the integration definition
	integrationDef, d := r.findIntegrationConfig(plan.IntegrationName.ValueString())
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read the current instance to get its ID and version
	existing, err := r.backend.GetIntegrationInstance(state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading integration instance for update", err.Error())
		return
	}

	dataParams := buildDataParams(integrationDef.Configuration, configMap)
	propLabels := extractStringList(ctx, plan.PropagationLabels)

	enabledStr := "true"
	if !plan.Enabled.IsNull() && !plan.Enabled.IsUnknown() && !plan.Enabled.ValueBool() {
		enabledStr = "false"
	}

	moduleInstance := map[string]interface{}{
		"id":                existing.ID,
		"brand":             integrationDef.Name,
		"category":          integrationDef.Category,
		"canSample":         true,
		"configuration":     integrationParamsToMaps(integrationDef.Configuration),
		"data":              dataParams,
		"name":              plan.Name.ValueString(),
		"enabled":           enabledStr,
		"propagationLabels": propLabels,
		"version":           existing.Version,
	}

	setOptionalString(moduleInstance, "engine", plan.Engine)
	setOptionalString(moduleInstance, "engineGroup", plan.EngineGroup)
	setOptionalString(moduleInstance, "incomingMapperId", plan.IncomingMapperID)
	setOptionalString(moduleInstance, "outgoingMapperId", plan.OutgoingMapperID)
	setOptionalString(moduleInstance, "mappingId", plan.MappingID)
	setOptionalString(moduleInstance, "integrationLogLevel", plan.LogLevel)

	_, err = r.backend.UpdateIntegrationInstance(moduleInstance)
	if err != nil {
		resp.Diagnostics.AddError("Error updating integration instance", err.Error())
		return
	}

	plan.ID = state.ID

	d = r.readInstanceIntoModel(ctx, plan.Name.ValueString(), &plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

func (r *IntegrationInstanceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state integrationInstanceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.backend.DeleteIntegrationInstance(state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("Error deleting integration instance", err.Error())
	}
}

func (r *IntegrationInstanceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := req.ID

	instance, err := r.backend.GetIntegrationInstance(name)
	if err != nil {
		resp.Diagnostics.AddError("Error importing integration instance", err.Error())
		return
	}

	var state integrationInstanceModel
	state.ID = types.StringValue(instance.ID)
	state.Name = types.StringValue(instance.Name)
	state.IntegrationName = types.StringValue(instance.Brand)

	enabledBool := instance.Enabled != "false"
	state.Enabled = types.BoolValue(enabledBool)

	// Build config map from the instance
	if len(instance.ConfigMap) > 0 {
		elements := make(map[string]attr.Value)
		for k, v := range instance.ConfigMap {
			elements[k] = types.StringValue(v)
		}
		mapVal, d := types.MapValue(types.StringType, elements)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Config = mapVal
	} else {
		state.Config = types.MapValueMust(types.StringType, map[string]attr.Value{})
	}

	// Propagation labels
	if len(instance.PropagationLabels) > 0 {
		elements := make([]attr.Value, len(instance.PropagationLabels))
		for i, l := range instance.PropagationLabels {
			elements[i] = types.StringValue(l)
		}
		listVal, d := types.ListValue(types.StringType, elements)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.PropagationLabels = listVal
	} else {
		state.PropagationLabels = types.ListNull(types.StringType)
	}

	setModelOptionalString(&state.Engine, instance.Engine)
	setModelOptionalString(&state.EngineGroup, instance.EngineGroup)
	setModelOptionalString(&state.IncomingMapperID, instance.IncomingMapperID)
	setModelOptionalString(&state.OutgoingMapperID, instance.OutgoingMapperID)
	setModelOptionalString(&state.MappingID, instance.MappingID)
	setModelOptionalString(&state.LogLevel, instance.LogLevel)

	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// findIntegrationConfig looks up the integration brand definition by name.
func (r *IntegrationInstanceResource) findIntegrationConfig(brandName string) (*api.IntegrationConfig, diag.Diagnostics) {
	var diags diag.Diagnostics

	configs, err := r.backend.ListIntegrationConfigs()
	if err != nil {
		diags.AddError("Error listing integration configs", err.Error())
		return nil, diags
	}

	for _, ic := range configs {
		if ic.Name == brandName {
			return &ic, diags
		}
	}

	diags.AddError(
		"Integration Not Found",
		fmt.Sprintf("Integration brand %q not found in available integrations.", brandName),
	)
	return nil, diags
}

// readInstanceIntoModel reads an integration instance from the backend and populates the model.
func (r *IntegrationInstanceResource) readInstanceIntoModel(_ context.Context, name string, model *integrationInstanceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	instance, err := r.backend.GetIntegrationInstance(name)
	if err != nil {
		diags.AddError("Error reading integration instance", err.Error())
		return diags
	}

	model.ID = types.StringValue(instance.ID)
	model.Name = types.StringValue(instance.Name)
	model.IntegrationName = types.StringValue(instance.Brand)

	enabledBool := instance.Enabled != "false"
	model.Enabled = types.BoolValue(enabledBool)

	// Build config map from the instance's ConfigMap
	if len(instance.ConfigMap) > 0 {
		elements := make(map[string]attr.Value)
		for k, v := range instance.ConfigMap {
			elements[k] = types.StringValue(v)
		}
		mapVal, d := types.MapValue(types.StringType, elements)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		model.Config = mapVal
	} else {
		model.Config = types.MapValueMust(types.StringType, map[string]attr.Value{})
	}

	// Propagation labels
	if len(instance.PropagationLabels) > 0 {
		elements := make([]attr.Value, len(instance.PropagationLabels))
		for i, l := range instance.PropagationLabels {
			elements[i] = types.StringValue(l)
		}
		listVal, d := types.ListValue(types.StringType, elements)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		model.PropagationLabels = listVal
	} else if !model.PropagationLabels.IsNull() {
		model.PropagationLabels = types.ListNull(types.StringType)
	}

	setModelOptionalString(&model.Engine, instance.Engine)
	setModelOptionalString(&model.EngineGroup, instance.EngineGroup)
	setModelOptionalString(&model.IncomingMapperID, instance.IncomingMapperID)
	setModelOptionalString(&model.OutgoingMapperID, instance.OutgoingMapperID)
	setModelOptionalString(&model.MappingID, instance.MappingID)
	setModelOptionalString(&model.LogLevel, instance.LogLevel)

	return diags
}

// buildDataParams constructs the data parameters array, matching user config to integration definition parameters.
func buildDataParams(params []api.IntegrationParam, configMap map[string]string) []map[string]interface{} {
	var dataParams []map[string]interface{}
	for _, p := range params {
		param := map[string]interface{}{
			"name":         p.Name,
			"display":      p.Display,
			"type":         p.Type,
			"required":     p.Required,
			"hidden":       p.Hidden,
			"defaultValue": p.DefaultValue,
			"hasvalue":     false,
			"value":        "",
		}
		if len(p.Options) > 0 {
			param["options"] = p.Options
		}

		// Check if user config has a value for this parameter by display or name
		if val, ok := configMap[p.Display]; ok && p.Display != "" {
			param["value"] = val
			param["hasvalue"] = true
		} else if val, ok := configMap[p.Name]; ok {
			param["value"] = val
			param["hasvalue"] = true
		}

		dataParams = append(dataParams, param)
	}
	return dataParams
}

// integrationParamsToMaps converts IntegrationParam structs to maps with lowercase keys
// for proper JSON serialization to the XSOAR API.
func integrationParamsToMaps(params []api.IntegrationParam) []map[string]interface{} {
	var result []map[string]interface{}
	for _, p := range params {
		m := map[string]interface{}{
			"name":         p.Name,
			"display":      p.Display,
			"defaultValue": p.DefaultValue,
			"type":         p.Type,
			"required":     p.Required,
			"hidden":       p.Hidden,
		}
		if len(p.Options) > 0 {
			m["options"] = p.Options
		}
		result = append(result, m)
	}
	return result
}

// extractStringList extracts a []string from a types.List.
func extractStringList(_ context.Context, list types.List) []string {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var result []string
	for _, e := range list.Elements() {
		if sv, ok := e.(types.String); ok {
			result = append(result, sv.ValueString())
		}
	}
	return result
}

// setOptionalString sets a key in a map if the types.String value is not null/unknown.
func setOptionalString(m map[string]interface{}, key string, val types.String) {
	if !val.IsNull() && !val.IsUnknown() {
		m[key] = val.ValueString()
	}
}

// setModelOptionalString sets a model string field: non-empty string becomes StringValue, empty becomes StringNull.
func setModelOptionalString(field *types.String, value string) {
	if value != "" {
		*field = types.StringValue(value)
	} else {
		*field = types.StringNull()
	}
}

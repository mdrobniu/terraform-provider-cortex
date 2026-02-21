package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &autoUpgradeSettingsResource{}

func NewAutoUpgradeSettingsResource() resource.Resource {
	return &autoUpgradeSettingsResource{}
}

type autoUpgradeSettingsResource struct {
	backend api.XSOARBackend
}

type autoUpgradeSettingsModel struct {
	StartTime types.String `tfsdk:"start_time"`
	EndTime   types.String `tfsdk:"end_time"`
	Days      types.List   `tfsdk:"days"`
	BatchSize types.Int64  `tfsdk:"batch_size"`
}

func (r *autoUpgradeSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_auto_upgrade_settings"
}

func (r *autoUpgradeSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages XDR collector auto-upgrade global settings in XSIAM. " +
			"This is a singleton resource (one per XSIAM tenant). " +
			"Create and update both set the settings; delete is a no-op. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"start_time": schema.StringAttribute{
				Description: "Start of the upgrade window (e.g., '02:00'). Empty means anytime.",
				Optional:    true,
				Computed:    true,
			},
			"end_time": schema.StringAttribute{
				Description: "End of the upgrade window (e.g., '06:00'). Empty means anytime.",
				Optional:    true,
				Computed:    true,
			},
			"days": schema.ListAttribute{
				Description: "Days of the week for upgrades (e.g., ['Monday', 'Tuesday']). Null means all days.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"batch_size": schema.Int64Attribute{
				Description: "Number of agents to upgrade per batch.",
				Required:    true,
			},
		},
	}
}

func (r *autoUpgradeSettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *autoUpgradeSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan autoUpgradeSettingsModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	settings := buildAutoUpgradePayload(ctx, &plan)
	result, err := r.backend.UpdateAutoUpgradeSettings(settings)
	if err != nil {
		resp.Diagnostics.AddError("Error Setting Auto Upgrade Settings", err.Error())
		return
	}

	setAutoUpgradeState(ctx, &plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *autoUpgradeSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state autoUpgradeSettingsModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.backend.GetAutoUpgradeSettings()
	if err != nil {
		// Some XSIAM instances return 500 on GET; keep existing state
		resp.Diagnostics.AddWarning("Auto Upgrade Settings Read Failed",
			"Could not read auto upgrade settings from API ("+err.Error()+"). Keeping existing state.")
		diags = resp.State.Set(ctx, state)
		resp.Diagnostics.Append(diags...)
		return
	}

	setAutoUpgradeState(ctx, &state, result)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *autoUpgradeSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan autoUpgradeSettingsModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	settings := buildAutoUpgradePayload(ctx, &plan)
	result, err := r.backend.UpdateAutoUpgradeSettings(settings)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating Auto Upgrade Settings", err.Error())
		return
	}

	setAutoUpgradeState(ctx, &plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *autoUpgradeSettingsResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// Singleton: delete is a no-op
}

func buildAutoUpgradePayload(ctx context.Context, model *autoUpgradeSettingsModel) map[string]interface{} {
	timeSettings := map[string]interface{}{
		"START_TIME": nil,
		"END_TIME":   nil,
		"DAYS":       nil,
	}
	if !model.StartTime.IsNull() && !model.StartTime.IsUnknown() {
		timeSettings["START_TIME"] = model.StartTime.ValueString()
	}
	if !model.EndTime.IsNull() && !model.EndTime.IsUnknown() {
		timeSettings["END_TIME"] = model.EndTime.ValueString()
	}
	if !model.Days.IsNull() && !model.Days.IsUnknown() {
		var days []string
		model.Days.ElementsAs(ctx, &days, false)
		timeSettings["DAYS"] = days
	}
	return map[string]interface{}{
		"TIME_SETTINGS": timeSettings,
		"BATCH_SETTINGS": map[string]interface{}{
			"BATCH_SIZE": model.BatchSize.ValueInt64(),
		},
	}
}

func setAutoUpgradeState(ctx context.Context, model *autoUpgradeSettingsModel, settings *api.AutoUpgradeSettings) {
	model.BatchSize = types.Int64Value(int64(settings.BatchSize))
	if settings.StartTime != "" {
		model.StartTime = types.StringValue(settings.StartTime)
	} else {
		model.StartTime = types.StringNull()
	}
	if settings.EndTime != "" {
		model.EndTime = types.StringValue(settings.EndTime)
	} else {
		model.EndTime = types.StringNull()
	}
	if len(settings.Days) > 0 {
		listVal, _ := types.ListValueFrom(ctx, types.StringType, settings.Days)
		model.Days = listVal
	} else {
		model.Days = types.ListNull(types.StringType)
	}
}

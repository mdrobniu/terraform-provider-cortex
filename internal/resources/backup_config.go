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

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &backupConfigResource{}
	_ resource.ResourceWithImportState = &backupConfigResource{}
)

// NewBackupConfigResource is a factory function for the resource.
func NewBackupConfigResource() resource.Resource {
	return &backupConfigResource{}
}

// backupConfigResource manages backup configuration in XSOAR (singleton resource).
type backupConfigResource struct {
	backend api.XSOARBackend
}

// backupConfigResourceModel maps the resource schema data.
type backupConfigResourceModel struct {
	ID            types.String `tfsdk:"id"`
	Enabled       types.Bool   `tfsdk:"enabled"`
	ScheduleCron  types.String `tfsdk:"schedule_cron"`
	RetentionDays types.Int64  `tfsdk:"retention_days"`
	Path          types.String `tfsdk:"path"`
}

func (r *backupConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_backup_config"
}

func (r *backupConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages backup configuration settings in XSOAR. This is a singleton resource; " +
			"only one instance can exist per XSOAR server.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The identifier of the backup configuration (always \"backup_config\").",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether automated backups are enabled.",
				Optional:    true,
			},
			"schedule_cron": schema.StringAttribute{
				Description: "The cron expression for the backup schedule.",
				Optional:    true,
			},
			"retention_days": schema.Int64Attribute{
				Description: "The number of days to retain backups.",
				Optional:    true,
			},
			"path": schema.StringAttribute{
				Description: "The filesystem path where backups are stored.",
				Optional:    true,
			},
		},
	}
}

func (r *backupConfigResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// buildConfigMap constructs the configuration map from the plan/state model.
func (r *backupConfigResource) buildConfigMap(model *backupConfigResourceModel) map[string]interface{} {
	configData := map[string]interface{}{}

	if !model.Enabled.IsNull() && !model.Enabled.IsUnknown() {
		configData["enabled"] = model.Enabled.ValueBool()
	}
	if !model.ScheduleCron.IsNull() && !model.ScheduleCron.IsUnknown() {
		configData["scheduleCron"] = model.ScheduleCron.ValueString()
	}
	if !model.RetentionDays.IsNull() && !model.RetentionDays.IsUnknown() {
		configData["retentionDays"] = model.RetentionDays.ValueInt64()
	}
	if !model.Path.IsNull() && !model.Path.IsUnknown() {
		configData["path"] = model.Path.ValueString()
	}

	return configData
}

// readBackupConfig reads the current backup config from the backend and populates the model.
func (r *backupConfigResource) readBackupConfig(model *backupConfigResourceModel) error {
	config, err := r.backend.GetBackupConfig()
	if err != nil {
		return err
	}

	model.ID = types.StringValue("backup_config")

	if !model.Enabled.IsNull() {
		model.Enabled = types.BoolValue(config.Enabled)
	}
	if !model.ScheduleCron.IsNull() {
		model.ScheduleCron = types.StringValue(config.ScheduleCron)
	}
	if !model.RetentionDays.IsNull() {
		model.RetentionDays = types.Int64Value(int64(config.RetentionDays))
	}
	if !model.Path.IsNull() {
		model.Path = types.StringValue(config.Path)
	}

	return nil
}

func (r *backupConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan backupConfigResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	configData := r.buildConfigMap(&plan)

	_, err := r.backend.UpdateBackupConfig(configData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Backup Configuration",
			fmt.Sprintf("Could not set backup configuration: %s", err),
		)
		return
	}

	err = r.readBackupConfig(&plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Backup Configuration",
			fmt.Sprintf("Could not read backup configuration after create: %s", err),
		)
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *backupConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state backupConfigResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	config, err := r.backend.GetBackupConfig()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Backup Configuration",
			fmt.Sprintf("Could not read backup configuration: %s", err),
		)
		return
	}

	state.ID = types.StringValue("backup_config")

	if !state.Enabled.IsNull() {
		state.Enabled = types.BoolValue(config.Enabled)
	}
	if !state.ScheduleCron.IsNull() {
		state.ScheduleCron = types.StringValue(config.ScheduleCron)
	}
	if !state.RetentionDays.IsNull() {
		state.RetentionDays = types.Int64Value(int64(config.RetentionDays))
	}
	if !state.Path.IsNull() {
		state.Path = types.StringValue(config.Path)
	}

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *backupConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan backupConfigResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	configData := r.buildConfigMap(&plan)

	_, err := r.backend.UpdateBackupConfig(configData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Backup Configuration",
			fmt.Sprintf("Could not update backup configuration: %s", err),
		)
		return
	}

	err = r.readBackupConfig(&plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Backup Configuration",
			fmt.Sprintf("Could not read backup configuration after update: %s", err),
		)
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *backupConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Reset to defaults by sending an empty/default config.
	defaultConfig := map[string]interface{}{
		"enabled":       false,
		"scheduleCron":  "",
		"retentionDays": 0,
		"path":          "",
	}

	_, err := r.backend.UpdateBackupConfig(defaultConfig)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Resetting Backup Configuration",
			fmt.Sprintf("Could not reset backup configuration to defaults: %s", err),
		)
		return
	}
}

func (r *backupConfigResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import ID is always "backup_config" for this singleton resource.
	config, err := r.backend.GetBackupConfig()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Backup Configuration",
			fmt.Sprintf("Could not read backup configuration: %s", err),
		)
		return
	}

	// Set all attributes from the current server state.
	state := backupConfigResourceModel{
		ID:            types.StringValue("backup_config"),
		Enabled:       types.BoolValue(config.Enabled),
		ScheduleCron:  types.StringValue(config.ScheduleCron),
		RetentionDays: types.Int64Value(int64(config.RetentionDays)),
		Path:          types.StringValue(config.Path),
	}

	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

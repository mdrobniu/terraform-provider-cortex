package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &backupScheduleResource{}
	_ resource.ResourceWithImportState = &backupScheduleResource{}
)

func NewBackupScheduleResource() resource.Resource {
	return &backupScheduleResource{}
}

type backupScheduleResource struct {
	backend api.XSOARBackend
}

type backupScheduleResourceModel struct {
	ScheduleID      types.String `tfsdk:"schedule_id"`
	StorageID       types.String `tfsdk:"storage_id"`
	RetentionPeriod types.Int64  `tfsdk:"retention_period"`
	RelativePath    types.String `tfsdk:"relative_path"`
	AtTimeHour      types.String `tfsdk:"at_time_hour"`
	AtTimeMinute    types.String `tfsdk:"at_time_minute"`
	TimePeriodType  types.String `tfsdk:"time_period_type"`
	TimePeriod      types.Int64  `tfsdk:"time_period"`
}

func (r *backupScheduleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_backup_schedule"
}

func (r *backupScheduleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a backup retention schedule on XSOAR 8 OPP. " +
			"Requires an external storage to be configured first, and session auth " +
			"(ui_url, username, password in provider config). " +
			"The XSOAR API has no update endpoint for schedules, so any change triggers a replacement.",
		Attributes: map[string]schema.Attribute{
			"schedule_id": schema.StringAttribute{
				Description: "The unique identifier of the backup schedule.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"storage_id": schema.StringAttribute{
				Description: "The ID of the external storage to use for backups.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"retention_period": schema.Int64Attribute{
				Description: "Number of days to retain backups.",
				Required:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"relative_path": schema.StringAttribute{
				Description: "The relative path within the external storage for backups (e.g., \"/mnt/data/xsoar/\").",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"at_time_hour": schema.StringAttribute{
				Description: "Hour to run backup (00-23). Defaults to \"02\".",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"at_time_minute": schema.StringAttribute{
				Description: "Minute to run backup (00-59). Defaults to \"00\".",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"time_period_type": schema.StringAttribute{
				Description: "Schedule period type (e.g., \"days\").",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"time_period": schema.Int64Attribute{
				Description: "Schedule period value (e.g., 1 for every 1 day).",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplaceIfConfigured(),
					int64planmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *backupScheduleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *backupScheduleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan backupScheduleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	humanCron := map[string]interface{}{
		"atTimeHour":     valueOrDefault(plan.AtTimeHour, "02"),
		"atTimeMinute":   valueOrDefault(plan.AtTimeMinute, "00"),
		"timePeriodType": valueOrDefault(plan.TimePeriodType, "days"),
		"timePeriod":     int64OrDefault(plan.TimePeriod, 1),
		"days":           []interface{}{},
	}

	payload := map[string]interface{}{
		"storage_id":       plan.StorageID.ValueString(),
		"retention_period": plan.RetentionPeriod.ValueInt64(),
		"relative_path":    plan.RelativePath.ValueString(),
		"human_cron":       humanCron,
	}

	schedule, err := r.backend.CreateBackupSchedule(payload)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Backup Schedule",
			fmt.Sprintf("Could not create backup schedule: %s", err),
		)
		return
	}

	plan.ScheduleID = types.StringValue(schedule.ScheduleID)
	r.populateFromSchedule(&plan, schedule)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *backupScheduleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state backupScheduleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	scheduleID := state.ScheduleID.ValueString()
	schedule, err := r.findScheduleByID(scheduleID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.ScheduleID = types.StringValue(schedule.ScheduleID)
	r.populateFromSchedule(&state, schedule)

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

// Update is not implemented - all fields use RequiresReplace because the XSOAR API
// has no update endpoint for backup schedules. Terraform will delete and recreate.
func (r *backupScheduleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"Backup schedules cannot be updated in-place. This is a provider bug if you see this error.",
	)
}

func (r *backupScheduleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state backupScheduleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.backend.DeleteBackupSchedule(state.ScheduleID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Backup Schedule",
			fmt.Sprintf("Could not delete backup schedule: %s", err),
		)
		return
	}
}

func (r *backupScheduleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	scheduleID := req.ID
	schedule, err := r.findScheduleByID(scheduleID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Backup Schedule",
			fmt.Sprintf("Could not find backup schedule with ID %q: %s", scheduleID, err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("schedule_id"), schedule.ScheduleID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("storage_id"), schedule.StorageID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("retention_period"), int64(schedule.RetentionPeriod))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("relative_path"), schedule.RelativePath)...)

	if schedule.HumanCron != nil {
		if v, ok := schedule.HumanCron["atTimeHour"].(string); ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("at_time_hour"), v)...)
		}
		if v, ok := schedule.HumanCron["atTimeMinute"].(string); ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("at_time_minute"), v)...)
		}
		if v, ok := schedule.HumanCron["timePeriodType"].(string); ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("time_period_type"), v)...)
		}
		if v, ok := schedule.HumanCron["timePeriod"].(float64); ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("time_period"), int64(v))...)
		}
	}
}

func (r *backupScheduleResource) findScheduleByID(scheduleID string) (*api.BackupSchedule, error) {
	schedules, err := r.backend.ListBackupSchedules()
	if err != nil {
		return nil, fmt.Errorf("listing backup schedules: %w", err)
	}
	for _, s := range schedules {
		if s.ScheduleID == scheduleID {
			return &s, nil
		}
	}
	return nil, fmt.Errorf("backup schedule %q not found", scheduleID)
}

func (r *backupScheduleResource) populateFromSchedule(model *backupScheduleResourceModel, schedule *api.BackupSchedule) {
	model.StorageID = types.StringValue(schedule.StorageID)
	model.RetentionPeriod = types.Int64Value(int64(schedule.RetentionPeriod))
	model.RelativePath = types.StringValue(schedule.RelativePath)

	if schedule.HumanCron != nil {
		if v, ok := schedule.HumanCron["atTimeHour"].(string); ok {
			model.AtTimeHour = types.StringValue(v)
		}
		if v, ok := schedule.HumanCron["atTimeMinute"].(string); ok {
			model.AtTimeMinute = types.StringValue(v)
		}
		if v, ok := schedule.HumanCron["timePeriodType"].(string); ok {
			model.TimePeriodType = types.StringValue(v)
		}
		if v, ok := schedule.HumanCron["timePeriod"].(float64); ok {
			model.TimePeriod = types.Int64Value(int64(v))
		}
	}
}

func valueOrDefault(v types.String, def string) string {
	if v.IsNull() || v.IsUnknown() {
		return def
	}
	return v.ValueString()
}

func int64OrDefault(v types.Int64, def int64) int64 {
	if v.IsNull() || v.IsUnknown() {
		return def
	}
	return v.ValueInt64()
}

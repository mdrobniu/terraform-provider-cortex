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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

var (
	_ resource.Resource                = &JobResource{}
	_ resource.ResourceWithImportState = &JobResource{}
)

// NewJobResource returns a new resource factory function.
func NewJobResource() resource.Resource {
	return &JobResource{}
}

// JobResource manages an XSOAR scheduled job.
type JobResource struct {
	backend api.XSOARBackend
}

// jobModel maps the resource schema data.
type jobModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	PlaybookID       types.String `tfsdk:"playbook_id"`
	Type             types.String `tfsdk:"type"`
	Scheduled        types.Bool   `tfsdk:"scheduled"`
	Cron             types.String `tfsdk:"cron"`
	Recurrent        types.Bool   `tfsdk:"recurrent"`
	ShouldTriggerNew types.Bool   `tfsdk:"should_trigger_new"`
	Tags             types.List   `tfsdk:"tags"`
	Version          types.Int64  `tfsdk:"version"`
	StartDate        types.String `tfsdk:"start_date"`
	EndingDate       types.String `tfsdk:"ending_date"`
	EndingType       types.String `tfsdk:"ending_type"`
	HumanCron        types.Object `tfsdk:"human_cron"`
}

// humanCronModel maps the human_cron nested attribute.
type humanCronModel struct {
	TimePeriodType types.String `tfsdk:"time_period_type"`
	TimePeriod     types.Int64  `tfsdk:"time_period"`
	Days           types.List   `tfsdk:"days"`
}

// humanCronAttrTypes defines the attribute types for the human_cron object.
var humanCronAttrTypes = map[string]attr.Type{
	"time_period_type": types.StringType,
	"time_period":      types.Int64Type,
	"days":             types.ListType{ElemType: types.StringType},
}

func (r *JobResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_job"
}

func (r *JobResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an XSOAR/XSIAM scheduled job.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the job.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the job.",
				Required:    true,
			},
			"playbook_id": schema.StringAttribute{
				Description: "The ID of the playbook to run. Leave empty or omit for no playbook.",
				Optional:    true,
				Computed:    true,
			},
			"type": schema.StringAttribute{
				Description: "The incident type for the job.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"scheduled": schema.BoolAttribute{
				Description: "Whether the job is scheduled.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"cron": schema.StringAttribute{
				Description: "The cron schedule expression (XSOAR 6/8). Not used on XSIAM; use human_cron instead.",
				Optional:    true,
			},
			"recurrent": schema.BoolAttribute{
				Description: "Whether the job is recurrent.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"should_trigger_new": schema.BoolAttribute{
				Description: "Whether to trigger a new incident each time.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"tags": schema.ListAttribute{
				Description: "Tags associated with the job.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"version": schema.Int64Attribute{
				Description: "The current version of the job (used for optimistic concurrency).",
				Computed:    true,
			},
			"start_date": schema.StringAttribute{
				Description: "The start date for the job schedule in ISO 8601 format (e.g., 2026-03-01T00:00:00Z). Required on XSIAM.",
				Optional:    true,
			},
			"ending_date": schema.StringAttribute{
				Description: "The ending date for the job schedule in ISO 8601 format. Defaults to start_date value.",
				Optional:    true,
				Computed:    true,
			},
			"ending_type": schema.StringAttribute{
				Description: "When the job should stop running. Valid values: never, by_date.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("never"),
			},
			"human_cron": schema.SingleNestedAttribute{
				Description: "Human-readable cron schedule (required on XSIAM, optional on XSOAR). Defines the job repeat interval.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"time_period_type": schema.StringAttribute{
						Description: "The time period unit: minutes, hours, days, weeks, months.",
						Required:    true,
					},
					"time_period": schema.Int64Attribute{
						Description: "The interval value (e.g., 1 = every 1 hour when time_period_type is hours).",
						Optional:    true,
						Computed:    true,
						Default:     int64default.StaticInt64(1),
					},
					"days": schema.ListAttribute{
						Description: "Days of the week to run: SUN, MON, TUE, WED, THU, FRI, SAT. If omitted, runs every day.",
						Optional:    true,
						ElementType: types.StringType,
					},
				},
			},
		},
	}
}

func (r *JobResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *JobResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan jobModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := r.buildPayload(ctx, &plan)

	created, err := r.backend.CreateJob(payload)
	if err != nil {
		resp.Diagnostics.AddError("Error creating job", err.Error())
		return
	}

	plan.ID = types.StringValue(created.ID)

	// Read back the full state
	d := r.readJobIntoModel(ctx, plan.Name.ValueString(), &plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

func (r *JobResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state jobModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	d := r.readJobIntoModel(ctx, state.Name.ValueString(), &state)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (r *JobResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan jobModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state jobModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := r.buildPayload(ctx, &plan)
	payload["id"] = state.ID.ValueString()
	payload["version"] = state.Version.ValueInt64()

	_, err := r.backend.UpdateJob(payload)
	if err != nil {
		resp.Diagnostics.AddError("Error updating job", err.Error())
		return
	}

	plan.ID = state.ID

	d := r.readJobIntoModel(ctx, plan.Name.ValueString(), &plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

func (r *JobResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state jobModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.backend.DeleteJob(state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("Error deleting job", err.Error())
	}
}

func (r *JobResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := req.ID

	var state jobModel
	state.Name = types.StringValue(name)

	d := r.readJobIntoModel(ctx, name, &state)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// buildPayload builds the API payload from the plan model.
func (r *JobResource) buildPayload(ctx context.Context, plan *jobModel) map[string]interface{} {
	payload := map[string]interface{}{
		"name":             plan.Name.ValueString(),
		"type":             plan.Type.ValueString(),
		"scheduled":        plan.Scheduled.ValueBool(),
		"recurrent":        plan.Recurrent.ValueBool(),
		"shouldTriggerNew": plan.ShouldTriggerNew.ValueBool(),
	}

	if !plan.PlaybookID.IsNull() && !plan.PlaybookID.IsUnknown() && plan.PlaybookID.ValueString() != "" {
		payload["playbookId"] = plan.PlaybookID.ValueString()
	}

	if !plan.Cron.IsNull() && !plan.Cron.IsUnknown() {
		payload["cron"] = plan.Cron.ValueString()
	}

	tags := extractStringList(ctx, plan.Tags)
	if tags != nil {
		payload["tags"] = tags
	}

	if !plan.StartDate.IsNull() && !plan.StartDate.IsUnknown() {
		payload["startDate"] = plan.StartDate.ValueString()
	}

	if !plan.EndingDate.IsNull() && !plan.EndingDate.IsUnknown() {
		payload["endingDate"] = plan.EndingDate.ValueString()
	} else if !plan.StartDate.IsNull() && !plan.StartDate.IsUnknown() {
		// Default endingDate to startDate if not specified
		payload["endingDate"] = plan.StartDate.ValueString()
	}

	if !plan.EndingType.IsNull() && !plan.EndingType.IsUnknown() {
		payload["endingType"] = plan.EndingType.ValueString()
	}

	// Build humanCron from nested object
	if !plan.HumanCron.IsNull() && !plan.HumanCron.IsUnknown() {
		var hc humanCronModel
		diags := plan.HumanCron.As(ctx, &hc, basetypes.ObjectAsOptions{})
		if !diags.HasError() {
			humanCron := map[string]interface{}{
				"timePeriodType": hc.TimePeriodType.ValueString(),
				"timePeriod":     hc.TimePeriod.ValueInt64(),
			}
			days := extractStringList(ctx, hc.Days)
			if days != nil {
				humanCron["days"] = days
			}
			payload["humanCron"] = humanCron
		}
	}

	return payload
}

// readJobIntoModel searches for a job by name and populates the model.
func (r *JobResource) readJobIntoModel(ctx context.Context, name string, model *jobModel) diag.Diagnostics {
	var diags diag.Diagnostics

	jobs, err := r.backend.SearchJobs()
	if err != nil {
		diags.AddError("Error searching jobs", err.Error())
		return diags
	}

	var found *api.Job
	for _, j := range jobs {
		if j.Name == name {
			found = &j
			break
		}
	}
	if found == nil {
		diags.AddError("Job Not Found", fmt.Sprintf("Job %q not found.", name))
		return diags
	}

	model.ID = types.StringValue(found.ID)
	model.Name = types.StringValue(found.Name)
	// API sets default "playbook0" when no playbook specified; map back to empty
	playbookID := found.PlaybookID
	if playbookID == "playbook0" {
		playbookID = ""
	}
	model.PlaybookID = types.StringValue(playbookID)
	model.Type = types.StringValue(found.Type)
	model.Scheduled = types.BoolValue(found.Scheduled)
	model.Recurrent = types.BoolValue(found.Recurrent)
	model.ShouldTriggerNew = types.BoolValue(found.ShouldTriggerNew)
	model.Version = types.Int64Value(int64(found.Version))

	if found.Cron != "" {
		model.Cron = types.StringValue(found.Cron)
	} else if model.Cron.IsNull() {
		// Keep null
	} else {
		model.Cron = types.StringNull()
	}

	if len(found.Tags) > 0 {
		elements := make([]attr.Value, len(found.Tags))
		for i, t := range found.Tags {
			elements[i] = types.StringValue(t)
		}
		listVal, d := types.ListValue(types.StringType, elements)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		model.Tags = listVal
	} else if !model.Tags.IsNull() {
		model.Tags = types.ListNull(types.StringType)
	}

	// Start date / ending date / ending type
	zeroDate := "0001-01-01T00:00:00Z"
	epochDate := "1970-01-01T00:00:00Z"
	if found.StartDate != "" && found.StartDate != zeroDate && found.StartDate != epochDate {
		model.StartDate = types.StringValue(found.StartDate)
	} else if model.StartDate.IsNull() {
		// Keep null
	} else {
		model.StartDate = types.StringNull()
	}

	if found.EndingDate != "" && found.EndingDate != zeroDate && found.EndingDate != epochDate {
		model.EndingDate = types.StringValue(found.EndingDate)
	} else if model.EndingDate.IsNull() {
		// Keep null
	} else {
		model.EndingDate = types.StringNull()
	}

	if found.EndingType != "" {
		model.EndingType = types.StringValue(found.EndingType)
	}

	// Human cron
	if found.HumanCron != nil && len(found.HumanCron) > 0 {
		attrs := map[string]attr.Value{}

		if tpt, ok := found.HumanCron["timePeriodType"].(string); ok {
			attrs["time_period_type"] = types.StringValue(tpt)
		} else {
			attrs["time_period_type"] = types.StringValue("")
		}

		switch tp := found.HumanCron["timePeriod"].(type) {
		case float64:
			attrs["time_period"] = types.Int64Value(int64(tp))
		default:
			attrs["time_period"] = types.Int64Value(1)
		}

		if daysRaw, ok := found.HumanCron["days"].([]interface{}); ok && len(daysRaw) > 0 {
			dayElements := make([]attr.Value, len(daysRaw))
			for i, d := range daysRaw {
				if s, ok := d.(string); ok {
					dayElements[i] = types.StringValue(s)
				}
			}
			dayList, d := types.ListValue(types.StringType, dayElements)
			diags.Append(d...)
			if diags.HasError() {
				return diags
			}
			attrs["days"] = dayList
		} else {
			attrs["days"] = types.ListNull(types.StringType)
		}

		objVal, d := types.ObjectValue(humanCronAttrTypes, attrs)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		model.HumanCron = objVal
	} else if model.HumanCron.IsNull() {
		// Keep null
	} else {
		model.HumanCron = types.ObjectNull(humanCronAttrTypes)
	}

	return diags
}

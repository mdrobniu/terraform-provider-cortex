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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
}

func (r *JobResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_job"
}

func (r *JobResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an XSOAR scheduled job.",
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
				Description: "The cron schedule expression.",
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

	return diags
}

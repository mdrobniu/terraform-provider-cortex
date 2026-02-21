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
	_ resource.Resource                = &customStatusResource{}
	_ resource.ResourceWithImportState = &customStatusResource{}
)

func NewCustomStatusResource() resource.Resource {
	return &customStatusResource{}
}

type customStatusResource struct {
	backend api.XSOARBackend
}

type customStatusModel struct {
	EnumName   types.String `tfsdk:"enum_name"`
	PrettyName types.String `tfsdk:"pretty_name"`
	Priority   types.Int64  `tfsdk:"priority"`
	StatusType types.String `tfsdk:"status_type"`
	CanDelete  types.Bool   `tfsdk:"can_delete"`
}

func (r *customStatusResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_custom_status"
}

func (r *customStatusResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a custom alert/incident status in XSIAM. " +
			"Custom statuses extend the default status and resolution workflows. " +
			"Requires webapp session authentication (session_token or cortex-login). " +
			"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
		Attributes: map[string]schema.Attribute{
			"enum_name": schema.StringAttribute{
				Description: "The internal enum name of the status, assigned by XSIAM.",
				Computed:    true,
			},
			"pretty_name": schema.StringAttribute{
				Description: "The display name of the custom status.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"priority": schema.Int64Attribute{
				Description: "The priority/ordering of the status.",
				Optional:    true,
				Computed:    true,
			},
			"status_type": schema.StringAttribute{
				Description: "The type of status. Valid values: status, resolution.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"can_delete": schema.BoolAttribute{
				Description: "Whether this custom status can be deleted.",
				Computed:    true,
			},
		},
	}
}

func (r *customStatusResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *customStatusResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan customStatusModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	statusData := map[string]interface{}{
		"pretty_name": plan.PrettyName.ValueString(),
		"status_type": plan.StatusType.ValueString(),
	}

	if !plan.Priority.IsNull() && !plan.Priority.IsUnknown() {
		statusData["priority"] = plan.Priority.ValueInt64()
	}

	result, err := r.backend.CreateCustomStatus(statusData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Custom Status",
			fmt.Sprintf("Could not create custom status %q: %s", plan.PrettyName.ValueString(), err),
		)
		return
	}

	setCustomStatusState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *customStatusResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state customStatusModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	enumName := state.EnumName.ValueString()
	statuses, err := r.backend.ListCustomStatuses()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Custom Status",
			fmt.Sprintf("Could not list custom statuses: %s", err),
		)
		return
	}

	var found *api.CustomStatus
	for i := range statuses {
		if statuses[i].EnumName == enumName {
			found = &statuses[i]
			break
		}
	}

	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setCustomStatusState(&state, found)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *customStatusResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"Custom statuses cannot be updated. Change pretty_name or status_type to trigger replacement.",
	)
}

func (r *customStatusResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state customStatusModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	enumName := state.EnumName.ValueString()
	err := r.backend.DeleteCustomStatus(enumName)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Custom Status",
			fmt.Sprintf("Could not delete custom status %q: %s", enumName, err),
		)
		return
	}
}

func (r *customStatusResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	enumName := req.ID

	statuses, err := r.backend.ListCustomStatuses()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Custom Status",
			fmt.Sprintf("Could not list custom statuses: %s", err),
		)
		return
	}

	var found *api.CustomStatus
	for i := range statuses {
		if statuses[i].EnumName == enumName {
			found = &statuses[i]
			break
		}
	}

	if found == nil {
		resp.Diagnostics.AddError(
			"Error Importing Custom Status",
			fmt.Sprintf("Could not find custom status with enum_name %q", enumName),
		)
		return
	}

	var state customStatusModel
	setCustomStatusState(&state, found)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setCustomStatusState(model *customStatusModel, status *api.CustomStatus) {
	model.EnumName = types.StringValue(status.EnumName)
	model.PrettyName = types.StringValue(status.PrettyName)
	model.Priority = types.Int64Value(int64(status.Priority))
	model.StatusType = types.StringValue(status.StatusType)
	model.CanDelete = types.BoolValue(status.CanDelete)
}

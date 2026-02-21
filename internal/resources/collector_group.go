package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &collectorGroupResource{}
	_ resource.ResourceWithImportState = &collectorGroupResource{}
)

func NewCollectorGroupResource() resource.Resource {
	return &collectorGroupResource{}
}

type collectorGroupResource struct {
	backend api.XSOARBackend
}

type collectorGroupModel struct {
	GroupID       types.Int64  `tfsdk:"group_id"`
	Name          types.String `tfsdk:"name"`
	Description   types.String `tfsdk:"description"`
	Type          types.String `tfsdk:"type"`
	Filter        types.String `tfsdk:"filter"`
	EndpointCount types.Int64  `tfsdk:"endpoint_count"`
	CreatedBy     types.String `tfsdk:"created_by"`
	ModifiedBy    types.String `tfsdk:"modified_by"`
}

func (r *collectorGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_collector_group"
}

func (r *collectorGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an XDR collector group in XSIAM. " +
			"Collector groups organize XDR collectors (log forwarders). " +
			"Not to be confused with cortex_agent_group which manages endpoint agent groups. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"group_id": schema.Int64Attribute{
				Description: "The unique numeric identifier of the collector group.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "The name of the collector group.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "A description of the collector group.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Description: "The group type. Valid values: STATIC, DYNAMIC.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"filter": schema.StringAttribute{
				Description: "JSON filter for dynamic group membership.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"endpoint_count": schema.Int64Attribute{
				Description: "Number of endpoints in the group.",
				Computed:    true,
			},
			"created_by": schema.StringAttribute{
				Description: "User who created the group.",
				Computed:    true,
			},
			"modified_by": schema.StringAttribute{
				Description: "User who last modified the group.",
				Computed:    true,
			},
		},
	}
}

func (r *collectorGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *collectorGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan collectorGroupModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupData := map[string]interface{}{
		"name":      plan.Name.ValueString(),
		"groupType": plan.Type.ValueString(),
	}
	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		groupData["description"] = plan.Description.ValueString()
	}
	lockedFilter := map[string]interface{}{
		"AND": []interface{}{
			map[string]interface{}{
				"SEARCH_FIELD": "AGENT_STATUS",
				"SEARCH_TYPE":  "NEQ",
				"SEARCH_VALUE": "STATUS_050_UNINSTALLED",
			},
		},
	}
	groupData["locked"] = lockedFilter
	groupData["lockedFilter"] = lockedFilter

	if !plan.Filter.IsNull() && !plan.Filter.IsUnknown() {
		var filterObj interface{}
		if err := json.Unmarshal([]byte(plan.Filter.ValueString()), &filterObj); err != nil {
			resp.Diagnostics.AddError("Invalid Filter JSON", fmt.Sprintf("filter must be valid JSON: %s", err))
			return
		}
		groupData["filter"] = filterObj
	} else {
		// API requires a non-empty filter object even for STATIC groups
		groupData["filter"] = map[string]interface{}{"AND": []interface{}{}}
	}

	result, err := r.backend.CreateCollectorGroup(groupData)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Collector Group", err.Error())
		return
	}

	setCollectorGroupState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *collectorGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state collectorGroupModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := int(state.GroupID.ValueInt64())
	group, err := r.backend.GetCollectorGroup(groupID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setCollectorGroupState(&state, group)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *collectorGroupResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update Not Supported",
		"Collector groups cannot be updated in-place. All fields require replacement.")
}

func (r *collectorGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state collectorGroupModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := int(state.GroupID.ValueInt64())
	err := r.backend.DeleteCollectorGroup(groupID)
	if err != nil {
		resp.Diagnostics.AddError("Error Deleting Collector Group", err.Error())
	}
}

func (r *collectorGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	groupID, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Error Importing Collector Group",
			fmt.Sprintf("Invalid group ID %q: must be numeric", req.ID))
		return
	}

	group, err := r.backend.GetCollectorGroup(groupID)
	if err != nil {
		resp.Diagnostics.AddError("Error Importing Collector Group", err.Error())
		return
	}

	var state collectorGroupModel
	setCollectorGroupState(&state, group)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setCollectorGroupState(model *collectorGroupModel, group *api.CollectorGroup) {
	model.GroupID = types.Int64Value(int64(group.GroupID))
	model.Name = types.StringValue(group.Name)
	model.Type = types.StringValue(group.Type)
	model.EndpointCount = types.Int64Value(int64(group.Count))
	if group.Description != "" {
		model.Description = types.StringValue(group.Description)
	} else {
		model.Description = types.StringNull()
	}
	if group.Filter != "" {
		model.Filter = types.StringValue(group.Filter)
	} else {
		model.Filter = types.StringNull()
	}
	if group.CreatedBy != "" {
		model.CreatedBy = types.StringValue(group.CreatedBy)
	} else {
		model.CreatedBy = types.StringNull()
	}
	if group.ModifiedBy != "" {
		model.ModifiedBy = types.StringValue(group.ModifiedBy)
	} else {
		model.ModifiedBy = types.StringNull()
	}
}

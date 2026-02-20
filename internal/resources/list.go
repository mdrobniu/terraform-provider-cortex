package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &listResource{}
	_ resource.ResourceWithImportState = &listResource{}
)

// NewListResource is a factory function for the resource.
func NewListResource() resource.Resource {
	return &listResource{}
}

type listResource struct {
	backend api.XSOARBackend
}

type listResourceModel struct {
	ID      types.String `tfsdk:"id"`
	Name    types.String `tfsdk:"name"`
	Type    types.String `tfsdk:"type"`
	Data    types.String `tfsdk:"data"`
	Version types.Int64  `tfsdk:"version"`
}

func (r *listResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_list"
}

func (r *listResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a list in XSOAR/XSIAM. Lists store configuration data such as IP lists, CSV tables, or JSON config used by playbooks and integrations.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the list.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the list. Also serves as the list identifier.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Description: "The content type of the list. Valid values: plain_text, json, html, markdown, css.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("plain_text"),
			},
			"data": schema.StringAttribute{
				Description: "The content of the list as a string.",
				Required:    true,
			},
			"version": schema.Int64Attribute{
				Description: "The version number of the list, used for optimistic concurrency control.",
				Computed:    true,
			},
		},
	}
}

func (r *listResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *listResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan listResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	listData := map[string]interface{}{
		"name": plan.Name.ValueString(),
		"type": plan.Type.ValueString(),
		"data": plan.Data.ValueString(),
	}

	result, err := r.backend.CreateList(listData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating List",
			fmt.Sprintf("Could not create list %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	plan.ID = types.StringValue(result.ID)
	plan.Version = types.Int64Value(int64(result.Version))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *listResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state listResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := state.Name.ValueString()

	list, err := r.backend.GetList(name)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(list.ID)
	state.Name = types.StringValue(list.Name)
	state.Type = types.StringValue(list.Type)
	state.Data = types.StringValue(list.Data)
	state.Version = types.Int64Value(int64(list.Version))

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *listResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan listResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state listResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	listData := map[string]interface{}{
		"id":      state.ID.ValueString(),
		"version": state.Version.ValueInt64(),
		"name":    plan.Name.ValueString(),
		"type":    plan.Type.ValueString(),
		"data":    plan.Data.ValueString(),
	}

	result, err := r.backend.UpdateList(listData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating List",
			fmt.Sprintf("Could not update list %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	plan.ID = types.StringValue(result.ID)
	plan.Version = types.Int64Value(int64(result.Version))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *listResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state listResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.backend.DeleteList(state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting List",
			fmt.Sprintf("Could not delete list %q: %s", state.Name.ValueString(), err),
		)
		return
	}
}

func (r *listResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := req.ID

	list, err := r.backend.GetList(name)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing List",
			fmt.Sprintf("Could not find list with name %q: %s", name, err),
		)
		return
	}

	state := listResourceModel{
		ID:      types.StringValue(list.ID),
		Name:    types.StringValue(list.Name),
		Type:    types.StringValue(list.Type),
		Data:    types.StringValue(list.Data),
		Version: types.Int64Value(int64(list.Version)),
	}

	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

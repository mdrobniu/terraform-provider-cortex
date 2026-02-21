package resources

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &incidentDomainResource{}
	_ resource.ResourceWithImportState = &incidentDomainResource{}
)

func NewIncidentDomainResource() resource.Resource {
	return &incidentDomainResource{}
}

type incidentDomainResource struct {
	backend api.XSOARBackend
}

type incidentDomainModel struct {
	DomainID         types.Int64  `tfsdk:"domain_id"`
	Name             types.String `tfsdk:"name"`
	PrettyName       types.String `tfsdk:"pretty_name"`
	Color            types.String `tfsdk:"color"`
	Description      types.String `tfsdk:"description"`
	IsDefault        types.Bool   `tfsdk:"is_default"`
	Statuses         types.List   `tfsdk:"statuses"`
	ResolvedStatuses types.List   `tfsdk:"resolved_statuses"`
}

func (r *incidentDomainResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_incident_domain"
}

func (r *incidentDomainResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an incident domain in XSIAM. " +
			"Incident domains categorize alerts and incidents into logical groups with their own status workflows. " +
			"Requires webapp session authentication (session_token or cortex-login). " +
			"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
		Attributes: map[string]schema.Attribute{
			"domain_id": schema.Int64Attribute{
				Description: "The unique numeric identifier of the incident domain, assigned by XSIAM.",
				Computed:    true,
			},
			"name": schema.StringAttribute{
				Description: "The internal name of the incident domain, assigned by XSIAM.",
				Computed:    true,
			},
			"pretty_name": schema.StringAttribute{
				Description: "The display name of the incident domain.",
				Required:    true,
			},
			"color": schema.StringAttribute{
				Description: "The color of the incident domain (hex color code, e.g. '#FF5733').",
				Optional:    true,
				Computed:    true,
			},
			"description": schema.StringAttribute{
				Description: "A description of the incident domain.",
				Optional:    true,
				Computed:    true,
			},
			"is_default": schema.BoolAttribute{
				Description: "Whether this is the default incident domain.",
				Computed:    true,
			},
			"statuses": schema.ListAttribute{
				Description: "The list of active status names available in this domain.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"resolved_statuses": schema.ListAttribute{
				Description: "The list of resolved/closed status names available in this domain.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *incidentDomainResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *incidentDomainResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan incidentDomainModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainData := map[string]interface{}{
		"pretty_name": plan.PrettyName.ValueString(),
	}

	if !plan.Color.IsNull() && !plan.Color.IsUnknown() {
		domainData["color"] = plan.Color.ValueString()
	}
	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		domainData["description"] = plan.Description.ValueString()
	}

	result, err := r.backend.CreateIncidentDomain(domainData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Incident Domain",
			fmt.Sprintf("Could not create incident domain %q: %s", plan.PrettyName.ValueString(), err),
		)
		return
	}

	setIncidentDomainState(ctx, &plan, result, &resp.Diagnostics)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *incidentDomainResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state incidentDomainModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainID := int(state.DomainID.ValueInt64())
	domain, err := r.backend.GetIncidentDomain(domainID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setIncidentDomainState(ctx, &state, domain, &resp.Diagnostics)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *incidentDomainResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan incidentDomainModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state incidentDomainModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainID := int(state.DomainID.ValueInt64())
	domainData := map[string]interface{}{
		"pretty_name": plan.PrettyName.ValueString(),
	}

	if !plan.Color.IsNull() && !plan.Color.IsUnknown() {
		domainData["color"] = plan.Color.ValueString()
	}
	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		domainData["description"] = plan.Description.ValueString()
	}

	result, err := r.backend.UpdateIncidentDomain(domainID, domainData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Incident Domain",
			fmt.Sprintf("Could not update incident domain %d: %s", domainID, err),
		)
		return
	}

	setIncidentDomainState(ctx, &plan, result, &resp.Diagnostics)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *incidentDomainResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state incidentDomainModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	domainID := int(state.DomainID.ValueInt64())
	err := r.backend.DeleteIncidentDomain(domainID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Incident Domain",
			fmt.Sprintf("Could not delete incident domain %d: %s", domainID, err),
		)
		return
	}
}

func (r *incidentDomainResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	domainID, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Incident Domain",
			fmt.Sprintf("Invalid domain ID %q: must be a numeric ID", req.ID),
		)
		return
	}

	domain, err := r.backend.GetIncidentDomain(domainID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Incident Domain",
			fmt.Sprintf("Could not find incident domain %d: %s", domainID, err),
		)
		return
	}

	var state incidentDomainModel
	setIncidentDomainState(ctx, &state, domain, &resp.Diagnostics)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setIncidentDomainState(ctx context.Context, model *incidentDomainModel, domain *api.IncidentDomain, diagnostics *diag.Diagnostics) {
	model.DomainID = types.Int64Value(int64(domain.DomainID))
	model.Name = types.StringValue(domain.Name)
	model.PrettyName = types.StringValue(domain.PrettyName)
	model.IsDefault = types.BoolValue(domain.IsDefault)

	if domain.Color != "" {
		model.Color = types.StringValue(domain.Color)
	} else {
		model.Color = types.StringNull()
	}
	if domain.Description != "" {
		model.Description = types.StringValue(domain.Description)
	} else {
		model.Description = types.StringNull()
	}

	if domain.Statuses != nil {
		statusesList, diags := types.ListValueFrom(ctx, types.StringType, domain.Statuses)
		diagnostics.Append(diags...)
		model.Statuses = statusesList
	} else {
		model.Statuses = types.ListNull(types.StringType)
	}

	if domain.ResolvedStatuses != nil {
		resolvedList, diags := types.ListValueFrom(ctx, types.StringType, domain.ResolvedStatuses)
		diagnostics.Append(diags...)
		model.ResolvedStatuses = resolvedList
	} else {
		model.ResolvedStatuses = types.ListNull(types.StringType)
	}
}

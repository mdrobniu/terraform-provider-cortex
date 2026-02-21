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

var _ resource.Resource = &dataModelingRulesResource{}

func NewDataModelingRulesResource() resource.Resource {
	return &dataModelingRulesResource{}
}

type dataModelingRulesResource struct {
	backend api.XSOARBackend
}

type dataModelingRulesModel struct {
	Text       types.String `tfsdk:"text"`
	Hash       types.String `tfsdk:"hash"`
	LastUpdate types.String `tfsdk:"last_update"`
}

func (r *dataModelingRulesResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_data_modeling_rules"
}

func (r *dataModelingRulesResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages user-defined data modeling rules in XSIAM. " +
			"This is a singleton resource containing the full XQL data modeling rules text. " +
			"Uses hash-based optimistic locking to detect concurrent modifications. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"text": schema.StringAttribute{
				Description: "The full XQL data modeling rules text.",
				Required:    true,
			},
			"hash": schema.StringAttribute{
				Description: "Optimistic lock hash. Used internally to detect concurrent modifications.",
				Computed:    true,
			},
			"last_update": schema.StringAttribute{
				Description: "Timestamp of the last update.",
				Computed:    true,
			},
		},
	}
}

func (r *dataModelingRulesResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *dataModelingRulesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dataModelingRulesModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	current, err := r.backend.GetDataModelingRules()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Current Data Modeling Rules", err.Error())
		return
	}

	result, err := r.backend.SaveDataModelingRules(plan.Text.ValueString(), current.Hash)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Data Modeling Rules", err.Error())
		return
	}

	plan.Text = types.StringValue(result.Text)
	plan.Hash = types.StringValue(result.Hash)
	plan.LastUpdate = types.StringValue(result.LastUpdate)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *dataModelingRulesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dataModelingRulesModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.backend.GetDataModelingRules()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Data Modeling Rules", err.Error())
		return
	}

	state.Text = types.StringValue(result.Text)
	state.Hash = types.StringValue(result.Hash)
	state.LastUpdate = types.StringValue(result.LastUpdate)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *dataModelingRulesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan dataModelingRulesModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state dataModelingRulesModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	baseHash := state.Hash.ValueString()
	result, err := r.backend.SaveDataModelingRules(plan.Text.ValueString(), baseHash)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating Data Modeling Rules", err.Error())
		return
	}

	plan.Text = types.StringValue(result.Text)
	plan.Hash = types.StringValue(result.Hash)
	plan.LastUpdate = types.StringValue(result.LastUpdate)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *dataModelingRulesResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	current, err := r.backend.GetDataModelingRules()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Data Modeling Rules for Delete", err.Error())
		return
	}
	_, err = r.backend.SaveDataModelingRules("// Cleared by Terraform", current.Hash)
	if err != nil {
		resp.Diagnostics.AddError("Error Clearing Data Modeling Rules", err.Error())
	}
}

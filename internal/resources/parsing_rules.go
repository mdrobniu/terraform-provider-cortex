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

var _ resource.Resource = &parsingRulesResource{}

func NewParsingRulesResource() resource.Resource {
	return &parsingRulesResource{}
}

type parsingRulesResource struct {
	backend api.XSOARBackend
}

type parsingRulesModel struct {
	Text types.String `tfsdk:"text"`
	Hash types.String `tfsdk:"hash"`
}

func (r *parsingRulesResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_parsing_rules"
}

func (r *parsingRulesResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages user-defined parsing rules in XSIAM. " +
			"This is a singleton resource containing the full XQL parsing rules text. " +
			"Uses hash-based optimistic locking to detect concurrent modifications. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"text": schema.StringAttribute{
				Description: "The full XQL parsing rules text.",
				Required:    true,
			},
			"hash": schema.StringAttribute{
				Description: "Optimistic lock hash. Used internally to detect concurrent modifications.",
				Computed:    true,
			},
		},
	}
}

func (r *parsingRulesResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *parsingRulesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan parsingRulesModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	current, err := r.backend.GetParsingRules()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Current Parsing Rules", err.Error())
		return
	}

	result, err := r.backend.SaveParsingRules(plan.Text.ValueString(), current.Hash)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Parsing Rules", err.Error())
		return
	}

	plan.Text = types.StringValue(result.Text)
	plan.Hash = types.StringValue(result.Hash)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *parsingRulesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state parsingRulesModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := r.backend.GetParsingRules()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Parsing Rules", err.Error())
		return
	}

	state.Text = types.StringValue(result.Text)
	state.Hash = types.StringValue(result.Hash)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *parsingRulesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan parsingRulesModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state parsingRulesModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	baseHash := state.Hash.ValueString()
	result, err := r.backend.SaveParsingRules(plan.Text.ValueString(), baseHash)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating Parsing Rules", err.Error())
		return
	}

	plan.Text = types.StringValue(result.Text)
	plan.Hash = types.StringValue(result.Hash)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *parsingRulesResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	current, err := r.backend.GetParsingRules()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Parsing Rules for Delete", err.Error())
		return
	}
	_, err = r.backend.SaveParsingRules("// Cleared by Terraform", current.Hash)
	if err != nil {
		resp.Diagnostics.AddError("Error Clearing Parsing Rules", err.Error())
	}
}

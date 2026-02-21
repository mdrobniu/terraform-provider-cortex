package datasources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &collectorPoliciesDataSource{}

func NewCollectorPoliciesDataSource() datasource.DataSource {
	return &collectorPoliciesDataSource{}
}

type collectorPoliciesDataSource struct {
	backend api.XSOARBackend
}

type collectorPolicyModel struct {
	ID         types.String `tfsdk:"id"`
	Name       types.String `tfsdk:"name"`
	Platform   types.String `tfsdk:"platform"`
	Priority   types.Int64  `tfsdk:"priority"`
	IsEnabled  types.Bool   `tfsdk:"is_enabled"`
	TargetID   types.Int64  `tfsdk:"target_id"`
	StandardID types.Int64  `tfsdk:"standard_id"`
}

type collectorPoliciesModel struct {
	Policies []collectorPolicyModel `tfsdk:"policies"`
}

func (d *collectorPoliciesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_collector_policies"
}

func (d *collectorPoliciesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists all XDR collector policies in XSIAM. " +
			"Collector policies define which collector profiles are applied to which groups. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"policies": schema.ListNestedAttribute{
				Description: "List of collector policies.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The unique identifier of the policy.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The name of the policy.",
							Computed:    true,
						},
						"platform": schema.StringAttribute{
							Description: "The platform this policy applies to.",
							Computed:    true,
						},
						"priority": schema.Int64Attribute{
							Description: "The priority of the policy.",
							Computed:    true,
						},
						"is_enabled": schema.BoolAttribute{
							Description: "Whether the policy is enabled.",
							Computed:    true,
						},
						"target_id": schema.Int64Attribute{
							Description: "The target group ID.",
							Computed:    true,
						},
						"standard_id": schema.Int64Attribute{
							Description: "The standard profile ID.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *collectorPoliciesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	pd, ok := req.ProviderData.(*providerdata.ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected DataSource Configure Type",
			fmt.Sprintf("Expected *providerdata.ProviderData, got: %T", req.ProviderData),
		)
		return
	}
	d.backend = pd.Backend
}

func (d *collectorPoliciesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	policies, err := d.backend.ListCollectorPolicies()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Collector Policies", err.Error())
		return
	}

	var state collectorPoliciesModel
	for _, p := range policies {
		state.Policies = append(state.Policies, collectorPolicyModel{
			ID:         types.StringValue(p.ID),
			Name:       types.StringValue(p.Name),
			Platform:   types.StringValue(p.Platform),
			Priority:   types.Int64Value(int64(p.Priority)),
			IsEnabled:  types.BoolValue(p.IsEnabled),
			TargetID:   types.Int64Value(int64(p.TargetID)),
			StandardID: types.Int64Value(int64(p.StandardID)),
		})
	}
	if state.Policies == nil {
		state.Policies = []collectorPolicyModel{}
	}

	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

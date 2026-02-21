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

var _ datasource.DataSource = &datasetsDataSource{}

func NewDatasetsDataSource() datasource.DataSource {
	return &datasetsDataSource{}
}

type datasetsDataSource struct {
	backend api.XSOARBackend
}

type datasetModel struct {
	ID                types.Int64  `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Type              types.String `tfsdk:"type"`
	TotalSizeBytes    types.Int64  `tfsdk:"total_size_bytes"`
	TotalEventsStored types.Int64  `tfsdk:"total_events_stored"`
	SourceQuery       types.String `tfsdk:"source_query"`
}

type datasetsModel struct {
	Datasets []datasetModel `tfsdk:"datasets"`
}

func (d *datasetsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_datasets"
}

func (d *datasetsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists all datasets in XSIAM. " +
			"Datasets represent data collections used for XQL queries and analytics. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"datasets": schema.ListNestedAttribute{
				Description: "List of datasets.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							Description: "The unique numeric identifier of the dataset.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The name of the dataset.",
							Computed:    true,
						},
						"type": schema.StringAttribute{
							Description: "The dataset type (SYSTEM, LOOKUP, RAW, USER, SNAPSHOT, CORRELATION, SYSTEM_AUDIT).",
							Computed:    true,
						},
						"total_size_bytes": schema.Int64Attribute{
							Description: "Total size of the dataset in bytes.",
							Computed:    true,
						},
						"total_events_stored": schema.Int64Attribute{
							Description: "Total number of events stored in the dataset.",
							Computed:    true,
						},
						"source_query": schema.StringAttribute{
							Description: "Source XQL query for computed datasets.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *datasetsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *datasetsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	datasets, err := d.backend.ListDatasets()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Datasets", err.Error())
		return
	}

	var state datasetsModel
	for _, ds := range datasets {
		state.Datasets = append(state.Datasets, datasetModel{
			ID:                types.Int64Value(int64(ds.ID)),
			Name:              types.StringValue(ds.Name),
			Type:              types.StringValue(ds.Type),
			TotalSizeBytes:    types.Int64Value(ds.TotalSizeBytes),
			TotalEventsStored: types.Int64Value(ds.TotalEventsStored),
			SourceQuery:       types.StringValue(ds.SourceQuery),
		})
	}
	if state.Datasets == nil {
		state.Datasets = []datasetModel{}
	}

	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

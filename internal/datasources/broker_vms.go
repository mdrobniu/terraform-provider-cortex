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

var _ datasource.DataSource = &brokerVMsDataSource{}

func NewBrokerVMsDataSource() datasource.DataSource {
	return &brokerVMsDataSource{}
}

type brokerVMsDataSource struct {
	backend api.XSOARBackend
}

type brokerVMModel struct {
	DeviceID  types.String `tfsdk:"device_id"`
	Name      types.String `tfsdk:"name"`
	Status    types.String `tfsdk:"status"`
	FQDN      types.String `tfsdk:"fqdn"`
	IsCluster types.Bool   `tfsdk:"is_cluster"`
}

type brokerVMsModel struct {
	VMs []brokerVMModel `tfsdk:"vms"`
}

func (d *brokerVMsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_broker_vms"
}

func (d *brokerVMsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists all broker VMs in XSIAM. " +
			"Broker VMs are virtual machines that handle data brokering for collector profiles. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"vms": schema.ListNestedAttribute{
				Description: "List of broker VMs.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"device_id": schema.StringAttribute{
							Description: "The unique device identifier.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "The name of the broker VM.",
							Computed:    true,
						},
						"status": schema.StringAttribute{
							Description: "The current status of the broker VM.",
							Computed:    true,
						},
						"fqdn": schema.StringAttribute{
							Description: "The fully qualified domain name.",
							Computed:    true,
						},
						"is_cluster": schema.BoolAttribute{
							Description: "Whether this is a cluster node.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *brokerVMsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *brokerVMsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	vms, err := d.backend.ListBrokerVMs()
	if err != nil {
		resp.Diagnostics.AddError("Error Reading Broker VMs", err.Error())
		return
	}

	var state brokerVMsModel
	for _, vm := range vms {
		state.VMs = append(state.VMs, brokerVMModel{
			DeviceID:  types.StringValue(vm.DeviceID),
			Name:      types.StringValue(vm.Name),
			Status:    types.StringValue(vm.Status),
			FQDN:      types.StringValue(vm.FQDN),
			IsCluster: types.BoolValue(vm.IsCluster),
		})
	}
	if state.VMs == nil {
		state.VMs = []brokerVMModel{}
	}

	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

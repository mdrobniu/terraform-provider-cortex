package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &asmAssetRemovalResource{}

func NewASMAssetRemovalResource() resource.Resource {
	return &asmAssetRemovalResource{}
}

type asmAssetRemovalResource struct {
	backend api.XSOARBackend
}

type asmAssetModel struct {
	AssetType types.String `tfsdk:"asset_type"`
	AssetName types.String `tfsdk:"asset_name"`
}

type asmAssetRemovalModel struct {
	Assets        types.List `tfsdk:"assets"`
	RemovedAssets types.List `tfsdk:"removed_assets"`
	Errors        types.List `tfsdk:"errors"`
}

func (r *asmAssetRemovalResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_asm_asset_removal"
}

func (r *asmAssetRemovalResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Performs bulk ASM (Attack Surface Management) asset removal in XSIAM. " +
			"This is a fire-and-forget resource: assets are removed on create. " +
			"Deletion is a no-op (asset removal is irreversible). " +
			"All fields are ForceNew; any change triggers a new removal. " +
			"Requires webapp session authentication (session_token or cortex-login).",
		Attributes: map[string]schema.Attribute{
			"assets": schema.ListNestedAttribute{
				Description: "List of assets to remove.",
				Required:    true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"asset_type": schema.StringAttribute{
							Description: "Asset type. Valid values: Domain, IP_RANGE, Certificate.",
							Required:    true,
						},
						"asset_name": schema.StringAttribute{
							Description: "Asset identifier (domain name, IP range, or certificate).",
							Required:    true,
						},
					},
				},
			},
			"removed_assets": schema.ListAttribute{
				Description: "List of successfully removed asset identifiers.",
				Computed:    true,
				ElementType: types.StringType,
			},
			"errors": schema.ListAttribute{
				Description: "List of errors encountered during removal.",
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *asmAssetRemovalResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *asmAssetRemovalResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan asmAssetRemovalModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var assets []asmAssetModel
	diags = plan.Assets.ElementsAs(ctx, &assets, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	assetMaps := make([]map[string]string, len(assets))
	for i, a := range assets {
		assetMaps[i] = map[string]string{
			"asset_type": a.AssetType.ValueString(),
			"asset_name": a.AssetName.ValueString(),
		}
	}

	result, err := r.backend.BulkRemoveASMAssets(assetMaps)
	if err != nil {
		resp.Diagnostics.AddError("Error Removing ASM Assets", err.Error())
		return
	}

	removedList, _ := types.ListValueFrom(ctx, types.StringType, result.RemovedAssets)
	plan.RemovedAssets = removedList
	if len(result.Errors) > 0 {
		errorList, _ := types.ListValueFrom(ctx, types.StringType, result.Errors)
		plan.Errors = errorList
	} else {
		plan.Errors = types.ListNull(types.StringType)
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *asmAssetRemovalResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
	// State-only resource; read returns stored state
}

func (r *asmAssetRemovalResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update Not Supported",
		"ASM asset removal is a one-time action. All fields require replacement.")
}

func (r *asmAssetRemovalResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// No-op: asset removal is irreversible
}

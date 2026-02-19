package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &externalStorageResource{}
	_ resource.ResourceWithImportState = &externalStorageResource{}
)

func NewExternalStorageResource() resource.Resource {
	return &externalStorageResource{}
}

type externalStorageResource struct {
	backend api.XSOARBackend
}

type externalStorageResourceModel struct {
	StorageID   types.String `tfsdk:"storage_id"`
	Name        types.String `tfsdk:"name"`
	StorageType types.String `tfsdk:"storage_type"`
	// NFS fields
	NFSServer types.String `tfsdk:"nfs_server"`
	NFSPath   types.String `tfsdk:"nfs_path"`
	// AWS fields
	BucketName types.String `tfsdk:"bucket_name"`
	Region     types.String `tfsdk:"region"`
	AccessKey  types.String `tfsdk:"access_key"`
	SecretKey  types.String `tfsdk:"secret_key"`
	// S3-compatible fields (also uses bucket_name, access_key, secret_key)
	S3URL types.String `tfsdk:"s3_url"`
}

func (r *externalStorageResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_external_storage"
}

func (r *externalStorageResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an external storage configuration on XSOAR 8 OPP. " +
			"Supports NFS, AWS S3, and S3-compatible storage types. " +
			"Requires session auth (ui_url, username, password in provider config).",
		Attributes: map[string]schema.Attribute{
			"storage_id": schema.StringAttribute{
				Description: "The unique identifier of the external storage.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "The display name of the external storage.",
				Required:    true,
			},
			"storage_type": schema.StringAttribute{
				Description: "The type of external storage: \"nfs\", \"aws\", or \"s3compatible\".",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			// NFS fields
			"nfs_server": schema.StringAttribute{
				Description: "The NFS server hostname or IP address. Required when storage_type is \"nfs\".",
				Optional:    true,
			},
			"nfs_path": schema.StringAttribute{
				Description: "The NFS export path. Required when storage_type is \"nfs\".",
				Optional:    true,
			},
			// AWS / S3-compatible shared fields
			"bucket_name": schema.StringAttribute{
				Description: "The S3 bucket name. Required when storage_type is \"aws\" or \"s3compatible\".",
				Optional:    true,
			},
			"region": schema.StringAttribute{
				Description: "The AWS region (e.g., \"us-east-1\"). Required when storage_type is \"aws\".",
				Optional:    true,
			},
			"access_key": schema.StringAttribute{
				Description: "The access key for S3 authentication. Required when storage_type is \"aws\" or \"s3compatible\".",
				Optional:    true,
				Sensitive:   true,
			},
			"secret_key": schema.StringAttribute{
				Description: "The secret key for S3 authentication. Required when storage_type is \"aws\" or \"s3compatible\".",
				Optional:    true,
				Sensitive:   true,
			},
			// S3-compatible only
			"s3_url": schema.StringAttribute{
				Description: "The S3-compatible endpoint URL. Required when storage_type is \"s3compatible\".",
				Optional:    true,
			},
		},
	}
}

func (r *externalStorageResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *externalStorageResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan externalStorageResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := map[string]interface{}{
		"name":         plan.Name.ValueString(),
		"storage_type": plan.StorageType.ValueString(),
	}

	connDetails := r.buildConnectionDetails(&plan)
	if len(connDetails) > 0 {
		payload["connection_details"] = connDetails
	}

	storage, err := r.backend.CreateExternalStorage(payload)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating External Storage",
			fmt.Sprintf("Could not create external storage %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	plan.StorageID = types.StringValue(storage.StorageID)
	plan.Name = types.StringValue(storage.Name)
	plan.StorageType = types.StringValue(storage.StorageType)
	// Connection details are preserved from plan - the API transforms them internally.

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *externalStorageResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state externalStorageResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	storageID := state.StorageID.ValueString()
	storage, err := r.findStorageByID(storageID)
	if err != nil {
		resp.State.RemoveResource(ctx)
		return
	}

	state.StorageID = types.StringValue(storage.StorageID)
	state.Name = types.StringValue(storage.Name)
	state.StorageType = types.StringValue(storage.StorageType)
	// Connection details (nfs_server, nfs_path, bucket_name, etc.) are transformed by
	// the API internally and not returned in the original format. Preserve from state.

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *externalStorageResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan externalStorageResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state externalStorageResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := map[string]interface{}{
		"storage_id":   state.StorageID.ValueString(),
		"name":         plan.Name.ValueString(),
		"storage_type": plan.StorageType.ValueString(),
	}

	connDetails := r.buildConnectionDetails(&plan)
	if len(connDetails) > 0 {
		payload["connection_details"] = connDetails
	}

	storage, err := r.backend.UpdateExternalStorage(payload)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating External Storage",
			fmt.Sprintf("Could not update external storage %q: %s", plan.Name.ValueString(), err),
		)
		return
	}

	plan.StorageID = types.StringValue(storage.StorageID)
	plan.Name = types.StringValue(storage.Name)
	plan.StorageType = types.StringValue(storage.StorageType)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *externalStorageResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state externalStorageResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.backend.DeleteExternalStorage(state.StorageID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting External Storage",
			fmt.Sprintf("Could not delete external storage %q: %s", state.Name.ValueString(), err),
		)
		return
	}
}

func (r *externalStorageResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	storageID := req.ID
	storage, err := r.findStorageByID(storageID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing External Storage",
			fmt.Sprintf("Could not find external storage with ID %q: %s", storageID, err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("storage_id"), storage.StorageID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), storage.Name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("storage_type"), storage.StorageType)...)

	cd := storage.ConnectionDetails
	switch storage.StorageType {
	case "nfs":
		if v, ok := cd["nfs_server"]; ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("nfs_server"), v)...)
		}
		if v, ok := cd["nfs_path"]; ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("nfs_path"), v)...)
		}
	case "aws":
		if v, ok := cd["bucket_name"]; ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("bucket_name"), v)...)
		}
		if v, ok := cd["region"]; ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("region"), v)...)
		}
		if v, ok := cd["access_key"]; ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("access_key"), v)...)
		}
		if v, ok := cd["secret_key"]; ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("secret_key"), v)...)
		}
	case "s3compatible":
		if v, ok := cd["url"]; ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("s3_url"), v)...)
		}
		if v, ok := cd["bucket_name"]; ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("bucket_name"), v)...)
		}
		if v, ok := cd["access_key"]; ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("access_key"), v)...)
		}
		if v, ok := cd["secret_key"]; ok {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("secret_key"), v)...)
		}
	}
}

func (r *externalStorageResource) findStorageByID(storageID string) (*api.ExternalStorage, error) {
	storages, err := r.backend.ListExternalStorage()
	if err != nil {
		return nil, fmt.Errorf("listing external storage: %w", err)
	}
	for _, s := range storages {
		if s.StorageID == storageID {
			return &s, nil
		}
	}
	return nil, fmt.Errorf("external storage %q not found", storageID)
}

func (r *externalStorageResource) buildConnectionDetails(model *externalStorageResourceModel) map[string]string {
	connDetails := map[string]string{}

	switch model.StorageType.ValueString() {
	case "nfs":
		if !model.NFSServer.IsNull() && !model.NFSServer.IsUnknown() {
			connDetails["nfs_server"] = model.NFSServer.ValueString()
		}
		if !model.NFSPath.IsNull() && !model.NFSPath.IsUnknown() {
			connDetails["nfs_path"] = model.NFSPath.ValueString()
		}
	case "aws":
		if !model.BucketName.IsNull() && !model.BucketName.IsUnknown() {
			connDetails["bucket_name"] = model.BucketName.ValueString()
		}
		if !model.Region.IsNull() && !model.Region.IsUnknown() {
			connDetails["region"] = model.Region.ValueString()
		}
		if !model.AccessKey.IsNull() && !model.AccessKey.IsUnknown() {
			connDetails["access_key"] = model.AccessKey.ValueString()
		}
		if !model.SecretKey.IsNull() && !model.SecretKey.IsUnknown() {
			connDetails["secret_key"] = model.SecretKey.ValueString()
		}
	case "s3compatible":
		if !model.S3URL.IsNull() && !model.S3URL.IsUnknown() {
			connDetails["url"] = model.S3URL.ValueString()
		}
		if !model.BucketName.IsNull() && !model.BucketName.IsUnknown() {
			connDetails["bucket_name"] = model.BucketName.ValueString()
		}
		if !model.AccessKey.IsNull() && !model.AccessKey.IsUnknown() {
			connDetails["access_key"] = model.AccessKey.ValueString()
		}
		if !model.SecretKey.IsNull() && !model.SecretKey.IsUnknown() {
			connDetails["secret_key"] = model.SecretKey.ValueString()
		}
	}

	return connDetails
}

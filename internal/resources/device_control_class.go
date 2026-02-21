package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &deviceControlClassResource{}
	_ resource.ResourceWithImportState = &deviceControlClassResource{}
)

func NewDeviceControlClassResource() resource.Resource {
	return &deviceControlClassResource{}
}

type deviceControlClassResource struct {
	backend api.XSOARBackend
}

type deviceControlClassModel struct {
	Identifier types.String `tfsdk:"identifier"`
	Type       types.String `tfsdk:"type"`
}

func (r *deviceControlClassResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_device_control_class"
}

func (r *deviceControlClassResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a device control class in XSIAM. " +
			"Device control classes define user-defined USB device categories for endpoint policy enforcement. " +
			"Requires webapp session authentication (session_token or cortex-login). " +
			"Webapp API endpoints based on XSIAM V3.4; may differ on other versions.",
		Attributes: map[string]schema.Attribute{
			"identifier": schema.StringAttribute{
				Description: "The unique identifier of the device control class, assigned by XSIAM.",
				Computed:    true,
			},
			"type": schema.StringAttribute{
				Description: "The device class type name.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *deviceControlClassResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *deviceControlClassResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan deviceControlClassModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	classData := map[string]interface{}{
		"type": plan.Type.ValueString(),
	}

	result, err := r.backend.CreateDeviceControlClass(classData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Device Control Class",
			fmt.Sprintf("Could not create device control class %q: %s", plan.Type.ValueString(), err),
		)
		return
	}

	setDeviceControlClassState(&plan, result)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *deviceControlClassResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state deviceControlClassModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	identifier := state.Identifier.ValueString()
	classes, err := r.backend.ListDeviceControlClasses()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Device Control Class",
			fmt.Sprintf("Could not list device control classes: %s", err),
		)
		return
	}

	var found *api.DeviceControlClass
	for i := range classes {
		if classes[i].Identifier == identifier {
			found = &classes[i]
			break
		}
	}

	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	setDeviceControlClassState(&state, found)
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *deviceControlClassResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"Device control classes cannot be updated. Change the type to trigger replacement.",
	)
}

func (r *deviceControlClassResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state deviceControlClassModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	identifier := state.Identifier.ValueString()
	err := r.backend.DeleteDeviceControlClass(identifier)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Device Control Class",
			fmt.Sprintf("Could not delete device control class %q: %s", identifier, err),
		)
		return
	}
}

func (r *deviceControlClassResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	identifier := req.ID

	classes, err := r.backend.ListDeviceControlClasses()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Importing Device Control Class",
			fmt.Sprintf("Could not list device control classes: %s", err),
		)
		return
	}

	var found *api.DeviceControlClass
	for i := range classes {
		if classes[i].Identifier == identifier {
			found = &classes[i]
			break
		}
	}

	if found == nil {
		resp.Diagnostics.AddError(
			"Error Importing Device Control Class",
			fmt.Sprintf("Could not find device control class with identifier %q", identifier),
		)
		return
	}

	var state deviceControlClassModel
	setDeviceControlClassState(&state, found)
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func setDeviceControlClassState(model *deviceControlClassModel, class *api.DeviceControlClass) {
	model.Identifier = types.StringValue(class.Identifier)
	model.Type = types.StringValue(class.Type)
}

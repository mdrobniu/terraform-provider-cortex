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

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &passwordPolicyResource{}
	_ resource.ResourceWithImportState = &passwordPolicyResource{}
)

// NewPasswordPolicyResource is a factory function for the resource.
func NewPasswordPolicyResource() resource.Resource {
	return &passwordPolicyResource{}
}

// passwordPolicyResource manages the singleton password policy settings.
type passwordPolicyResource struct {
	backend api.XSOARBackend
}

// passwordPolicyResourceModel maps the resource schema data.
type passwordPolicyResourceModel struct {
	ID                     types.String `tfsdk:"id"`
	Enabled                types.Bool   `tfsdk:"enabled"`
	MinPasswordLength      types.Int64  `tfsdk:"min_password_length"`
	MinLowercaseChars      types.Int64  `tfsdk:"min_lowercase_chars"`
	MinUppercaseChars      types.Int64  `tfsdk:"min_uppercase_chars"`
	MinDigitsOrSymbols     types.Int64  `tfsdk:"min_digits_or_symbols"`
	PreventRepetition      types.Bool   `tfsdk:"prevent_repetition"`
	ExpireAfter            types.Int64  `tfsdk:"expire_after"`
	MaxFailedLoginAttempts types.Int64  `tfsdk:"max_failed_login_attempts"`
	SelfUnlockAfterMinutes types.Int64  `tfsdk:"self_unlock_after_minutes"`
}

func (r *passwordPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_password_policy"
}

func (r *passwordPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the password policy settings on the XSOAR instance. " +
			"This is a singleton resource; only one instance should exist.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The identifier of the password policy (always 'password_policy').",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the password policy is enabled.",
				Optional:    true,
				Computed:    true,
			},
			"min_password_length": schema.Int64Attribute{
				Description: "Minimum password length.",
				Optional:    true,
				Computed:    true,
			},
			"min_lowercase_chars": schema.Int64Attribute{
				Description: "Minimum number of lowercase characters.",
				Optional:    true,
				Computed:    true,
			},
			"min_uppercase_chars": schema.Int64Attribute{
				Description: "Minimum number of uppercase characters.",
				Optional:    true,
				Computed:    true,
			},
			"min_digits_or_symbols": schema.Int64Attribute{
				Description: "Minimum number of digits or special characters.",
				Optional:    true,
				Computed:    true,
			},
			"prevent_repetition": schema.BoolAttribute{
				Description: "Whether to prevent password reuse.",
				Optional:    true,
				Computed:    true,
			},
			"expire_after": schema.Int64Attribute{
				Description: "Number of months before a password expires (0 = no expiration).",
				Optional:    true,
				Computed:    true,
			},
			"max_failed_login_attempts": schema.Int64Attribute{
				Description: "Maximum number of failed login attempts before lockout (0 = no limit).",
				Optional:    true,
				Computed:    true,
			},
			"self_unlock_after_minutes": schema.Int64Attribute{
				Description: "Minutes after which a locked account automatically unlocks (0 = manual unlock only).",
				Optional:    true,
				Computed:    true,
			},
		},
	}
}

func (r *passwordPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *passwordPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan passwordPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyPayload := r.buildPolicyPayload(&plan)

	_, err := r.backend.UpdatePasswordPolicy(policyPayload)
	if err != nil {
		resp.Diagnostics.AddError("Error Creating Password Policy", fmt.Sprintf("Could not set password policy: %s", err))
		return
	}

	if err := r.readPolicyIntoModel(&plan); err != nil {
		resp.Diagnostics.AddError("Error Reading Password Policy", fmt.Sprintf("Could not read password policy: %s", err))
		return
	}

	plan.ID = types.StringValue("password_policy")

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *passwordPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state passwordPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.readPolicyIntoModel(&state); err != nil {
		resp.Diagnostics.AddError("Error Reading Password Policy", fmt.Sprintf("Could not read password policy: %s", err))
		return
	}

	state.ID = types.StringValue("password_policy")

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *passwordPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan passwordPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyPayload := r.buildPolicyPayload(&plan)

	_, err := r.backend.UpdatePasswordPolicy(policyPayload)
	if err != nil {
		resp.Diagnostics.AddError("Error Updating Password Policy", fmt.Sprintf("Could not update password policy: %s", err))
		return
	}

	if err := r.readPolicyIntoModel(&plan); err != nil {
		resp.Diagnostics.AddError("Error Reading Password Policy", fmt.Sprintf("Could not read password policy: %s", err))
		return
	}

	plan.ID = types.StringValue("password_policy")

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *passwordPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	defaults := map[string]interface{}{
		"enabled":                false,
		"minPasswordLength":      0,
		"minLowercaseChars":      0,
		"minUppercaseChars":      0,
		"minDigitsOrSymbols":     0,
		"preventRepetition":      false,
		"expireAfter":            0,
		"expireUnit":             "month",
		"maxFailedLoginAttempts": 0,
		"selfUnlockAfterMinutes": 0,
	}

	_, err := r.backend.UpdatePasswordPolicy(defaults)
	if err != nil {
		resp.Diagnostics.AddError("Error Resetting Password Policy", fmt.Sprintf("Could not reset password policy to defaults: %s", err))
		return
	}
}

func (r *passwordPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), "password_policy")...)
}

func (r *passwordPolicyResource) buildPolicyPayload(model *passwordPolicyResourceModel) map[string]interface{} {
	payload := map[string]interface{}{}

	if !model.Enabled.IsNull() && !model.Enabled.IsUnknown() {
		payload["enabled"] = model.Enabled.ValueBool()
	}
	if !model.MinPasswordLength.IsNull() && !model.MinPasswordLength.IsUnknown() {
		payload["minPasswordLength"] = model.MinPasswordLength.ValueInt64()
	}
	if !model.MinLowercaseChars.IsNull() && !model.MinLowercaseChars.IsUnknown() {
		payload["minLowercaseChars"] = model.MinLowercaseChars.ValueInt64()
	}
	if !model.MinUppercaseChars.IsNull() && !model.MinUppercaseChars.IsUnknown() {
		payload["minUppercaseChars"] = model.MinUppercaseChars.ValueInt64()
	}
	if !model.MinDigitsOrSymbols.IsNull() && !model.MinDigitsOrSymbols.IsUnknown() {
		payload["minDigitsOrSymbols"] = model.MinDigitsOrSymbols.ValueInt64()
	}
	if !model.PreventRepetition.IsNull() && !model.PreventRepetition.IsUnknown() {
		payload["preventRepetition"] = model.PreventRepetition.ValueBool()
	}
	if !model.ExpireAfter.IsNull() && !model.ExpireAfter.IsUnknown() {
		payload["expireAfter"] = model.ExpireAfter.ValueInt64()
		// V8 requires expireUnit when expireAfter is set
		payload["expireUnit"] = "month"
	}
	if !model.MaxFailedLoginAttempts.IsNull() && !model.MaxFailedLoginAttempts.IsUnknown() {
		payload["maxFailedLoginAttempts"] = model.MaxFailedLoginAttempts.ValueInt64()
	}
	if !model.SelfUnlockAfterMinutes.IsNull() && !model.SelfUnlockAfterMinutes.IsUnknown() {
		payload["selfUnlockAfterMinutes"] = model.SelfUnlockAfterMinutes.ValueInt64()
	}

	return payload
}

func (r *passwordPolicyResource) readPolicyIntoModel(model *passwordPolicyResourceModel) error {
	policy, err := r.backend.GetPasswordPolicy()
	if err != nil {
		return err
	}

	model.Enabled = types.BoolValue(policy.Enabled)
	model.MinPasswordLength = types.Int64Value(int64(policy.MinPasswordLength))
	model.MinLowercaseChars = types.Int64Value(int64(policy.MinLowercaseChars))
	model.MinUppercaseChars = types.Int64Value(int64(policy.MinUppercaseChars))
	model.MinDigitsOrSymbols = types.Int64Value(int64(policy.MinDigitsOrSymbols))
	model.PreventRepetition = types.BoolValue(policy.PreventRepetition)
	model.ExpireAfter = types.Int64Value(int64(policy.ExpireAfter))
	model.MaxFailedLoginAttempts = types.Int64Value(int64(policy.MaxFailedLoginAttempts))
	model.SelfUnlockAfterMinutes = types.Int64Value(int64(policy.SelfUnlockAfterMinutes))

	return nil
}

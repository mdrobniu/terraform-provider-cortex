package resources

import (
	"context"
	"fmt"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/providerdata"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource = &securitySettingsResource{}
)

func NewSecuritySettingsResource() resource.Resource {
	return &securitySettingsResource{}
}

type securitySettingsResource struct {
	backend api.XSOARBackend
}

type securitySettingsResourceModel struct {
	ID                     types.String `tfsdk:"id"`
	UserLoginExpiration    types.Int64  `tfsdk:"user_login_expiration"`
	AutoLogoutEnabled      types.Bool   `tfsdk:"auto_logout_enabled"`
	AutoLogoutTime         types.Int64  `tfsdk:"auto_logout_time"`
	DashboardExpiration    types.Int64  `tfsdk:"dashboard_expiration"`
	ApprovedIPRanges       types.List   `tfsdk:"approved_ip_ranges"`
	ApprovedDomains        types.List   `tfsdk:"approved_domains"`
	TimeToInactiveUsers    types.Int64  `tfsdk:"time_to_inactive_users"`
	InactiveUsersIsEnable  types.Bool   `tfsdk:"inactive_users_is_enable"`
	ApprovedMailingDomains types.List   `tfsdk:"approved_mailing_domains"`
	ExternalIPMonitoring   types.Bool   `tfsdk:"external_ip_monitoring"`
	LimitAPIAccess         types.Bool   `tfsdk:"limit_api_access"`
}

func (r *securitySettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_security_settings"
}

func (r *securitySettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages security and authentication settings on XSOAR 8 OPP. " +
			"This is a singleton resource. " +
			"Requires session auth (ui_url, username, password in provider config).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Resource identifier (always \"security_settings\").",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"user_login_expiration": schema.Int64Attribute{
				Description: "Session expiration time in minutes. Default: 60.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(60),
			},
			"auto_logout_enabled": schema.BoolAttribute{
				Description: "Whether auto-logout on idle is enabled. Default: false.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"auto_logout_time": schema.Int64Attribute{
				Description: "Auto-logout idle time in minutes. Default: 30.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(30),
			},
			"dashboard_expiration": schema.Int64Attribute{
				Description: "Dashboard session expiration in minutes. Default: 10080 (7 days).",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(10080),
			},
			"approved_ip_ranges": schema.ListAttribute{
				Description: "List of approved IP CIDR ranges for access control.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"approved_domains": schema.ListAttribute{
				Description: "List of approved domains for access control.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"time_to_inactive_users": schema.Int64Attribute{
				Description: "Time in minutes before marking users as inactive. Default: 43200 (30 days).",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(43200),
			},
			"inactive_users_is_enable": schema.BoolAttribute{
				Description: "Whether inactive user detection is enabled. Default: false.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"approved_mailing_domains": schema.ListAttribute{
				Description: "List of approved email domains for user registration.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"external_ip_monitoring": schema.BoolAttribute{
				Description: "Whether external IP monitoring is enabled. Default: true.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"limit_api_access": schema.BoolAttribute{
				Description: "Whether to limit API access to approved IP ranges. Default: false.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
		},
	}
}

func (r *securitySettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *securitySettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan securitySettingsResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := r.buildPayload(ctx, &plan)

	settings, err := r.backend.UpdateSecuritySettings(payload)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Security Settings",
			fmt.Sprintf("Could not update security settings: %s", err),
		)
		return
	}

	r.populateModel(ctx, &plan, settings)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *securitySettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state securitySettingsResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	settings, err := r.backend.GetSecuritySettings()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Security Settings",
			fmt.Sprintf("Could not read security settings: %s", err),
		)
		return
	}

	r.populateModel(ctx, &state, settings)

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *securitySettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan securitySettingsResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := r.buildPayload(ctx, &plan)

	settings, err := r.backend.UpdateSecuritySettings(payload)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Security Settings",
			fmt.Sprintf("Could not update security settings: %s", err),
		)
		return
	}

	r.populateModel(ctx, &plan, settings)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *securitySettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Singleton resource: on delete, reset to defaults
	defaults := map[string]interface{}{
		"user_login_expiration":    60,
		"auto_logout_enabled":      false,
		"auto_logout_time":         30,
		"dashboard_expiration":     10080,
		"approved_ip_ranges":       []string{},
		"approved_domains":         []string{},
		"time_to_inactive_users":   43200,
		"inactive_users_is_enable": false,
		"approved_mailing_domains": []string{},
		"external_ip_monitoring":   true,
		"limit_api_access":         false,
	}
	_, err := r.backend.UpdateSecuritySettings(defaults)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Resetting Security Settings",
			fmt.Sprintf("Could not reset security settings to defaults: %s", err),
		)
		return
	}
}

func (r *securitySettingsResource) buildPayload(ctx context.Context, model *securitySettingsResourceModel) map[string]interface{} {
	payload := map[string]interface{}{
		"user_login_expiration":    model.UserLoginExpiration.ValueInt64(),
		"auto_logout_enabled":      model.AutoLogoutEnabled.ValueBool(),
		"auto_logout_time":         model.AutoLogoutTime.ValueInt64(),
		"dashboard_expiration":     model.DashboardExpiration.ValueInt64(),
		"time_to_inactive_users":   model.TimeToInactiveUsers.ValueInt64(),
		"inactive_users_is_enable": model.InactiveUsersIsEnable.ValueBool(),
		"external_ip_monitoring":   model.ExternalIPMonitoring.ValueBool(),
		"limit_api_access":         model.LimitAPIAccess.ValueBool(),
	}

	// Convert list attributes (always send empty arrays, never null)
	ipRanges := []string{}
	if !model.ApprovedIPRanges.IsNull() && !model.ApprovedIPRanges.IsUnknown() {
		model.ApprovedIPRanges.ElementsAs(ctx, &ipRanges, false)
	}
	payload["approved_ip_ranges"] = ipRanges

	domains := []string{}
	if !model.ApprovedDomains.IsNull() && !model.ApprovedDomains.IsUnknown() {
		model.ApprovedDomains.ElementsAs(ctx, &domains, false)
	}
	payload["approved_domains"] = domains

	mailingDomains := []string{}
	if !model.ApprovedMailingDomains.IsNull() && !model.ApprovedMailingDomains.IsUnknown() {
		model.ApprovedMailingDomains.ElementsAs(ctx, &mailingDomains, false)
	}
	payload["approved_mailing_domains"] = mailingDomains

	return payload
}

func (r *securitySettingsResource) populateModel(ctx context.Context, model *securitySettingsResourceModel, settings *api.SecuritySettings) {
	model.ID = types.StringValue("security_settings")
	model.UserLoginExpiration = types.Int64Value(settings.UserLoginExpiration)
	model.AutoLogoutEnabled = types.BoolValue(settings.AutoLogoutEnabled)
	model.AutoLogoutTime = types.Int64Value(settings.AutoLogoutTime)
	model.DashboardExpiration = types.Int64Value(settings.DashboardExpiration)
	model.TimeToInactiveUsers = types.Int64Value(settings.TimeToInactiveUsers)
	model.InactiveUsersIsEnable = types.BoolValue(settings.InactiveUsersIsEnable)
	model.ExternalIPMonitoring = types.BoolValue(settings.ExternalIPMonitoring)
	model.LimitAPIAccess = types.BoolValue(settings.LimitAPIAccess)

	// Ensure nil slices from API are treated as empty
	if settings.ApprovedIPRanges == nil {
		settings.ApprovedIPRanges = []string{}
	}
	if settings.ApprovedDomains == nil {
		settings.ApprovedDomains = []string{}
	}
	if settings.ApprovedMailingDomains == nil {
		settings.ApprovedMailingDomains = []string{}
	}

	ipRanges, _ := types.ListValueFrom(ctx, types.StringType, settings.ApprovedIPRanges)
	model.ApprovedIPRanges = ipRanges

	domains, _ := types.ListValueFrom(ctx, types.StringType, settings.ApprovedDomains)
	model.ApprovedDomains = domains

	mailingDomains, _ := types.ListValueFrom(ctx, types.StringType, settings.ApprovedMailingDomains)
	model.ApprovedMailingDomains = mailingDomains
}

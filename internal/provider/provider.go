package provider

import (
	"context"
	"os"

	"terraform-provider-cortex/internal/api"
	v6 "terraform-provider-cortex/internal/api/v6"
	v8 "terraform-provider-cortex/internal/api/v8"
	"terraform-provider-cortex/internal/client"
	"terraform-provider-cortex/internal/providerdata"
	"terraform-provider-cortex/internal/resources"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ provider.Provider = &XSOARProvider{}

// XSOARProvider implements the Terraform provider for XSOAR.
type XSOARProvider struct {
	version string
}

type providerModel struct {
	BaseURL      types.String `tfsdk:"base_url"`
	APIKey       types.String `tfsdk:"api_key"`
	AuthID       types.String `tfsdk:"auth_id"`
	Insecure     types.Bool   `tfsdk:"insecure"`
	UIURL        types.String `tfsdk:"ui_url"`
	Username     types.String `tfsdk:"username"`
	Password     types.String `tfsdk:"password"`
	SessionToken types.String `tfsdk:"session_token"`
}

// New returns a factory function for the provider.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &XSOARProvider{version: version}
	}
}

func (p *XSOARProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "cortex"
	resp.Version = p.version
}

func (p *XSOARProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Terraform provider for Cortex XSOAR and XSIAM instance configuration management.",
		Attributes: map[string]schema.Attribute{
			"base_url": schema.StringAttribute{
				Description: "The base URL of the XSOAR instance (e.g., https://xsoar.example.com). " +
					"Can also be set via DEMISTO_BASE_URL environment variable.",
				Optional: true,
			},
			"api_key": schema.StringAttribute{
				Description: "API key for authentication. " +
					"Can also be set via DEMISTO_API_KEY environment variable.",
				Optional:  true,
				Sensitive: true,
			},
			"auth_id": schema.StringAttribute{
				Description: "Authentication ID for XSOAR 8 (x-xdr-auth-id header). " +
					"Can also be set via DEMISTO_AUTH_ID environment variable. " +
					"Not needed for XSOAR 6.",
				Optional: true,
			},
			"insecure": schema.BoolAttribute{
				Description: "Skip TLS certificate verification. " +
					"Can also be set via DEMISTO_INSECURE environment variable.",
				Optional: true,
			},
			"ui_url": schema.StringAttribute{
				Description: "The UI URL for XSOAR 8 OPP session auth (e.g., https://xsoar8.example.com). " +
					"Required for managing external storage and backup schedules. " +
					"Can also be set via XSOAR_UI_URL environment variable.",
				Optional: true,
			},
			"username": schema.StringAttribute{
				Description: "Username for XSOAR 8 OPP session auth. " +
					"Required together with password for managing external storage and backup schedules. " +
					"Can also be set via XSOAR_USERNAME environment variable.",
				Optional: true,
			},
			"password": schema.StringAttribute{
				Description: "Password for XSOAR 8 OPP session auth. " +
					"Required together with username for managing external storage and backup schedules. " +
					"Can also be set via XSOAR_PASSWORD environment variable.",
				Optional:  true,
				Sensitive: true,
			},
			"session_token": schema.StringAttribute{
				Description: "Session token for webapp API access on XSIAM or XSOAR 8 SaaS. " +
					"Obtain by logging into the UI, then copying the session cookie value from browser DevTools. " +
					"Required for correlation rules, datasets, and other webapp-managed resources. " +
					"Can also be set via CORTEX_SESSION_TOKEN environment variable.",
				Optional:  true,
				Sensitive: true,
			},
		},
	}
}

func (p *XSOARProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Resolve base_url
	baseURL := os.Getenv("DEMISTO_BASE_URL")
	if !config.BaseURL.IsNull() && !config.BaseURL.IsUnknown() {
		baseURL = config.BaseURL.ValueString()
	}
	if baseURL == "" {
		resp.Diagnostics.AddError(
			"Missing XSOAR Base URL",
			"The provider requires base_url to be set in the provider configuration or via DEMISTO_BASE_URL environment variable.",
		)
		return
	}

	// Resolve api_key
	apiKey := os.Getenv("DEMISTO_API_KEY")
	if !config.APIKey.IsNull() && !config.APIKey.IsUnknown() {
		apiKey = config.APIKey.ValueString()
	}
	if apiKey == "" {
		resp.Diagnostics.AddError(
			"Missing XSOAR API Key",
			"The provider requires api_key to be set in the provider configuration or via DEMISTO_API_KEY environment variable.",
		)
		return
	}

	// Resolve auth_id (XSOAR 8)
	authID := os.Getenv("DEMISTO_AUTH_ID")
	if !config.AuthID.IsNull() && !config.AuthID.IsUnknown() {
		authID = config.AuthID.ValueString()
	}

	// Resolve insecure
	insecure := os.Getenv("DEMISTO_INSECURE") != ""
	if !config.Insecure.IsNull() && !config.Insecure.IsUnknown() {
		insecure = config.Insecure.ValueBool()
	}

	// Create HTTP client
	c, err := client.NewClient(baseURL, apiKey, insecure)
	if err != nil {
		resp.Diagnostics.AddError("Client Creation Failed", err.Error())
		return
	}
	c.AuthID = authID

	// Detect XSOAR version, deployment mode, and product mode
	majorVer, versionStr, deploymentMode, productMode, err := c.DetectVersion(ctx)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Version Detection Failed",
			"Could not detect XSOAR version via /about endpoint. Defaulting to XSOAR 6. Error: "+err.Error(),
		)
		majorVer = 6
	}
	tflog.Info(ctx, "XSOAR version detected", map[string]interface{}{
		"version":        versionStr,
		"major":          majorVer,
		"deploymentMode": deploymentMode,
		"productMode":    productMode,
	})

	// XSIAM uses V8 backend with SaaS deployment mode
	if productMode == "xsiam" && majorVer < 8 {
		majorVer = 8
	}

	// Select backend based on version
	var backend api.XSOARBackend
	switch majorVer {
	case 8:
		v8Backend := v8.NewBackend(c, deploymentMode, productMode)

		// Resolve UI URL (used for both OPP login and session token auth)
		uiURL := os.Getenv("XSOAR_UI_URL")
		if !config.UIURL.IsNull() && !config.UIURL.IsUnknown() {
			uiURL = config.UIURL.ValueString()
		}

		// Set up webapp client for OPP session auth if credentials provided
		if deploymentMode == "opp" && productMode != "xsiam" {
			username := os.Getenv("XSOAR_USERNAME")
			if !config.Username.IsNull() && !config.Username.IsUnknown() {
				username = config.Username.ValueString()
			}

			password := os.Getenv("XSOAR_PASSWORD")
			if !config.Password.IsNull() && !config.Password.IsUnknown() {
				password = config.Password.ValueString()
			}

			if username != "" && password != "" {
				if uiURL == "" {
					uiURL = baseURL // Default to base_url if ui_url not set
				}
				wc, err := client.NewWebappClient(ctx, uiURL, username, password, insecure)
				if err != nil {
					resp.Diagnostics.AddWarning(
						"Webapp Session Auth Failed",
						"Could not establish session auth for OPP webapp API. "+
							"External storage and backup schedule resources will not be available. "+
							"Error: "+err.Error(),
					)
				} else {
					v8Backend.SetWebappClient(wc)
					tflog.Info(ctx, "Webapp session auth established", map[string]interface{}{
						"ui_url": uiURL,
					})
				}
			}
		}

		// Set up webapp client from session token (for XSIAM or SaaS)
		sessionToken := os.Getenv("CORTEX_SESSION_TOKEN")
		if !config.SessionToken.IsNull() && !config.SessionToken.IsUnknown() {
			sessionToken = config.SessionToken.ValueString()
		}
		if sessionToken != "" && v8Backend.WebappClient == nil {
			if uiURL == "" {
				uiURL = baseURL
			}
			wc, err := client.NewWebappClientFromToken(uiURL, sessionToken, insecure)
			if err != nil {
				resp.Diagnostics.AddWarning(
					"Session Token Auth Failed",
					"Could not create webapp client from session token. "+
						"Webapp-managed resources will not be available. "+
						"Error: "+err.Error(),
				)
			} else {
				v8Backend.SetWebappClient(wc)
				tflog.Info(ctx, "Webapp session token auth established", map[string]interface{}{
					"ui_url": uiURL,
				})
			}
		}

		backend = v8Backend
	default:
		backend = v6.NewBackend(c)
	}

	providerData := &providerdata.ProviderData{
		Client:         c,
		Backend:        backend,
		DeploymentMode: deploymentMode,
		ProductMode:    productMode,
	}

	resp.DataSourceData = providerData
	resp.ResourceData = providerData
}

func (p *XSOARProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		resources.NewServerConfigResource,
		resources.NewMarketplacePackResource,
		resources.NewIntegrationInstanceResource,
		resources.NewRoleResource,
		resources.NewAPIKeyResource,
		resources.NewJobResource,
		resources.NewPreprocessingRuleResource,
		resources.NewPasswordPolicyResource,
		resources.NewHAGroupResource,
		resources.NewHostResource,
		resources.NewAccountResource,
		resources.NewCredentialResource,
		resources.NewExclusionListResource,
		resources.NewBackupConfigResource,
		resources.NewExternalStorageResource,
		resources.NewBackupScheduleResource,
		resources.NewSecuritySettingsResource,
		resources.NewListResource,
	}
}

func (p *XSOARProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		// Data sources will be added later
	}
}

package providerdata

import (
	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/client"
)

// ProviderData holds the configured client and backend for use by resources and data sources.
type ProviderData struct {
	Client         *client.Client
	Backend        api.XSOARBackend
	DeploymentMode string // "saas", "opp", or "" (V6)
}

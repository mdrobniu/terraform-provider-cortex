package v8

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/client"
)

// Backend implements api.XSOARBackend for XSOAR 8 and XSIAM.
// All API paths are prefixed with /xsoar/ for the XSOAR 8/XSIAM architecture.
type Backend struct {
	Client         *client.Client
	WebappClient   *client.WebappClient // optional, for /api/webapp/ endpoints (session auth)
	Ctx            context.Context
	prefix         string // "/xsoar"
	deploymentMode string // "saas", "opp", or ""
	productMode    string // "xsoar", "xsiam", or ""
}

// NewBackend creates a new V8 backend.
func NewBackend(c *client.Client, deploymentMode, productMode string) *Backend {
	return &Backend{
		Client:         c,
		Ctx:            context.Background(),
		prefix:         "/xsoar",
		deploymentMode: deploymentMode,
		productMode:    productMode,
	}
}

// SetWebappClient attaches a webapp client for session-authenticated OPP endpoints.
func (b *Backend) SetWebappClient(wc *client.WebappClient) {
	b.WebappClient = wc
}

// isSaaS returns true if this is a SaaS deployment.
func (b *Backend) isSaaS() bool {
	return b.deploymentMode == "saas"
}

// isXSIAM returns true if this is an XSIAM instance.
func (b *Backend) isXSIAM() bool {
	return b.productMode == "xsiam"
}

// modeLabel returns a human-readable deployment mode label for error messages.
func (b *Backend) modeLabel() string {
	if b.isXSIAM() {
		return "XSIAM"
	}
	if b.isSaaS() {
		return "XSOAR 8 SaaS"
	}
	return "XSOAR 8 OPP"
}

// Ensure Backend implements XSOARBackend at compile time.
var _ api.XSOARBackend = &Backend{}

// p prepends the /xsoar prefix to an API path.
func (b *Backend) p(path string) string {
	return b.prefix + path
}

// --- Server ---

func (b *Backend) GetServerInfo() (*api.ServerInfo, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", b.p("/about"), nil)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing /about: %w", err)
	}
	info := &api.ServerInfo{
		Version:        getString(resp, "demistoVersion"),
		BuildNum:       getString(resp, "buildNum"),
		MajorVer:       8,
		DeploymentMode: b.deploymentMode,
		ProductMode:    b.productMode,
	}
	return info, nil
}

func (b *Backend) GetServerConfig() (map[string]interface{}, int, error) {
	if b.isXSIAM() {
		return nil, 0, fmt.Errorf("system/config is blocked on %s; this endpoint is not available for public API requests", b.modeLabel())
	}
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", b.p("/system/config"), nil)
	if err != nil {
		return nil, 0, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, fmt.Errorf("parsing /system/config: %w", err)
	}
	sysConf, _ := resp["sysConf"].(map[string]interface{})
	version := 0
	if v, ok := sysConf["versn"].(float64); ok {
		version = int(v)
	}
	return sysConf, version, nil
}

func (b *Backend) UpdateServerConfig(config map[string]string, version int) error {
	if b.isXSIAM() {
		return fmt.Errorf("system/config is blocked on %s; this endpoint is not available for public API requests", b.modeLabel())
	}
	payload := map[string]interface{}{
		"data":    config,
		"version": version,
	}
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/system/config"), payload)
	return err
}

// --- Marketplace ---

func (b *Backend) ListInstalledPacks() ([]api.Pack, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", b.p("/contentpacks/metadata/installed"), nil)
	if err != nil {
		return nil, err
	}
	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing installed packs: %w", err)
	}
	var packs []api.Pack
	for _, p := range raw {
		packs = append(packs, api.Pack{
			ID:             getString(p, "id"),
			Name:           getString(p, "name"),
			CurrentVersion: getString(p, "currentVersion"),
		})
	}
	return packs, nil
}

func (b *Backend) SearchMarketplacePacks(query string) ([]api.MarketplacePackInfo, error) {
	payload := map[string]interface{}{
		"page": 0,
		"size": 500,
	}
	if query != "" {
		payload["query"] = query
	}
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/contentpacks/marketplace/search"), payload)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing marketplace search: %w", err)
	}
	packsRaw, _ := resp["packs"].([]interface{})
	var packs []api.MarketplacePackInfo
	for _, p := range packsRaw {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		packs = append(packs, api.MarketplacePackInfo{
			ID:             getString(pm, "id"),
			Name:           getString(pm, "name"),
			CurrentVersion: getString(pm, "currentVersion"),
			Description:    getString(pm, "description"),
		})
	}
	return packs, nil
}

func (b *Backend) InstallPacks(packs []api.Pack) error {
	var installList []map[string]string
	for _, p := range packs {
		installList = append(installList, map[string]string{
			"id":      p.ID,
			"version": p.CurrentVersion,
		})
	}
	payload := map[string]interface{}{
		"packs": installList,
	}
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/contentpacks/marketplace/install"), payload)
	return err
}

func (b *Backend) UninstallPack(id string) error {
	payload := map[string]interface{}{
		"IDs": []string{id},
	}
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/contentpacks/installed/delete"), payload)
	return err
}

// --- Integration Instances ---

func (b *Backend) ListIntegrationConfigs() ([]api.IntegrationConfig, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/settings/integration/search"), map[string]interface{}{
		"size": 500,
	})
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing integration search: %w", err)
	}
	configsRaw, _ := resp["configurations"].([]interface{})
	var configs []api.IntegrationConfig
	for _, c := range configsRaw {
		cm, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		config := api.IntegrationConfig{
			ID:       getString(cm, "id"),
			Name:     getString(cm, "name"),
			Display:  getString(cm, "display"),
			Category: getString(cm, "category"),
		}
		paramsRaw, _ := cm["configuration"].([]interface{})
		for _, p := range paramsRaw {
			pm, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			paramType := 0
			if t, ok := pm["type"].(float64); ok {
				paramType = int(t)
			}
			param := api.IntegrationParam{
				Name:         getString(pm, "name"),
				Display:      getString(pm, "display"),
				DefaultValue: getString(pm, "defaultValue"),
				Type:         paramType,
				Required:     getBool(pm, "required"),
				Hidden:       getBool(pm, "hidden"),
			}
			if opts, ok := pm["options"].([]interface{}); ok {
				for _, o := range opts {
					if s, ok := o.(string); ok {
						param.Options = append(param.Options, s)
					}
				}
			}
			config.Configuration = append(config.Configuration, param)
		}
		configs = append(configs, config)
	}
	return configs, nil
}

func (b *Backend) SearchIntegrationInstances() ([]api.IntegrationInstance, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/settings/integration/search"), map[string]interface{}{
		"size": 500,
	})
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing integration instances: %w", err)
	}
	instancesRaw, _ := resp["instances"].([]interface{})
	var instances []api.IntegrationInstance
	for _, inst := range instancesRaw {
		im, ok := inst.(map[string]interface{})
		if !ok {
			continue
		}
		instance := parseIntegrationInstance(im)
		instances = append(instances, instance)
	}
	return instances, nil
}

func (b *Backend) GetIntegrationInstance(name string) (*api.IntegrationInstance, error) {
	instances, err := b.SearchIntegrationInstances()
	if err != nil {
		return nil, err
	}
	for _, inst := range instances {
		if inst.Name == name {
			return &inst, nil
		}
	}
	return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("integration instance %q not found", name)}
}

func (b *Backend) CreateIntegrationInstance(instance map[string]interface{}) (*api.IntegrationInstance, error) {
	instance["version"] = -1
	body, _, err := b.Client.DoRequest(b.Ctx, "PUT", b.p("/settings/integration"), instance)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing create response: %w", err)
	}
	result := parseIntegrationInstance(resp)
	return &result, nil
}

func (b *Backend) UpdateIntegrationInstance(instance map[string]interface{}) (*api.IntegrationInstance, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "PUT", b.p("/settings/integration"), instance)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing update response: %w", err)
	}
	result := parseIntegrationInstance(resp)
	return &result, nil
}

func (b *Backend) DeleteIntegrationInstance(id string) error {
	payload := map[string]interface{}{
		"id": id,
	}
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/settings/integration/delete"), payload)
	return err
}

// --- Roles ---
// XSOAR 8 OPP: roles are managed at the XDR platform level.
// Read works, but create/delete return errors.

func (b *Backend) ListRoles() ([]api.Role, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", b.p("/roles"), nil)
	if err != nil {
		return nil, err
	}
	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing roles: %w", err)
	}
	var roles []api.Role
	for _, r := range raw {
		role := api.Role{
			ID:   getString(r, "id"),
			Name: getString(r, "name"),
		}
		if v, ok := r["version"].(float64); ok {
			role.Version = int(v)
		}
		if perms, ok := r["permissions"].(map[string]interface{}); ok {
			role.Permissions = make(map[string][]string)
			for k, v := range perms {
				if arr, ok := v.([]interface{}); ok {
					var vals []string
					for _, a := range arr {
						if s, ok := a.(string); ok {
							vals = append(vals, s)
						}
					}
					role.Permissions[k] = vals
				}
			}
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func (b *Backend) CreateRole(role map[string]interface{}) (*api.Role, error) {
	return nil, fmt.Errorf("role creation is not supported on XSOAR 8; roles are managed at the XDR platform level")
}

func (b *Backend) DeleteRole(id string) error {
	return fmt.Errorf("role deletion is not supported on XSOAR 8; roles are managed at the XDR platform level")
}

// --- API Keys ---

func (b *Backend) ListAPIKeys() ([]api.APIKeyInfo, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", b.p("/apikeys"), nil)
	if err != nil {
		return nil, err
	}
	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing api keys: %w", err)
	}
	var keys []api.APIKeyInfo
	for _, k := range raw {
		keys = append(keys, api.APIKeyInfo{
			ID:       getString(k, "id"),
			Name:     getString(k, "name"),
			UserName: getString(k, "userName"),
		})
	}
	return keys, nil
}

func (b *Backend) CreateAPIKey(name string) (*api.APIKeyInfo, error) {
	if b.isSaaS() {
		return nil, fmt.Errorf("API key creation is not supported on %s; manage API keys via the Cortex Hub", b.modeLabel())
	}
	payload := map[string]interface{}{
		"name": name,
	}
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/apikeys"), payload)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing api key response: %w", err)
	}
	return &api.APIKeyInfo{
		ID:   getString(resp, "id"),
		Name: getString(resp, "name"),
		Key:  getString(resp, "key"),
	}, nil
}

func (b *Backend) DeleteAPIKey(id string) error {
	if b.isSaaS() {
		return fmt.Errorf("API key deletion is not supported on %s; manage API keys via the Cortex Hub", b.modeLabel())
	}
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/apikeys/revoke"), map[string]interface{}{
		"id": id,
	})
	return err
}

// --- Jobs ---

func (b *Backend) SearchJobs() ([]api.Job, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/jobs/search"), map[string]interface{}{
		"page": 0,
		"size": 500,
	})
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing jobs: %w", err)
	}
	jobsRaw, _ := resp["data"].([]interface{})
	var jobs []api.Job
	for _, j := range jobsRaw {
		jm, ok := j.(map[string]interface{})
		if !ok {
			continue
		}
		job := api.Job{
			ID:               getString(jm, "id"),
			Name:             getString(jm, "name"),
			PlaybookID:       getString(jm, "playbookId"),
			Type:             getString(jm, "type"),
			Scheduled:        getBool(jm, "scheduled"),
			Cron:             getString(jm, "cron"),
			Recurrent:        getBool(jm, "recurrent"),
			ShouldTriggerNew: getBool(jm, "shouldTriggerNew"),
			StartDate:        getString(jm, "startDate"),
			EndingDate:       getString(jm, "endingDate"),
			EndingType:       getString(jm, "endingType"),
		}
		if v, ok := jm["version"].(float64); ok {
			job.Version = int(v)
		}
		if tags, ok := jm["tags"].([]interface{}); ok {
			for _, t := range tags {
				if s, ok := t.(string); ok {
					job.Tags = append(job.Tags, s)
				}
			}
		}
		if hc, ok := jm["humanCron"].(map[string]interface{}); ok && len(hc) > 0 {
			job.HumanCron = hc
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (b *Backend) CreateJob(job map[string]interface{}) (*api.Job, error) {
	// XSOAR 8 requires a non-empty type field
	if t, ok := job["type"].(string); !ok || t == "" {
		job["type"] = "Unclassified"
	}
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/jobs"), job)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing job response: %w", err)
	}
	return &api.Job{
		ID:   getString(resp, "id"),
		Name: getString(resp, "name"),
	}, nil
}

func (b *Backend) UpdateJob(job map[string]interface{}) (*api.Job, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/jobs"), job)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing job update response: %w", err)
	}
	return &api.Job{
		ID:   getString(resp, "id"),
		Name: getString(resp, "name"),
	}, nil
}

func (b *Backend) DeleteJob(id string) error {
	_, _, err := b.Client.DoRequest(b.Ctx, "DELETE", b.p("/jobs/"+id), nil)
	return err
}

// --- Preprocessing Rules ---

func (b *Backend) GetPreprocessingRules() ([]api.PreprocessingRule, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", b.p("/preprocess/rules"), nil)
	if err != nil {
		return nil, err
	}
	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing preprocessing rules: %w", err)
	}
	var rules []api.PreprocessingRule
	for _, r := range raw {
		rule := api.PreprocessingRule{
			ID:         getString(r, "id"),
			Name:       getString(r, "name"),
			Enabled:    getBool(r, "enabled"),
			Action:     getString(r, "action"),
			ScriptName: getString(r, "scriptName"),
		}
		if v, ok := r["version"].(float64); ok {
			rule.Version = int(v)
		}
		rule.NewEventFilters = r["newEventFilters"]
		rule.ExistingEventsFilters = r["existingEventsFilters"]
		rule.LinkTo = getString(r, "linkTo")
		rules = append(rules, rule)
	}
	return rules, nil
}

func (b *Backend) CreatePreprocessingRule(rule map[string]interface{}) (*api.PreprocessingRule, error) {
	if b.isSaaS() {
		return nil, fmt.Errorf("preprocessing rule creation is not supported on %s", b.modeLabel())
	}
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/preprocess/rules"), rule)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing preprocessing rule response: %w", err)
	}
	return &api.PreprocessingRule{
		ID:   getString(resp, "id"),
		Name: getString(resp, "name"),
	}, nil
}

func (b *Backend) UpdatePreprocessingRule(rule map[string]interface{}) (*api.PreprocessingRule, error) {
	if b.isSaaS() {
		return nil, fmt.Errorf("preprocessing rule update is not supported on %s", b.modeLabel())
	}
	body, _, err := b.Client.DoRequest(b.Ctx, "PUT", b.p("/preprocess/rules"), rule)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing preprocessing rule update response: %w", err)
	}
	return &api.PreprocessingRule{
		ID:   getString(resp, "id"),
		Name: getString(resp, "name"),
	}, nil
}

func (b *Backend) DeletePreprocessingRule(id string) error {
	if b.isSaaS() {
		return fmt.Errorf("preprocessing rule deletion is not supported on %s", b.modeLabel())
	}
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/preprocess/rules/delete"), map[string]interface{}{
		"id": id,
	})
	return err
}

// --- Password Policy ---

func (b *Backend) GetPasswordPolicy() (*api.PasswordPolicy, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", b.p("/settings/password-policy"), nil)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing password policy: %w", err)
	}
	policy := &api.PasswordPolicy{
		ID:      "password_policy",
		Enabled: getBool(resp, "enabled"),
	}
	if v, ok := resp["version"].(float64); ok {
		policy.Version = int(v)
	}
	if v, ok := resp["minPasswordLength"].(float64); ok {
		policy.MinPasswordLength = int(v)
	}
	if v, ok := resp["minLowercaseChars"].(float64); ok {
		policy.MinLowercaseChars = int(v)
	}
	if v, ok := resp["minUppercaseChars"].(float64); ok {
		policy.MinUppercaseChars = int(v)
	}
	if v, ok := resp["minDigitsOrSymbols"].(float64); ok {
		policy.MinDigitsOrSymbols = int(v)
	}
	policy.PreventRepetition = getBool(resp, "preventRepetition")
	if v, ok := resp["expireAfter"].(float64); ok {
		policy.ExpireAfter = int(v)
	}
	if v, ok := resp["maxFailedLoginAttempts"].(float64); ok {
		policy.MaxFailedLoginAttempts = int(v)
	}
	if v, ok := resp["selfUnlockAfterMinutes"].(float64); ok {
		policy.SelfUnlockAfterMinutes = int(v)
	}
	return policy, nil
}

func (b *Backend) UpdatePasswordPolicy(policy map[string]interface{}) (*api.PasswordPolicy, error) {
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/settings/password-policy"), policy)
	if err != nil {
		return nil, err
	}
	return b.GetPasswordPolicy()
}

// --- HA Groups ---
// Not available in XSOAR 8 (OPP or SaaS).

func (b *Backend) ListHAGroups() ([]api.HAGroup, error) {
	return nil, fmt.Errorf("HA groups are not available on %s", b.modeLabel())
}

func (b *Backend) GetHAGroup(id string) (*api.HAGroup, error) {
	return nil, fmt.Errorf("HA groups are not available on %s", b.modeLabel())
}

func (b *Backend) CreateHAGroup(group map[string]interface{}) (*api.HAGroup, error) {
	return nil, fmt.Errorf("HA groups are not available on %s", b.modeLabel())
}

func (b *Backend) DeleteHAGroup(id string) error {
	return fmt.Errorf("HA groups are not available on %s", b.modeLabel())
}

// --- Hosts ---
// Not available in XSOAR 8 (OPP or SaaS).

func (b *Backend) GetHost(name string) (*api.Host, error) {
	return nil, fmt.Errorf("host management is not available on %s", b.modeLabel())
}

func (b *Backend) DeleteHost(id string) error {
	return fmt.Errorf("host management is not available on %s", b.modeLabel())
}

// --- Accounts ---
// Not available in XSOAR 8 (OPP or SaaS); use XDR tenant management.

func (b *Backend) ListAccounts() ([]api.Account, error) {
	return nil, fmt.Errorf("account management is not available on %s; use XDR tenant management", b.modeLabel())
}

func (b *Backend) GetAccount(name string) (*api.Account, error) {
	return nil, fmt.Errorf("account management is not available on %s; use XDR tenant management", b.modeLabel())
}

func (b *Backend) CreateAccount(account map[string]interface{}) (*api.Account, error) {
	return nil, fmt.Errorf("account management is not available on %s; use XDR tenant management", b.modeLabel())
}

func (b *Backend) UpdateAccount(name string, update map[string]interface{}) error {
	return fmt.Errorf("account management is not available on %s; use XDR tenant management", b.modeLabel())
}

func (b *Backend) DeleteAccount(name string) error {
	return fmt.Errorf("account management is not available on %s; use XDR tenant management", b.modeLabel())
}

// --- Credentials ---

func (b *Backend) ListCredentials() ([]api.Credential, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/settings/credentials"), map[string]interface{}{
		"page": 0,
		"size": 500,
	})
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing credentials response: %w", err)
	}
	var raw []map[string]interface{}
	if creds, ok := resp["credentials"].([]interface{}); ok {
		for _, c := range creds {
			if cm, ok := c.(map[string]interface{}); ok {
				raw = append(raw, cm)
			}
		}
	}
	var creds []api.Credential
	for _, c := range raw {
		cred := api.Credential{
			ID:      getString(c, "id"),
			Name:    getString(c, "name"),
			User:    getString(c, "user"),
			Comment: getString(c, "comment"),
		}
		if v, ok := c["version"].(float64); ok {
			cred.Version = int(v)
		}
		creds = append(creds, cred)
	}
	return creds, nil
}

func (b *Backend) CreateCredential(cred map[string]interface{}) (*api.Credential, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "PUT", b.p("/settings/credentials"), cred)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing credential response: %w", err)
	}
	result := &api.Credential{
		ID:   getString(resp, "id"),
		Name: getString(resp, "name"),
		User: getString(resp, "user"),
	}
	if v, ok := resp["version"].(float64); ok {
		result.Version = int(v)
	}
	return result, nil
}

func (b *Backend) UpdateCredential(cred map[string]interface{}) (*api.Credential, error) {
	return b.CreateCredential(cred) // Same endpoint for create and update
}

func (b *Backend) DeleteCredential(id string) error {
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/settings/credentials/delete"), map[string]interface{}{
		"id": id,
	})
	return err
}

// --- Exclusion List (Whitelist) ---

func (b *Backend) GetExclusionList() ([]api.ExclusionEntry, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", b.p("/indicators/whitelisted"), nil)
	if err != nil {
		return nil, err
	}
	var rawEntries []map[string]interface{}
	if err := json.Unmarshal(body, &rawEntries); err != nil {
		return nil, fmt.Errorf("parsing exclusion list: %w", err)
	}
	var entries []api.ExclusionEntry
	for _, em := range rawEntries {
		entries = append(entries, api.ExclusionEntry{
			ID:      getString(em, "id"),
			Version: getInt(em, "version"),
			Value:   getString(em, "value"),
			Type:    getString(em, "type"),
			Reason:  getString(em, "reason"),
		})
	}
	return entries, nil
}

func (b *Backend) AddExclusion(entry map[string]interface{}) (*api.ExclusionEntry, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/indicators/whitelist/update"), entry)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing exclusion response: %w", err)
	}
	return &api.ExclusionEntry{
		ID:      getString(resp, "id"),
		Version: getInt(resp, "version"),
		Value:   getString(resp, "value"),
		Type:    getString(resp, "type"),
		Reason:  getString(resp, "reason"),
	}, nil
}

func (b *Backend) UpdateExclusion(entry map[string]interface{}) (*api.ExclusionEntry, error) {
	return b.AddExclusion(entry)
}

func (b *Backend) RemoveExclusion(id string) error {
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/indicators/whitelist/remove"), map[string]interface{}{
		"data": []string{id},
	})
	return err
}

// --- Backup Config ---
// Not available in XSOAR 8 (OPP or SaaS).

func (b *Backend) GetBackupConfig() (*api.BackupConfig, error) {
	return nil, fmt.Errorf("backup configuration is not available on %s", b.modeLabel())
}

func (b *Backend) UpdateBackupConfig(config map[string]interface{}) (*api.BackupConfig, error) {
	return nil, fmt.Errorf("backup configuration is not available on %s", b.modeLabel())
}

// --- External Storage ---
// Available on XSOAR 8 OPP only, requires session auth (webapp client).

func (b *Backend) requireWebapp(operation string) error {
	if b.isSaaS() && !b.isXSIAM() {
		// XSOAR 8 SaaS without session token
		if b.WebappClient == nil {
			return fmt.Errorf("%s is not available on %s without session_token", operation, b.modeLabel())
		}
	}
	if b.isXSIAM() && b.WebappClient == nil {
		return fmt.Errorf("%s requires session_token on %s; configure session_token in the provider", operation, b.modeLabel())
	}
	if !b.isSaaS() && !b.isXSIAM() && b.WebappClient == nil {
		return fmt.Errorf("%s requires session auth; configure ui_url, username, and password in the provider", operation)
	}
	return nil
}

// requireXSIAMWebapp checks that this is an XSIAM instance and has webapp auth.
// Used for XSIAM-only features like correlation rules and IOC rules.
func (b *Backend) requireXSIAMWebapp(operation string) error {
	if !b.isXSIAM() {
		return fmt.Errorf("%s is only available on XSIAM, not on %s", operation, b.modeLabel())
	}
	if b.WebappClient == nil {
		return fmt.Errorf("%s requires session_token on XSIAM; configure session_token in the provider or run cortex-login", operation)
	}
	return nil
}

func (b *Backend) ListExternalStorage() ([]api.ExternalStorage, error) {
	if err := b.requireWebapp("external storage management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "GET", "/api/webapp/external_storage/list", nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply []struct {
			StorageID         string                 `json:"storage_id"`
			Name              string                 `json:"name"`
			StorageType       string                 `json:"storage_type"`
			ConnectionDetails map[string]interface{} `json:"connection_details"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing external storage list: %w", err)
	}
	var storages []api.ExternalStorage
	for _, s := range resp.Reply {
		connDetails := make(map[string]string)
		for k, v := range s.ConnectionDetails {
			connDetails[k] = fmt.Sprintf("%v", v)
		}
		storages = append(storages, api.ExternalStorage{
			StorageID:         s.StorageID,
			Name:              s.Name,
			StorageType:       s.StorageType,
			ConnectionDetails: connDetails,
		})
	}
	return storages, nil
}

func (b *Backend) CreateExternalStorage(storage map[string]interface{}) (*api.ExternalStorage, error) {
	if err := b.requireWebapp("external storage creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST", "/api/webapp/external_storage/create", storage)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Success   bool   `json:"success"`
			StorageID string `json:"storage_id"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing external storage create response: %w", err)
	}
	if !resp.Reply.Success {
		return nil, fmt.Errorf("external storage creation failed: %s", string(body))
	}
	// Read back to get full details
	storages, err := b.ListExternalStorage()
	if err != nil {
		// Return partial result with the ID
		name, _ := storage["name"].(string)
		storageType, _ := storage["storage_type"].(string)
		return &api.ExternalStorage{
			StorageID:   resp.Reply.StorageID,
			Name:        name,
			StorageType: storageType,
		}, nil
	}
	for _, s := range storages {
		if s.StorageID == resp.Reply.StorageID {
			return &s, nil
		}
	}
	return &api.ExternalStorage{StorageID: resp.Reply.StorageID}, nil
}

func (b *Backend) UpdateExternalStorage(storage map[string]interface{}) (*api.ExternalStorage, error) {
	if err := b.requireWebapp("external storage update"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST", "/api/webapp/external_storage/update", storage)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Success   bool   `json:"success"`
			StorageID string `json:"storage_id"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing external storage update response: %w", err)
	}
	if !resp.Reply.Success {
		return nil, fmt.Errorf("external storage update failed: %s", string(body))
	}
	// Read back to get full details
	storages, err := b.ListExternalStorage()
	if err != nil {
		return &api.ExternalStorage{StorageID: resp.Reply.StorageID}, nil
	}
	for _, s := range storages {
		if s.StorageID == resp.Reply.StorageID {
			return &s, nil
		}
	}
	return &api.ExternalStorage{StorageID: resp.Reply.StorageID}, nil
}

func (b *Backend) DeleteExternalStorage(storageID string) error {
	if err := b.requireWebapp("external storage deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST", "/api/webapp/external_storage/delete", map[string]interface{}{
		"storage_id": storageID,
	})
	return err
}

// --- Backup Schedule ---
// Available on XSOAR 8 OPP only, requires session auth (webapp client).

func (b *Backend) ListBackupSchedules() ([]api.BackupSchedule, error) {
	if err := b.requireWebapp("backup schedule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST", "/api/webapp/retention/schedule/list", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	// API response structure: {"reply": {"schedules": [{"schedule": {...}, "storage": {...}}]}}
	var resp struct {
		Reply struct {
			Schedules []struct {
				Schedule struct {
					ID              string                 `json:"id"`
					HumanCron       map[string]interface{} `json:"human_cron"`
					RetentionPeriod int                    `json:"retention_period"`
				} `json:"schedule"`
				Storage struct {
					ID           string `json:"id"`
					RelativePath string `json:"relative_path"`
				} `json:"storage"`
			} `json:"schedules"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing backup schedule list: %w", err)
	}
	var schedules []api.BackupSchedule
	for _, s := range resp.Reply.Schedules {
		schedules = append(schedules, api.BackupSchedule{
			ScheduleID:      s.Schedule.ID,
			StorageID:       s.Storage.ID,
			RetentionPeriod: s.Schedule.RetentionPeriod,
			RelativePath:    s.Storage.RelativePath,
			HumanCron:       s.Schedule.HumanCron,
		})
	}
	return schedules, nil
}

func (b *Backend) CreateBackupSchedule(schedule map[string]interface{}) (*api.BackupSchedule, error) {
	if err := b.requireWebapp("backup schedule creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST", "/api/webapp/retention/schedule/create", schedule)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Success    bool   `json:"success"`
			ScheduleID string `json:"schedule_id"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing backup schedule create response: %w", err)
	}
	if !resp.Reply.Success && resp.Reply.ScheduleID == "" {
		return nil, fmt.Errorf("backup schedule creation failed: %s", string(body))
	}
	// Read back to get full details
	schedules, err := b.ListBackupSchedules()
	if err != nil {
		return &api.BackupSchedule{ScheduleID: resp.Reply.ScheduleID}, nil
	}
	for _, s := range schedules {
		if s.ScheduleID == resp.Reply.ScheduleID {
			return &s, nil
		}
	}
	// If schedule_id not in reply, return the last created schedule
	if resp.Reply.ScheduleID == "" && len(schedules) > 0 {
		last := schedules[len(schedules)-1]
		return &last, nil
	}
	return &api.BackupSchedule{ScheduleID: resp.Reply.ScheduleID}, nil
}

func (b *Backend) DeleteBackupSchedule(scheduleID string) error {
	if err := b.requireWebapp("backup schedule deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST", "/api/webapp/retention/schedule/delete", map[string]interface{}{
		"schedule_id": scheduleID,
	})
	return err
}

// --- Security Settings ---
// Available on XSOAR 8 OPP only, requires session auth (webapp client).

func (b *Backend) GetSecuritySettings() (*api.SecuritySettings, error) {
	if err := b.requireWebapp("security settings"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST", "/api/webapp/user_settings/get_proxy_data", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			UserLoginExpiration    int64    `json:"user_login_expiration"`
			AutoLogoutEnabled      bool     `json:"auto_logout_enabled"`
			AutoLogoutTime         int64    `json:"auto_logout_time"`
			DashboardExpiration    int64    `json:"dashboard_expiration"`
			ApprovedIPRanges       []string `json:"approved_ip_ranges"`
			ApprovedDomains        []string `json:"approved_domains"`
			TimeToInactiveUsers    int64    `json:"time_to_inactive_users"`
			InactiveUsersIsEnable  bool     `json:"inactive_users_is_enable"`
			ApprovedMailingDomains []string `json:"approved_mailing_domains"`
			ExternalIPMonitoring   bool     `json:"external_ip_monitoring"`
			LimitAPIAccess         bool     `json:"limit_api_access"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing security settings: %w", err)
	}
	r := resp.Reply
	return &api.SecuritySettings{
		UserLoginExpiration:    r.UserLoginExpiration,
		AutoLogoutEnabled:      r.AutoLogoutEnabled,
		AutoLogoutTime:         r.AutoLogoutTime,
		DashboardExpiration:    r.DashboardExpiration,
		ApprovedIPRanges:       r.ApprovedIPRanges,
		ApprovedDomains:        r.ApprovedDomains,
		TimeToInactiveUsers:    r.TimeToInactiveUsers,
		InactiveUsersIsEnable:  r.InactiveUsersIsEnable,
		ApprovedMailingDomains: r.ApprovedMailingDomains,
		ExternalIPMonitoring:   r.ExternalIPMonitoring,
		LimitAPIAccess:         r.LimitAPIAccess,
	}, nil
}

func (b *Backend) UpdateSecuritySettings(settings map[string]interface{}) (*api.SecuritySettings, error) {
	if err := b.requireWebapp("security settings update"); err != nil {
		return nil, err
	}
	payload := map[string]interface{}{
		"data": settings,
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST", "/api/webapp/user_settings/set_proxy_data", payload)
	if err != nil {
		return nil, err
	}
	return b.GetSecuritySettings()
}

// --- Lists ---

func (b *Backend) GetList(name string) (*api.List, error) {
	// Get metadata from /lists to find version
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", b.p("/lists"), nil)
	if err != nil {
		return nil, err
	}
	var allLists []map[string]interface{}
	if err := json.Unmarshal(body, &allLists); err != nil {
		return nil, fmt.Errorf("parsing lists: %w", err)
	}
	var listMeta map[string]interface{}
	for _, l := range allLists {
		if getString(l, "name") == name {
			listMeta = l
			break
		}
	}
	if listMeta == nil {
		return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("list %q not found", name)}
	}

	// Get data from /lists/download/{name}
	dataBody, _, err := b.Client.DoRequestRaw(b.Ctx, "GET", b.p("/lists/download/"+name), nil)
	if err != nil {
		return nil, fmt.Errorf("downloading list data: %w", err)
	}

	return &api.List{
		ID:      getString(listMeta, "id"),
		Version: getInt(listMeta, "version"),
		Name:    getString(listMeta, "name"),
		Type:    getString(listMeta, "type"),
		Data:    string(dataBody),
	}, nil
}

func (b *Backend) CreateList(list map[string]interface{}) (*api.List, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/lists/save"), list)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing list save response: %w", err)
	}
	return &api.List{
		ID:      getString(resp, "id"),
		Version: getInt(resp, "version"),
		Name:    getString(resp, "name"),
		Type:    getString(resp, "type"),
	}, nil
}

func (b *Backend) UpdateList(list map[string]interface{}) (*api.List, error) {
	return b.CreateList(list) // Same endpoint for create and update
}

func (b *Backend) DeleteList(name string) error {
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", b.p("/lists/delete"), map[string]interface{}{
		"id": name,
	})
	return err
}

// --- Correlation Rules ---
// Available on XSIAM only, requires webapp session.

func (b *Backend) ListCorrelationRules() ([]api.CorrelationRule, error) {
	if err := b.requireXSIAMWebapp("correlation rule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=CORRELATION_RULES",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort": []map[string]string{
					{"FIELD": "MODIFY_TIME", "ORDER": "DESC"},
				},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing correlation rules: %w", err)
	}
	var rules []api.CorrelationRule
	for _, d := range resp.Reply.Data {
		rules = append(rules, parseCorrelationRule(d))
	}
	return rules, nil
}

func (b *Backend) GetCorrelationRule(ruleID int) (*api.CorrelationRule, error) {
	if err := b.requireXSIAMWebapp("correlation rule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=CORRELATION_RULES",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"filter": map[string]interface{}{
					"AND": []map[string]interface{}{
						{
							"SEARCH_FIELD": "RULE_ID",
							"SEARCH_TYPE":  "EQ",
							"SEARCH_VALUE": ruleID,
						},
					},
				},
				"paging": map[string]int{"from": 0, "to": 1},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing correlation rule: %w", err)
	}
	if len(resp.Reply.Data) == 0 {
		return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("correlation rule %d not found", ruleID)}
	}
	rule := parseCorrelationRule(resp.Reply.Data[0])
	return &rule, nil
}

func (b *Backend) CreateCorrelationRule(rule map[string]interface{}) (*api.CorrelationRule, error) {
	if err := b.requireXSIAMWebapp("correlation rule creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/correlations/create_rule/", rule)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing create correlation rule response: %w", err)
	}
	// The reply may contain the rule ID
	var newRuleID int
	switch v := resp.Reply.(type) {
	case float64:
		newRuleID = int(v)
	case map[string]interface{}:
		if id, ok := v["RULE_ID"].(float64); ok {
			newRuleID = int(id)
		}
	}
	if newRuleID > 0 {
		return b.GetCorrelationRule(newRuleID)
	}
	// If we didn't get an ID, list all and find the one we just created
	name, _ := rule["NAME"].(string)
	rules, err := b.ListCorrelationRules()
	if err != nil {
		return nil, fmt.Errorf("could not verify correlation rule creation: %w", err)
	}
	for i := range rules {
		if rules[i].Name == name {
			return &rules[i], nil
		}
	}
	return nil, fmt.Errorf("correlation rule was created but could not be found by name %q", name)
}

func (b *Backend) UpdateCorrelationRule(ruleID int, rule map[string]interface{}) (*api.CorrelationRule, error) {
	if err := b.requireXSIAMWebapp("correlation rule update"); err != nil {
		return nil, err
	}
	rule["RULE_ID"] = ruleID
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/correlations/update_rule/", rule)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing update correlation rule response: %w", err)
	}
	return b.GetCorrelationRule(ruleID)
}

func (b *Backend) DeleteCorrelationRule(ruleID int) error {
	if err := b.requireXSIAMWebapp("correlation rule deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/correlations/delete_rule/",
		map[string]interface{}{
			"rule_ids": []int{ruleID},
		})
	return err
}

func parseCorrelationRule(d map[string]interface{}) api.CorrelationRule {
	rule := api.CorrelationRule{
		Name:            getString(d, "NAME"),
		Description:     getString(d, "DESCRIPTION"),
		Severity:        getString(d, "SEVERITY"),
		Status:          getString(d, "STATUS"),
		XQLQuery:        getString(d, "XQL_QUERY"),
		ExecutionMode:   getString(d, "EXECUTION_MODE"),
		SearchWindow:    getString(d, "SEARCH_WINDOW"),
		SimpleSchedule:  getString(d, "SIMPLE_SCHEDULE"),
		Dataset:         getString(d, "DATASET"),
		Timezone:        getString(d, "TIMEZONE"),
		AlertDomain:     getString(d, "ALERT_DOMAIN"),
		AlertCategory:   getString(d, "ALERT_CATEGORY"),
		AlertName:       getString(d, "ALERT_NAME"),
		MappingStrategy: getString(d, "MAPPING_STRATEGY"),
		Action:          getString(d, "ACTION"),
	}
	if id, ok := d["RULE_ID"].(float64); ok {
		rule.RuleID = int(id)
	}
	return rule
}

// --- IOC Rules ---
// Available on XSIAM, requires webapp session.

func (b *Backend) ListIOCRules() ([]api.IOCRule, error) {
	if err := b.requireXSIAMWebapp("IOC rule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=IOC_RULE_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort": []map[string]string{
					{"FIELD": "RULE_MODIFY_TIME", "ORDER": "DESC"},
				},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing IOC rules: %w", err)
	}
	var rules []api.IOCRule
	for _, d := range resp.Reply.Data {
		rules = append(rules, parseIOCRule(d))
	}
	return rules, nil
}

func (b *Backend) GetIOCRule(ruleID int) (*api.IOCRule, error) {
	if err := b.requireXSIAMWebapp("IOC rule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=IOC_RULE_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"filter": map[string]interface{}{
					"AND": []map[string]interface{}{
						{
							"SEARCH_FIELD": "RULE_ID",
							"SEARCH_TYPE":  "EQ",
							"SEARCH_VALUE": ruleID,
						},
					},
				},
				"paging": map[string]int{"from": 0, "to": 1},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing IOC rule: %w", err)
	}
	if len(resp.Reply.Data) == 0 {
		return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("IOC rule %d not found", ruleID)}
	}
	rule := parseIOCRule(resp.Reply.Data[0])
	return &rule, nil
}

func (b *Backend) CreateIOCRule(rule map[string]interface{}) (*api.IOCRule, error) {
	if err := b.requireXSIAMWebapp("IOC rule creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/ioc/add_rule/",
		map[string]interface{}{
			"ioc_rule": rule,
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing create IOC rule response: %w", err)
	}
	// Reply is the rule ID as a number
	var newRuleID int
	switch v := resp.Reply.(type) {
	case float64:
		newRuleID = int(v)
	}
	if newRuleID > 0 {
		return b.GetIOCRule(newRuleID)
	}
	return nil, fmt.Errorf("IOC rule was created but reply did not contain a rule ID")
}

func (b *Backend) DeleteIOCRule(ruleID int) error {
	if err := b.requireXSIAMWebapp("IOC rule deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/ioc/delete_rules/",
		map[string]interface{}{
			"rule_ids": []int{ruleID},
		})
	return err
}

func parseIOCRule(d map[string]interface{}) api.IOCRule {
	rule := api.IOCRule{
		Severity:    getString(d, "RULE_SEVERITY"),
		Indicator:   getString(d, "RULE_INDICATOR"),
		IOCType:     getString(d, "IOC_TYPE"),
		Comment:     getString(d, "RULE_COMMENT"),
		Status:      getString(d, "RULE_STATUS"),
		Reputation:  getString(d, "REPUTATION"),
		Reliability: getString(d, "RELIABILITY"),
	}
	if id, ok := d["RULE_ID"].(float64); ok {
		rule.RuleID = int(id)
	}
	rule.IsDefaultTTL = getBool(d, "IS_DEFAULT_TTL")
	if ttl, ok := d["RULE_TTL"].(float64); ok {
		rule.TTL = int(ttl)
	}
	return rule
}

// --- Helper functions ---

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func getInt(m map[string]interface{}, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	}
	return 0
}

func parseIntegrationInstance(im map[string]interface{}) api.IntegrationInstance {
	instance := api.IntegrationInstance{
		ID:       getString(im, "id"),
		Name:     getString(im, "name"),
		Brand:    getString(im, "brand"),
		Category: getString(im, "category"),
		Enabled:  getString(im, "enabled"),
		Engine:   getString(im, "engine"),
	}
	if v, ok := im["version"].(float64); ok {
		instance.Version = int(v)
	}
	if v, ok := im["engineGroup"].(string); ok {
		instance.EngineGroup = v
	}
	instance.IncomingMapperID = getString(im, "incomingMapperId")
	instance.OutgoingMapperID = getString(im, "outgoingMapperId")
	instance.MappingID = getString(im, "mappingId")
	instance.LogLevel = getString(im, "integrationLogLevel")
	instance.IsIntegrationScript = getBool(im, "isIntegrationScript")
	instance.CanSample = getBool(im, "canSample")

	if labels, ok := im["propagationLabels"].([]interface{}); ok {
		for _, l := range labels {
			if s, ok := l.(string); ok {
				instance.PropagationLabels = append(instance.PropagationLabels, s)
			}
		}
	}

	if data, ok := im["data"].([]interface{}); ok {
		for _, d := range data {
			if dm, ok := d.(map[string]interface{}); ok {
				instance.Data = append(instance.Data, dm)
			}
		}
	}

	instance.ConfigMap = make(map[string]string)
	for _, param := range instance.Data {
		name := getString(param, "name")
		display := getString(param, "display")
		value := getString(param, "value")
		hasValue := getBool(param, "hasvalue")
		if hasValue && value != "" {
			key := display
			if key == "" {
				key = name
			}
			instance.ConfigMap[key] = value
		}
	}

	return instance
}

// --- EDL Config ---
// Available on XSIAM only, requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

func (b *Backend) GetEDLConfig() (*api.EDLConfig, error) {
	if err := b.requireXSIAMWebapp("EDL configuration"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/edl/get_edl_status", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply map[string]interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing EDL config: %w", err)
	}
	return &api.EDLConfig{
		Enabled:   getBool(resp.Reply, "enabled"),
		Username:  getString(resp.Reply, "username"),
		Password:  getString(resp.Reply, "password"),
		URLIP:     getString(resp.Reply, "url_ip"),
		URLDomain: getString(resp.Reply, "url_domain"),
	}, nil
}

func (b *Backend) UpdateEDLConfig(config map[string]interface{}) (*api.EDLConfig, error) {
	if err := b.requireXSIAMWebapp("EDL configuration"); err != nil {
		return nil, err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/edl/update_settings", config)
	if err != nil {
		return nil, err
	}
	return b.GetEDLConfig()
}

// --- Vulnerability Scan Settings ---
// Available on XSIAM only, requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

func (b *Backend) GetVulnerabilityScanSettings() (*api.VulnerabilityScanSettings, error) {
	if err := b.requireXSIAMWebapp("vulnerability scan settings"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/vulnerability_tests/get_settings", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	// Response is top-level with UPPERCASE keys (no reply wrapper)
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing vulnerability scan settings: %w", err)
	}
	return &api.VulnerabilityScanSettings{
		EULAAccepted:          getBool(resp, "EULA_ACCEPTED"),
		NewTestsEnabled:       getBool(resp, "NEW_TESTS_ENABLED"),
		PauseTesting:          getBool(resp, "PAUSE_TESTING"),
		RunTestsOnAllServices: getBool(resp, "RUN_TESTS_ON_ALL_SERVICES"),
		IntrusiveLevel:        getInt(resp, "INTRUSIVE_LEVEL"),
		TargetFilter:          getString(resp, "TARGET_FILTER"),
	}, nil
}

// vulnScanKeyMap maps lowercase resource keys to UPPERCASE API keys.
var vulnScanKeyMap = map[string]string{
	"eula_accepted":             "EULA_ACCEPTED",
	"new_tests_enabled":         "NEW_TESTS_ENABLED",
	"pause_testing":             "PAUSE_TESTING",
	"run_tests_on_all_services": "RUN_TESTS_ON_ALL_SERVICES",
	"intrusive_level":           "INTRUSIVE_LEVEL",
	"target_filter":             "TARGET_FILTER",
}

func (b *Backend) UpdateVulnerabilityScanSettings(settings map[string]interface{}) (*api.VulnerabilityScanSettings, error) {
	if err := b.requireXSIAMWebapp("vulnerability scan settings"); err != nil {
		return nil, err
	}
	// Convert lowercase keys to UPPERCASE for the API
	upperSettings := make(map[string]interface{})
	for k, v := range settings {
		if upper, ok := vulnScanKeyMap[k]; ok {
			upperSettings[upper] = v
		} else {
			upperSettings[k] = v
		}
	}
	wrappedBody := map[string]interface{}{
		"request_data": upperSettings,
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/vulnerability_tests/update_settings", wrappedBody)
	if err != nil {
		return nil, err
	}
	return b.GetVulnerabilityScanSettings()
}

// --- Device Control Classes ---
// Available on XSIAM only, requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

func (b *Backend) ListDeviceControlClasses() ([]api.DeviceControlClass, error) {
	if err := b.requireXSIAMWebapp("device control class management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/device_control/user_defined/get_classes", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply []map[string]interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing device control classes: %w", err)
	}
	var classes []api.DeviceControlClass
	for _, d := range resp.Reply {
		classes = append(classes, api.DeviceControlClass{
			Identifier: getString(d, "identifier"),
			Type:       getString(d, "type"),
		})
	}
	return classes, nil
}

func (b *Backend) CreateDeviceControlClass(class map[string]interface{}) (*api.DeviceControlClass, error) {
	if err := b.requireXSIAMWebapp("device control class creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/device_control/user_defined/create_class", class)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply map[string]interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing device control class create response: %w", err)
	}
	identifier := getString(resp.Reply, "identifier")
	if identifier == "" {
		typeName, _ := class["type"].(string)
		classes, listErr := b.ListDeviceControlClasses()
		if listErr != nil {
			return nil, fmt.Errorf("could not verify device control class creation: %w", listErr)
		}
		for i := range classes {
			if classes[i].Type == typeName {
				return &classes[i], nil
			}
		}
		return nil, fmt.Errorf("device control class was created but could not be found")
	}
	return &api.DeviceControlClass{
		Identifier: identifier,
		Type:       getString(resp.Reply, "type"),
	}, nil
}

func (b *Backend) DeleteDeviceControlClass(identifier string) error {
	if err := b.requireXSIAMWebapp("device control class deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/device_control/user_defined/delete_class",
		map[string]interface{}{"identifier": identifier})
	return err
}

// --- Custom Statuses ---
// Available on XSIAM only, requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

// getCustomStatusesWithHash is an internal helper that returns the full response from get_statuses
// including the custom_status_hash needed for bulk updates.
func (b *Backend) getCustomStatusesWithHash() (*api.CustomStatusesResponse, error) {
	if err := b.requireXSIAMWebapp("custom status management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/custom_status/get_statuses", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Statuses           []map[string]interface{} `json:"statuses"`
			ResolutionStatuses []map[string]interface{} `json:"resolutionStatuses"`
			CustomStatusHash   string                   `json:"custom_status_hash"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing custom statuses: %w", err)
	}

	parseStatus := func(d map[string]interface{}, statusType string) api.CustomStatus {
		s := api.CustomStatus{
			EnumName:   getString(d, "enum_name"),
			PrettyName: getString(d, "pretty_name"),
			StatusType: statusType,
			CanDelete:  getBool(d, "can_delete"),
			CanReorder: getBool(d, "can_reorder"),
		}
		if p, ok := d["priority"].(float64); ok {
			s.Priority = int(p)
		}
		return s
	}

	result := &api.CustomStatusesResponse{
		CustomStatusHash: resp.Reply.CustomStatusHash,
	}
	for _, d := range resp.Reply.Statuses {
		result.Statuses = append(result.Statuses, parseStatus(d, "status"))
	}
	for _, d := range resp.Reply.ResolutionStatuses {
		result.ResolutionStatuses = append(result.ResolutionStatuses, parseStatus(d, "resolution"))
	}
	return result, nil
}

func (b *Backend) ListCustomStatuses() ([]api.CustomStatus, error) {
	resp, err := b.getCustomStatusesWithHash()
	if err != nil {
		return nil, err
	}
	// Combine both status types into a single list
	var all []api.CustomStatus
	all = append(all, resp.Statuses...)
	all = append(all, resp.ResolutionStatuses...)
	return all, nil
}

// buildSeparateStatusPayloads returns separate statuses and resolutionStatuses arrays
// for the update_statuses endpoint, including only custom (can_delete=true) statuses.
func buildSeparateStatusPayloads(resp *api.CustomStatusesResponse) (statuses, resolutionStatuses []map[string]interface{}) {
	for _, s := range resp.Statuses {
		if !s.CanDelete {
			continue
		}
		statuses = append(statuses, map[string]interface{}{
			"enum_name":   s.EnumName,
			"pretty_name": s.PrettyName,
			"priority":    s.Priority,
		})
	}
	for _, s := range resp.ResolutionStatuses {
		if !s.CanDelete {
			continue
		}
		resolutionStatuses = append(resolutionStatuses, map[string]interface{}{
			"enum_name":   s.EnumName,
			"pretty_name": s.PrettyName,
			"priority":    s.Priority,
		})
	}
	return
}

func (b *Backend) CreateCustomStatus(status map[string]interface{}) (*api.CustomStatus, error) {
	if err := b.requireXSIAMWebapp("custom status creation"); err != nil {
		return nil, err
	}

	prettyName, _ := status["pretty_name"].(string)

	// Step 1: Get current statuses and hash
	current, err := b.getCustomStatusesWithHash()
	if err != nil {
		return nil, fmt.Errorf("reading current statuses before create: %w", err)
	}

	// Check if status already exists (e.g. after a state-only delete)
	allExisting, _ := b.ListCustomStatuses()
	for i := range allExisting {
		if allExisting[i].PrettyName == prettyName {
			tflog.Info(b.Ctx, "Custom status already exists, adopting into state",
				map[string]interface{}{"pretty_name": prettyName, "enum_name": allExisting[i].EnumName})
			return &allExisting[i], nil
		}
	}

	// Step 2: Build separate status/resolution arrays with existing custom statuses
	statuses, resolutions := buildSeparateStatusPayloads(current)

	// Add the new status entry to the appropriate array based on status_type
	newEntry := map[string]interface{}{
		"pretty_name": prettyName,
	}
	if p, ok := status["priority"]; ok {
		newEntry["priority"] = p
	}

	statusType, _ := status["status_type"].(string)
	if statusType == "resolution" {
		resolutions = append(resolutions, newEntry)
	} else {
		statuses = append(statuses, newEntry)
	}

	updateBody := map[string]interface{}{
		"last_custom_status_hash": current.CustomStatusHash,
		"statuses":                statuses,
		"resolutionStatuses":      resolutions,
	}

	// Step 3: Call update_statuses
	_, _, err = b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/custom_status/update_statuses", updateBody)
	if err != nil {
		return nil, fmt.Errorf("creating custom status via bulk update: %w", err)
	}

	// Step 4: Re-read to find the newly created status by pretty_name
	allStatuses, listErr := b.ListCustomStatuses()
	if listErr != nil {
		return nil, fmt.Errorf("could not verify custom status creation: %w", listErr)
	}
	for i := range allStatuses {
		if allStatuses[i].PrettyName == prettyName {
			return &allStatuses[i], nil
		}
	}
	return nil, fmt.Errorf("custom status %q was created but could not be found in updated list", prettyName)
}

func (b *Backend) DeleteCustomStatus(enumName string) error {
	if err := b.requireXSIAMWebapp("custom status deletion"); err != nil {
		return err
	}

	// The XSIAM webapp API does not expose a delete endpoint for custom statuses.
	// The update_statuses endpoint only supports adding and reordering statuses,
	// not removing them. Deletion must be done manually via the XSIAM UI.
	// We log a warning and remove from Terraform state only.
	tflog.Warn(b.Ctx, "Custom status deletion is not supported by the XSIAM API; "+
		"the status has been removed from Terraform state but still exists in XSIAM. "+
		"Delete it manually via the XSIAM UI if needed.",
		map[string]interface{}{"enum_name": enumName})
	return nil
}

// --- Agent Groups ---
// Available on XSIAM only, requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

func (b *Backend) ListAgentGroups() ([]api.AgentGroup, error) {
	if err := b.requireXSIAMWebapp("agent group management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=AGENT_GROUPS_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing agent groups: %w", err)
	}
	var groups []api.AgentGroup
	for _, d := range resp.Reply.Data {
		group := api.AgentGroup{
			Name:        getString(d, "NAME"),
			Description: getString(d, "DESCRIPTION"),
			Type:        getString(d, "TYPE"),
		}
		if id, ok := d["GROUP_ID"].(float64); ok {
			group.GroupID = int(id)
		}
		if cnt, ok := d["COUNT"].(float64); ok {
			group.Count = int(cnt)
		}
		if f, ok := d["FILTER"]; ok && f != nil {
			if fBytes, err := json.Marshal(f); err == nil {
				group.Filter = string(fBytes)
			}
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (b *Backend) GetAgentGroup(groupID int) (*api.AgentGroup, error) {
	if err := b.requireXSIAMWebapp("agent group management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=AGENT_GROUPS_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"filter": map[string]interface{}{
					"AND": []map[string]interface{}{
						{
							"SEARCH_FIELD": "GROUP_ID",
							"SEARCH_TYPE":  "EQ",
							"SEARCH_VALUE": groupID,
						},
					},
				},
				"paging": map[string]int{"from": 0, "to": 1},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing agent group: %w", err)
	}
	if len(resp.Reply.Data) == 0 {
		return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("agent group %d not found", groupID)}
	}
	d := resp.Reply.Data[0]
	group := &api.AgentGroup{
		Name:        getString(d, "NAME"),
		Description: getString(d, "DESCRIPTION"),
		Type:        getString(d, "TYPE"),
	}
	if id, ok := d["GROUP_ID"].(float64); ok {
		group.GroupID = int(id)
	}
	if cnt, ok := d["COUNT"].(float64); ok {
		group.Count = int(cnt)
	}
	if f, ok := d["FILTER"]; ok && f != nil {
		if fBytes, err := json.Marshal(f); err == nil {
			group.Filter = string(fBytes)
		}
	}
	return group, nil
}

func (b *Backend) CreateAgentGroup(group map[string]interface{}) (*api.AgentGroup, error) {
	if err := b.requireXSIAMWebapp("agent group creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/agent_groups/create", group)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing agent group create response: %w", err)
	}
	var newGroupID int
	switch v := resp.Reply.(type) {
	case float64:
		newGroupID = int(v)
	case map[string]interface{}:
		if id, ok := v["GROUP_ID"].(float64); ok {
			newGroupID = int(id)
		}
	}
	if newGroupID > 0 {
		return b.GetAgentGroup(newGroupID)
	}
	name, _ := group["NAME"].(string)
	groups, listErr := b.ListAgentGroups()
	if listErr != nil {
		return nil, fmt.Errorf("could not verify agent group creation: %w", listErr)
	}
	for i := range groups {
		if groups[i].Name == name {
			return &groups[i], nil
		}
	}
	return nil, fmt.Errorf("agent group was created but could not be found by name %q", name)
}

func (b *Backend) UpdateAgentGroup(groupID int, group map[string]interface{}) (*api.AgentGroup, error) {
	if err := b.requireXSIAMWebapp("agent group update"); err != nil {
		return nil, err
	}
	group["GROUP_ID"] = groupID
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/agent_groups/update", group)
	if err != nil {
		return nil, err
	}
	return b.GetAgentGroup(groupID)
}

func (b *Backend) DeleteAgentGroup(groupID int) error {
	if err := b.requireXSIAMWebapp("agent group deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/agent_groups/delete",
		map[string]interface{}{"group_ids": []int{groupID}})
	return err
}

// --- Incident Domains ---
// Available on XSIAM only, requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

func (b *Backend) ListIncidentDomains() ([]api.IncidentDomain, error) {
	if err := b.requireXSIAMWebapp("incident domain management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/incident_domains/get_domains/", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply []map[string]interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing incident domains: %w", err)
	}
	var domains []api.IncidentDomain
	for _, d := range resp.Reply {
		domain := api.IncidentDomain{
			Name:        getString(d, "name"),
			PrettyName:  getString(d, "pretty_name"),
			Color:       getString(d, "color"),
			Description: getString(d, "description"),
			IsDefault:   getBool(d, "is_default"),
		}
		if id, ok := d["domain_id"].(float64); ok {
			domain.DomainID = int(id)
		}
		if statuses, ok := d["statuses"].([]interface{}); ok {
			for _, s := range statuses {
				if str, ok := s.(string); ok {
					domain.Statuses = append(domain.Statuses, str)
				}
			}
		}
		if resolved, ok := d["resolved_statuses"].([]interface{}); ok {
			for _, s := range resolved {
				if str, ok := s.(string); ok {
					domain.ResolvedStatuses = append(domain.ResolvedStatuses, str)
				}
			}
		}
		domains = append(domains, domain)
	}
	return domains, nil
}

func (b *Backend) GetIncidentDomain(domainID int) (*api.IncidentDomain, error) {
	domains, err := b.ListIncidentDomains()
	if err != nil {
		return nil, err
	}
	for i := range domains {
		if domains[i].DomainID == domainID {
			return &domains[i], nil
		}
	}
	return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("incident domain %d not found", domainID)}
}

func (b *Backend) CreateIncidentDomain(domain map[string]interface{}) (*api.IncidentDomain, error) {
	if err := b.requireXSIAMWebapp("incident domain creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/incident_domains/create_domain/", domain)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing incident domain create response: %w", err)
	}
	var newDomainID int
	switch v := resp.Reply.(type) {
	case float64:
		newDomainID = int(v)
	case map[string]interface{}:
		if id, ok := v["domain_id"].(float64); ok {
			newDomainID = int(id)
		}
	}
	if newDomainID > 0 {
		return b.GetIncidentDomain(newDomainID)
	}
	name, _ := domain["pretty_name"].(string)
	domains, listErr := b.ListIncidentDomains()
	if listErr != nil {
		return nil, fmt.Errorf("could not verify incident domain creation: %w", listErr)
	}
	for i := range domains {
		if domains[i].PrettyName == name {
			return &domains[i], nil
		}
	}
	return nil, fmt.Errorf("incident domain was created but could not be found by name %q", name)
}

func (b *Backend) UpdateIncidentDomain(domainID int, domain map[string]interface{}) (*api.IncidentDomain, error) {
	if err := b.requireXSIAMWebapp("incident domain update"); err != nil {
		return nil, err
	}
	domain["domain_id"] = domainID
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/incident_domains/update_domain/", domain)
	if err != nil {
		return nil, err
	}
	return b.GetIncidentDomain(domainID)
}

func (b *Backend) DeleteIncidentDomain(domainID int) error {
	if err := b.requireXSIAMWebapp("incident domain deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/incident_domains/delete_domain/",
		map[string]interface{}{"domain_id": domainID})
	return err
}

// --- TIM Rules ---
// Available on XSIAM only, requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

func (b *Backend) ListTIMRules() ([]api.TIMRule, error) {
	if err := b.requireXSIAMWebapp("TIM rule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=TIM_RULES_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing TIM rules: %w", err)
	}
	var rules []api.TIMRule
	for _, d := range resp.Reply.Data {
		rule := api.TIMRule{
			Name:        getString(d, "NAME"),
			Type:        getString(d, "TYPE"),
			Severity:    getString(d, "SEVERITY"),
			Status:      getString(d, "STATUS"),
			Description: getString(d, "DESCRIPTION"),
		}
		if id, ok := d["RULE_ID"].(float64); ok {
			rule.RuleID = int(id)
		}
		if t, ok := d["TARGET"]; ok && t != nil {
			if tBytes, err := json.Marshal(t); err == nil {
				rule.Target = string(tBytes)
			}
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (b *Backend) GetTIMRule(ruleID int) (*api.TIMRule, error) {
	if err := b.requireXSIAMWebapp("TIM rule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=TIM_RULES_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"filter": map[string]interface{}{
					"AND": []map[string]interface{}{
						{
							"SEARCH_FIELD": "RULE_ID",
							"SEARCH_TYPE":  "EQ",
							"SEARCH_VALUE": ruleID,
						},
					},
				},
				"paging": map[string]int{"from": 0, "to": 1},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing TIM rule: %w", err)
	}
	if len(resp.Reply.Data) == 0 {
		return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("TIM rule %d not found", ruleID)}
	}
	d := resp.Reply.Data[0]
	rule := &api.TIMRule{
		Name:        getString(d, "NAME"),
		Type:        getString(d, "TYPE"),
		Severity:    getString(d, "SEVERITY"),
		Status:      getString(d, "STATUS"),
		Description: getString(d, "DESCRIPTION"),
	}
	if id, ok := d["RULE_ID"].(float64); ok {
		rule.RuleID = int(id)
	}
	if t, ok := d["TARGET"]; ok && t != nil {
		if tBytes, err := json.Marshal(t); err == nil {
			rule.Target = string(tBytes)
		}
	}
	return rule, nil
}

func (b *Backend) CreateTIMRule(rule map[string]interface{}) (*api.TIMRule, error) {
	if err := b.requireXSIAMWebapp("TIM rule creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/tim/create_rule/", rule)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing TIM rule create response: %w", err)
	}
	var newRuleID int
	switch v := resp.Reply.(type) {
	case float64:
		newRuleID = int(v)
	case map[string]interface{}:
		if id, ok := v["RULE_ID"].(float64); ok {
			newRuleID = int(id)
		}
	}
	if newRuleID > 0 {
		return b.GetTIMRule(newRuleID)
	}
	name, _ := rule["NAME"].(string)
	rules, listErr := b.ListTIMRules()
	if listErr != nil {
		return nil, fmt.Errorf("could not verify TIM rule creation: %w", listErr)
	}
	for i := range rules {
		if rules[i].Name == name {
			return &rules[i], nil
		}
	}
	return nil, fmt.Errorf("TIM rule was created but could not be found by name %q", name)
}

func (b *Backend) UpdateTIMRule(ruleID int, rule map[string]interface{}) (*api.TIMRule, error) {
	if err := b.requireXSIAMWebapp("TIM rule update"); err != nil {
		return nil, err
	}
	rule["RULE_ID"] = ruleID
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/tim/update_rule/", rule)
	if err != nil {
		return nil, err
	}
	return b.GetTIMRule(ruleID)
}

func (b *Backend) DeleteTIMRule(ruleID int) error {
	if err := b.requireXSIAMWebapp("TIM rule deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/tim/delete_rule/",
		map[string]interface{}{"rule_ids": []int{ruleID}})
	return err
}

// --- Attack Surface Rules ---
// Available on XSIAM only, system-defined (no create/delete), requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

func (b *Backend) ListAttackSurfaceRules() ([]api.AttackSurfaceRule, error) {
	if err := b.requireXSIAMWebapp("attack surface rule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=ATTACK_SURFACE_RULES_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing attack surface rules: %w", err)
	}
	var rules []api.AttackSurfaceRule
	for _, d := range resp.Reply.Data {
		rules = append(rules, api.AttackSurfaceRule{
			IssueTypeID:   getString(d, "ISSUE_TYPE_ID"),
			IssueTypeName: getString(d, "ISSUE_TYPE_NAME"),
			EnabledStatus: getString(d, "ENABLED_STATUS"),
			Priority:      getString(d, "PRIORITY"),
			Description:   getString(d, "DESCRIPTION"),
		})
	}
	return rules, nil
}

func (b *Backend) GetAttackSurfaceRule(issueTypeID string) (*api.AttackSurfaceRule, error) {
	rules, err := b.ListAttackSurfaceRules()
	if err != nil {
		return nil, err
	}
	for i := range rules {
		if rules[i].IssueTypeID == issueTypeID {
			return &rules[i], nil
		}
	}
	return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("attack surface rule %q not found", issueTypeID)}
}

func (b *Backend) UpdateAttackSurfaceRule(issueTypeID string, rule map[string]interface{}) (*api.AttackSurfaceRule, error) {
	if err := b.requireXSIAMWebapp("attack surface rule update"); err != nil {
		return nil, err
	}
	rule["ISSUE_TYPE_ID"] = issueTypeID
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/attack_surface/update_rule/", rule)
	if err != nil {
		return nil, err
	}
	return b.GetAttackSurfaceRule(issueTypeID)
}

// --- BIOC Rules ---
// Available on XSIAM only, requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

func (b *Backend) ListBIOCRules() ([]api.BIOCRule, error) {
	if err := b.requireXSIAMWebapp("BIOC rule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=BIOC_RULE_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing BIOC rules: %w", err)
	}
	var rules []api.BIOCRule
	for _, d := range resp.Reply.Data {
		rules = append(rules, parseBIOCRule(d))
	}
	return rules, nil
}

func (b *Backend) GetBIOCRule(ruleID int) (*api.BIOCRule, error) {
	if err := b.requireXSIAMWebapp("BIOC rule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=BIOC_RULE_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"filter": map[string]interface{}{
					"AND": []map[string]interface{}{
						{
							"SEARCH_FIELD": "RULE_ID",
							"SEARCH_TYPE":  "EQ",
							"SEARCH_VALUE": ruleID,
						},
					},
				},
				"paging": map[string]int{"from": 0, "to": 1},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing BIOC rule: %w", err)
	}
	if len(resp.Reply.Data) == 0 {
		return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("BIOC rule %d not found", ruleID)}
	}
	rule := parseBIOCRule(resp.Reply.Data[0])
	return &rule, nil
}

func (b *Backend) CreateBIOCRule(rule map[string]interface{}) (*api.BIOCRule, error) {
	if err := b.requireXSIAMWebapp("BIOC rule creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/bioc/create_rule/", rule)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing BIOC rule create response: %w", err)
	}
	var newRuleID int
	switch v := resp.Reply.(type) {
	case float64:
		newRuleID = int(v)
	case map[string]interface{}:
		if id, ok := v["RULE_ID"].(float64); ok {
			newRuleID = int(id)
		}
	}
	if newRuleID > 0 {
		return b.GetBIOCRule(newRuleID)
	}
	name, _ := rule["NAME"].(string)
	rules, listErr := b.ListBIOCRules()
	if listErr != nil {
		return nil, fmt.Errorf("could not verify BIOC rule creation: %w", listErr)
	}
	for i := range rules {
		if rules[i].Name == name {
			return &rules[i], nil
		}
	}
	return nil, fmt.Errorf("BIOC rule was created but could not be found by name %q", name)
}

func (b *Backend) UpdateBIOCRule(ruleID int, rule map[string]interface{}) (*api.BIOCRule, error) {
	if err := b.requireXSIAMWebapp("BIOC rule update"); err != nil {
		return nil, err
	}
	rule["RULE_ID"] = ruleID
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/bioc/update_rule/", rule)
	if err != nil {
		return nil, err
	}
	return b.GetBIOCRule(ruleID)
}

func (b *Backend) DeleteBIOCRule(ruleID int) error {
	if err := b.requireXSIAMWebapp("BIOC rule deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/bioc/delete_rule/",
		map[string]interface{}{"rule_ids": []int{ruleID}})
	return err
}

func parseBIOCRule(d map[string]interface{}) api.BIOCRule {
	rule := api.BIOCRule{
		Name:     getString(d, "NAME"),
		Severity: getString(d, "SEVERITY"),
		Status:   getString(d, "STATUS"),
		Category: getString(d, "CATEGORY"),
		Comment:  getString(d, "COMMENT"),
		Source:   getString(d, "SOURCE"),
		IsXQL:    getBool(d, "IS_XQL"),
	}
	if id, ok := d["RULE_ID"].(float64); ok {
		rule.RuleID = int(id)
	}
	if tactics, ok := d["MITRE_TACTIC"].([]interface{}); ok {
		for _, t := range tactics {
			if s, ok := t.(string); ok {
				rule.MitreTactic = append(rule.MitreTactic, s)
			}
		}
	}
	if techniques, ok := d["MITRE_TECHNIQUE"].([]interface{}); ok {
		for _, t := range techniques {
			if s, ok := t.(string); ok {
				rule.MitreTechnique = append(rule.MitreTechnique, s)
			}
		}
	}
	if it, ok := d["INDICATOR_TEXT"]; ok && it != nil {
		if itBytes, err := json.Marshal(it); err == nil {
			rule.IndicatorText = string(itBytes)
		}
	}
	return rule
}

// --- Rules Exceptions ---
// Available on XSIAM only, requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

func (b *Backend) ListRulesExceptions() ([]api.RulesException, error) {
	if err := b.requireXSIAMWebapp("rules exception management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=RULES_EXCEPTIONS_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing rules exceptions: %w", err)
	}
	var rules []api.RulesException
	for _, d := range resp.Reply.Data {
		rule := api.RulesException{
			Name:        getString(d, "NAME"),
			Description: getString(d, "DESCRIPTION"),
			Status:      getString(d, "STATUS"),
			AlertID:     getString(d, "ALERT_ID"),
		}
		if id, ok := d["RULE_ID"].(float64); ok {
			rule.RuleID = int(id)
		}
		if f, ok := d["FILTER"]; ok && f != nil {
			if fBytes, err := json.Marshal(f); err == nil {
				rule.Filter = string(fBytes)
			}
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (b *Backend) GetRulesException(ruleID int) (*api.RulesException, error) {
	if err := b.requireXSIAMWebapp("rules exception management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=RULES_EXCEPTIONS_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"filter": map[string]interface{}{
					"AND": []map[string]interface{}{
						{
							"SEARCH_FIELD": "RULE_ID",
							"SEARCH_TYPE":  "EQ",
							"SEARCH_VALUE": ruleID,
						},
					},
				},
				"paging": map[string]int{"from": 0, "to": 1},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing rules exception: %w", err)
	}
	if len(resp.Reply.Data) == 0 {
		return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("rules exception %d not found", ruleID)}
	}
	d := resp.Reply.Data[0]
	rule := &api.RulesException{
		Name:        getString(d, "NAME"),
		Description: getString(d, "DESCRIPTION"),
		Status:      getString(d, "STATUS"),
		AlertID:     getString(d, "ALERT_ID"),
	}
	if id, ok := d["RULE_ID"].(float64); ok {
		rule.RuleID = int(id)
	}
	if f, ok := d["FILTER"]; ok && f != nil {
		if fBytes, err := json.Marshal(f); err == nil {
			rule.Filter = string(fBytes)
		}
	}
	return rule, nil
}

func (b *Backend) CreateRulesException(rule map[string]interface{}) (*api.RulesException, error) {
	if err := b.requireXSIAMWebapp("rules exception creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/exceptions/create_rule/", rule)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing rules exception create response: %w", err)
	}
	var newRuleID int
	switch v := resp.Reply.(type) {
	case float64:
		newRuleID = int(v)
	case map[string]interface{}:
		if id, ok := v["RULE_ID"].(float64); ok {
			newRuleID = int(id)
		}
	}
	if newRuleID > 0 {
		return b.GetRulesException(newRuleID)
	}
	name, _ := rule["NAME"].(string)
	exceptions, listErr := b.ListRulesExceptions()
	if listErr != nil {
		return nil, fmt.Errorf("could not verify rules exception creation: %w", listErr)
	}
	for i := range exceptions {
		if exceptions[i].Name == name {
			return &exceptions[i], nil
		}
	}
	return nil, fmt.Errorf("rules exception was created but could not be found by name %q", name)
}

func (b *Backend) DeleteRulesException(ruleID int) error {
	if err := b.requireXSIAMWebapp("rules exception deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/exceptions/delete_rule/",
		map[string]interface{}{"rule_ids": []int{ruleID}})
	return err
}

// --- Analytics Detectors ---
// Available on XSIAM only, system-defined rules (severity/status override only), requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

func (b *Backend) ListAnalyticsDetectors() ([]api.AnalyticsDetector, error) {
	if err := b.requireXSIAMWebapp("analytics detector management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=ANALYTICS_DETECTORS_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing analytics detectors: %w", err)
	}
	var detectors []api.AnalyticsDetector
	for _, d := range resp.Reply.Data {
		detectors = append(detectors, parseAnalyticsDetector(d))
	}
	return detectors, nil
}

func (b *Backend) GetAnalyticsDetector(globalRuleID string) (*api.AnalyticsDetector, error) {
	detectors, err := b.ListAnalyticsDetectors()
	if err != nil {
		return nil, err
	}
	for i := range detectors {
		if detectors[i].GlobalRuleID == globalRuleID {
			return &detectors[i], nil
		}
	}
	return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("analytics detector %q not found", globalRuleID)}
}

func (b *Backend) UpdateAnalyticsDetector(globalRuleID string, detector map[string]interface{}) (*api.AnalyticsDetector, error) {
	if err := b.requireXSIAMWebapp("analytics detector update"); err != nil {
		return nil, err
	}
	detector["GLOBAL_RULE_ID"] = globalRuleID
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/analytics/update_rule/", detector)
	if err != nil {
		return nil, err
	}
	return b.GetAnalyticsDetector(globalRuleID)
}

func parseAnalyticsDetector(d map[string]interface{}) api.AnalyticsDetector {
	detector := api.AnalyticsDetector{
		GlobalRuleID:     getString(d, "GLOBAL_RULE_ID"),
		Name:             getString(d, "NAME"),
		Description:      getString(d, "DESCRIPTION"),
		Severity:         getString(d, "SEVERITY"),
		Status:           getString(d, "STATUS"),
		OriginalSeverity: getString(d, "ORIGINAL_SEVERITY"),
		Source:           getString(d, "SOURCE"),
	}
	if tactics, ok := d["MITRE_TACTIC"].([]interface{}); ok {
		for _, t := range tactics {
			if s, ok := t.(string); ok {
				detector.MitreTactic = append(detector.MitreTactic, s)
			}
		}
	}
	if techniques, ok := d["MITRE_TECHNIQUE"].([]interface{}); ok {
		for _, t := range techniques {
			if s, ok := t.(string); ok {
				detector.MitreTechnique = append(detector.MitreTechnique, s)
			}
		}
	}
	return detector
}

// --- FIM Rule Groups ---
// Available on XSIAM only, requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

func (b *Backend) ListFIMRuleGroups() ([]api.FIMRuleGroup, error) {
	if err := b.requireXSIAMWebapp("FIM rule group management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=FILE_INTEGRITY_MONITORING_RULE_GROUPS",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing FIM rule groups: %w", err)
	}
	var groups []api.FIMRuleGroup
	for _, d := range resp.Reply.Data {
		group := api.FIMRuleGroup{
			Name:           getString(d, "NAME"),
			Description:    getString(d, "DESCRIPTION"),
			OSType:         getString(d, "OS_TYPE"),
			MonitoringMode: getString(d, "MONITORING_MODE"),
		}
		if id, ok := d["GROUP_ID"].(float64); ok {
			group.GroupID = int(id)
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (b *Backend) GetFIMRuleGroup(groupID int) (*api.FIMRuleGroup, error) {
	if err := b.requireXSIAMWebapp("FIM rule group management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=FILE_INTEGRITY_MONITORING_RULE_GROUPS",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"filter": map[string]interface{}{
					"AND": []map[string]interface{}{
						{
							"SEARCH_FIELD": "GROUP_ID",
							"SEARCH_TYPE":  "EQ",
							"SEARCH_VALUE": groupID,
						},
					},
				},
				"paging": map[string]int{"from": 0, "to": 1},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing FIM rule group: %w", err)
	}
	if len(resp.Reply.Data) == 0 {
		return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("FIM rule group %d not found", groupID)}
	}
	d := resp.Reply.Data[0]
	group := &api.FIMRuleGroup{
		Name:           getString(d, "NAME"),
		Description:    getString(d, "DESCRIPTION"),
		OSType:         getString(d, "OS_TYPE"),
		MonitoringMode: getString(d, "MONITORING_MODE"),
	}
	if id, ok := d["GROUP_ID"].(float64); ok {
		group.GroupID = int(id)
	}
	return group, nil
}

func (b *Backend) CreateFIMRuleGroup(group map[string]interface{}) (*api.FIMRuleGroup, error) {
	if err := b.requireXSIAMWebapp("FIM rule group creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/fim/create_rule_group/", group)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing FIM rule group create response: %w", err)
	}
	var newGroupID int
	switch v := resp.Reply.(type) {
	case float64:
		newGroupID = int(v)
	case map[string]interface{}:
		if id, ok := v["GROUP_ID"].(float64); ok {
			newGroupID = int(id)
		}
	}
	if newGroupID > 0 {
		return b.GetFIMRuleGroup(newGroupID)
	}
	name, _ := group["NAME"].(string)
	groups, listErr := b.ListFIMRuleGroups()
	if listErr != nil {
		return nil, fmt.Errorf("could not verify FIM rule group creation: %w", listErr)
	}
	for i := range groups {
		if groups[i].Name == name {
			return &groups[i], nil
		}
	}
	return nil, fmt.Errorf("FIM rule group was created but could not be found by name %q", name)
}

func (b *Backend) UpdateFIMRuleGroup(groupID int, group map[string]interface{}) (*api.FIMRuleGroup, error) {
	if err := b.requireXSIAMWebapp("FIM rule group update"); err != nil {
		return nil, err
	}
	group["GROUP_ID"] = groupID
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/fim/update_rule_group/", group)
	if err != nil {
		return nil, err
	}
	return b.GetFIMRuleGroup(groupID)
}

func (b *Backend) DeleteFIMRuleGroup(groupID int) error {
	if err := b.requireXSIAMWebapp("FIM rule group deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/fim/delete_rule_group/",
		map[string]interface{}{"group_ids": []int{groupID}})
	return err
}

// --- FIM Rules ---
// Available on XSIAM only, requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

func (b *Backend) ListFIMRules() ([]api.FIMRule, error) {
	if err := b.requireXSIAMWebapp("FIM rule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=FILE_INTEGRITY_MONITORING_RULES",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing FIM rules: %w", err)
	}
	var rules []api.FIMRule
	for _, d := range resp.Reply.Data {
		rule := api.FIMRule{
			Type:             getString(d, "TYPE"),
			Path:             getString(d, "PATH"),
			Description:      getString(d, "DESCRIPTION"),
			MonitorAllEvents: getBool(d, "MONITOR_ALL_EVENTS"),
		}
		if id, ok := d["RULE_ID"].(float64); ok {
			rule.RuleID = int(id)
		}
		if gid, ok := d["GROUP_ID"].(float64); ok {
			rule.GroupID = int(gid)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (b *Backend) GetFIMRule(ruleID int) (*api.FIMRule, error) {
	if err := b.requireXSIAMWebapp("FIM rule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=FILE_INTEGRITY_MONITORING_RULES",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"filter": map[string]interface{}{
					"AND": []map[string]interface{}{
						{
							"SEARCH_FIELD": "RULE_ID",
							"SEARCH_TYPE":  "EQ",
							"SEARCH_VALUE": ruleID,
						},
					},
				},
				"paging": map[string]int{"from": 0, "to": 1},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing FIM rule: %w", err)
	}
	if len(resp.Reply.Data) == 0 {
		return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("FIM rule %d not found", ruleID)}
	}
	d := resp.Reply.Data[0]
	rule := &api.FIMRule{
		Type:             getString(d, "TYPE"),
		Path:             getString(d, "PATH"),
		Description:      getString(d, "DESCRIPTION"),
		MonitorAllEvents: getBool(d, "MONITOR_ALL_EVENTS"),
	}
	if id, ok := d["RULE_ID"].(float64); ok {
		rule.RuleID = int(id)
	}
	if gid, ok := d["GROUP_ID"].(float64); ok {
		rule.GroupID = int(gid)
	}
	return rule, nil
}

func (b *Backend) CreateFIMRule(rule map[string]interface{}) (*api.FIMRule, error) {
	if err := b.requireXSIAMWebapp("FIM rule creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/fim/create_rule/", rule)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing FIM rule create response: %w", err)
	}
	var newRuleID int
	switch v := resp.Reply.(type) {
	case float64:
		newRuleID = int(v)
	case map[string]interface{}:
		if id, ok := v["RULE_ID"].(float64); ok {
			newRuleID = int(id)
		}
	}
	if newRuleID > 0 {
		return b.GetFIMRule(newRuleID)
	}
	path, _ := rule["PATH"].(string)
	rules, listErr := b.ListFIMRules()
	if listErr != nil {
		return nil, fmt.Errorf("could not verify FIM rule creation: %w", listErr)
	}
	for i := range rules {
		if rules[i].Path == path {
			return &rules[i], nil
		}
	}
	return nil, fmt.Errorf("FIM rule was created but could not be found")
}

func (b *Backend) UpdateFIMRule(ruleID int, rule map[string]interface{}) (*api.FIMRule, error) {
	if err := b.requireXSIAMWebapp("FIM rule update"); err != nil {
		return nil, err
	}
	rule["RULE_ID"] = ruleID
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/fim/update_rule/", rule)
	if err != nil {
		return nil, err
	}
	return b.GetFIMRule(ruleID)
}

func (b *Backend) DeleteFIMRule(ruleID int) error {
	if err := b.requireXSIAMWebapp("FIM rule deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/fim/delete_rule/",
		map[string]interface{}{"rule_ids": []int{ruleID}})
	return err
}

// --- Notification Rules ---
// Available on XSIAM only, requires webapp session.
// Webapp API endpoints based on XSIAM V3.4; may differ on other versions.

func (b *Backend) ListNotificationRules() ([]api.NotificationRule, error) {
	if err := b.requireXSIAMWebapp("notification rule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=ALERT_NOTIFICATION_RULES",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing notification rules: %w", err)
	}
	var rules []api.NotificationRule
	for _, d := range resp.Reply.Data {
		rules = append(rules, parseNotificationRule(d))
	}
	return rules, nil
}

func (b *Backend) GetNotificationRule(ruleID int) (*api.NotificationRule, error) {
	if err := b.requireXSIAMWebapp("notification rule management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=ALERT_NOTIFICATION_RULES",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"filter": map[string]interface{}{
					"AND": []map[string]interface{}{
						{
							"SEARCH_FIELD": "RULE_ID",
							"SEARCH_TYPE":  "EQ",
							"SEARCH_VALUE": ruleID,
						},
					},
				},
				"paging": map[string]int{"from": 0, "to": 1},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing notification rule: %w", err)
	}
	if len(resp.Reply.Data) == 0 {
		return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("notification rule %d not found", ruleID)}
	}
	rule := parseNotificationRule(resp.Reply.Data[0])
	return &rule, nil
}

func (b *Backend) CreateNotificationRule(rule map[string]interface{}) (*api.NotificationRule, error) {
	if err := b.requireXSIAMWebapp("notification rule creation"); err != nil {
		return nil, err
	}
	wrappedRule := map[string]interface{}{
		"rule_info": rule,
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/notifications/rule/create", wrappedRule)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing notification rule create response: %w", err)
	}
	var newRuleID int
	switch v := resp.Reply.(type) {
	case float64:
		newRuleID = int(v)
	case map[string]interface{}:
		if id, ok := v["RULE_ID"].(float64); ok {
			newRuleID = int(id)
		}
	}
	if newRuleID > 0 {
		return b.GetNotificationRule(newRuleID)
	}
	name, _ := rule["name"].(string)
	rules, listErr := b.ListNotificationRules()
	if listErr != nil {
		return nil, fmt.Errorf("could not verify notification rule creation: %w", listErr)
	}
	for i := range rules {
		if rules[i].Name == name {
			return &rules[i], nil
		}
	}
	return nil, fmt.Errorf("notification rule was created but could not be found by name %q", name)
}

func (b *Backend) UpdateNotificationRule(ruleID int, rule map[string]interface{}) (*api.NotificationRule, error) {
	if err := b.requireXSIAMWebapp("notification rule update"); err != nil {
		return nil, err
	}
	rule["rule_id"] = ruleID
	wrappedRule := map[string]interface{}{
		"rule_info": rule,
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/notifications/rule/put", wrappedRule)
	if err != nil {
		return nil, err
	}
	return b.GetNotificationRule(ruleID)
}

func (b *Backend) DeleteNotificationRule(ruleID int) error {
	if err := b.requireXSIAMWebapp("notification rule deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/notifications/rule/delete",
		map[string]interface{}{"rule_id": ruleID})
	return err
}

func parseNotificationRule(d map[string]interface{}) api.NotificationRule {
	rule := api.NotificationRule{
		Name:          getString(d, "NAME"),
		Description:   getString(d, "DESCRIPTION"),
		ForwardType:   getString(d, "FORWARD_TYPE"),
		SyslogEnabled: getBool(d, "SYSLOG_ENABLED"),
		Enabled:       getBool(d, "ENABLED"),
	}
	if id, ok := d["RULE_ID"].(float64); ok {
		rule.RuleID = int(id)
	}
	if agg, ok := d["EMAIL_AGGREGATION"].(float64); ok {
		rule.EmailAggregation = int(agg)
	}
	if f, ok := d["FILTER"]; ok && f != nil {
		if fBytes, err := json.Marshal(f); err == nil {
			rule.Filter = string(fBytes)
		}
	}
	if emails, ok := d["EMAIL_DISTRIBUTION_LIST"].([]interface{}); ok {
		for _, e := range emails {
			if s, ok := e.(string); ok {
				rule.EmailDistributionList = append(rule.EmailDistributionList, s)
			}
		}
	}
	return rule
}

// --- Auto Upgrade Settings ---
// Available on XSIAM only, requires webapp session.

func (b *Backend) GetAutoUpgradeSettings() (*api.AutoUpgradeSettings, error) {
	if err := b.requireXSIAMWebapp("auto upgrade settings"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/scouter_agents/auto_upgrade/get_auto_upgrade_global_settings",
		map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply map[string]interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing auto upgrade settings: %w", err)
	}
	settings := &api.AutoUpgradeSettings{}
	if timeSettings, ok := resp.Reply["TIME_SETTINGS"].(map[string]interface{}); ok {
		if v, ok := timeSettings["START_TIME"].(string); ok {
			settings.StartTime = v
		}
		if v, ok := timeSettings["END_TIME"].(string); ok {
			settings.EndTime = v
		}
		if days, ok := timeSettings["DAYS"].([]interface{}); ok {
			for _, d := range days {
				if s, ok := d.(string); ok {
					settings.Days = append(settings.Days, s)
				}
			}
		}
	}
	if batchSettings, ok := resp.Reply["BATCH_SETTINGS"].(map[string]interface{}); ok {
		settings.BatchSize = getInt(batchSettings, "BATCH_SIZE")
	}
	return settings, nil
}

func (b *Backend) UpdateAutoUpgradeSettings(settings map[string]interface{}) (*api.AutoUpgradeSettings, error) {
	if err := b.requireXSIAMWebapp("auto upgrade settings"); err != nil {
		return nil, err
	}
	wrappedBody := map[string]interface{}{
		"update_data": settings,
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/scouter_agents/auto_upgrade/set_auto_upgrade_global_settings",
		wrappedBody)
	if err != nil {
		return nil, err
	}
	// Try to read back; if GET fails (some XSIAM instances return 500), reconstruct from input
	result, err := b.GetAutoUpgradeSettings()
	if err == nil {
		return result, nil
	}
	// Fallback: reconstruct from the settings we just sent
	fallback := &api.AutoUpgradeSettings{}
	if ts, ok := settings["TIME_SETTINGS"].(map[string]interface{}); ok {
		if v, ok := ts["START_TIME"].(string); ok {
			fallback.StartTime = v
		}
		if v, ok := ts["END_TIME"].(string); ok {
			fallback.EndTime = v
		}
		if days, ok := ts["DAYS"].([]string); ok {
			fallback.Days = days
		}
	}
	if bs, ok := settings["BATCH_SETTINGS"].(map[string]interface{}); ok {
		if v, ok := bs["BATCH_SIZE"].(int64); ok {
			fallback.BatchSize = int(v)
		} else if v, ok := bs["BATCH_SIZE"].(float64); ok {
			fallback.BatchSize = int(v)
		}
	}
	return fallback, nil
}

// --- Parsing Rules ---
// Available on XSIAM only, requires webapp session.
// Uses hash-based optimistic locking.

func (b *Backend) GetParsingRules() (*api.ParsingRules, error) {
	if err := b.requireXSIAMWebapp("parsing rules"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/ingestion/xql/rule_files/user/get",
		map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Text string `json:"text"`
			Hash string `json:"hash"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing parsing rules: %w", err)
	}
	return &api.ParsingRules{
		Text: resp.Reply.Text,
		Hash: resp.Reply.Hash,
	}, nil
}

func (b *Backend) SaveParsingRules(text string, baseHash string) (*api.ParsingRules, error) {
	if err := b.requireXSIAMWebapp("parsing rules"); err != nil {
		return nil, err
	}
	payload := map[string]interface{}{
		"base_hash": baseHash,
		"text":      text,
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/ingestion/xql/rule_files/user/save",
		payload)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			HashMatch bool   `json:"hash_match"`
			Hash      string `json:"hash"`
			Text      string `json:"text"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing save parsing rules response: %w", err)
	}
	if !resp.Reply.HashMatch {
		return nil, fmt.Errorf("parsing rules hash mismatch: rules were modified concurrently; re-run terraform plan")
	}
	return &api.ParsingRules{
		Text: resp.Reply.Text,
		Hash: resp.Reply.Hash,
	}, nil
}

// --- Data Modeling Rules ---
// Available on XSIAM only, requires webapp session.
// Uses hash-based optimistic locking.

func (b *Backend) GetDataModelingRules() (*api.DataModelingRules, error) {
	if err := b.requireXSIAMWebapp("data modeling rules"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/xdm/xql/mappings_files/user/get",
		map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Text       string      `json:"text"`
			Hash       string      `json:"hash"`
			LastUpdate interface{} `json:"last_update"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing data modeling rules: %w", err)
	}
	lastUpdate := fmt.Sprintf("%v", resp.Reply.LastUpdate)
	return &api.DataModelingRules{
		Text:       resp.Reply.Text,
		Hash:       resp.Reply.Hash,
		LastUpdate: lastUpdate,
	}, nil
}

func (b *Backend) SaveDataModelingRules(text string, baseHash string) (*api.DataModelingRules, error) {
	if err := b.requireXSIAMWebapp("data modeling rules"); err != nil {
		return nil, err
	}
	payload := map[string]interface{}{
		"base_hash": baseHash,
		"text":      text,
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/xdm/xql/mappings_files/user/save",
		payload)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			HashMatch bool   `json:"hash_match"`
			Hash      string `json:"hash"`
			Text      string `json:"text"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing save data modeling rules response: %w", err)
	}
	if !resp.Reply.HashMatch {
		return nil, fmt.Errorf("data modeling rules hash mismatch: rules were modified concurrently; re-run terraform plan")
	}
	// Read back to get last_update
	return b.GetDataModelingRules()
}

// --- Collector Groups ---
// Available on XSIAM only, requires webapp session.
// Uses grid data pattern with SCOUTER_AGENT_GROUPS_TABLE.

func (b *Backend) ListCollectorGroups() ([]api.CollectorGroup, error) {
	if err := b.requireXSIAMWebapp("collector group management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=SCOUTER_AGENT_GROUPS_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing collector groups: %w", err)
	}
	var groups []api.CollectorGroup
	for _, d := range resp.Reply.Data {
		groups = append(groups, parseCollectorGroup(d))
	}
	return groups, nil
}

func (b *Backend) GetCollectorGroup(groupID int) (*api.CollectorGroup, error) {
	if err := b.requireXSIAMWebapp("collector group management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=SCOUTER_AGENT_GROUPS_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"filter": map[string]interface{}{
					"AND": []map[string]interface{}{
						{
							"SEARCH_FIELD": "GROUP_ID",
							"SEARCH_TYPE":  "EQ",
							"SEARCH_VALUE": groupID,
						},
					},
				},
				"paging": map[string]int{"from": 0, "to": 1},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing collector group: %w", err)
	}
	if len(resp.Reply.Data) == 0 {
		return nil, &client.APIError{StatusCode: 404, Message: fmt.Sprintf("collector group %d not found", groupID)}
	}
	group := parseCollectorGroup(resp.Reply.Data[0])
	return &group, nil
}

func (b *Backend) CreateCollectorGroup(group map[string]interface{}) (*api.CollectorGroup, error) {
	if err := b.requireXSIAMWebapp("collector group creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/scouter_agents/groups/create_group",
		map[string]interface{}{
			"request_data": group,
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply map[string]interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing collector group create response: %w", err)
	}
	groupID := getInt(resp.Reply, "GROUP_ID")
	if groupID == 0 {
		// Try reading back by name
		name, _ := group["name"].(string)
		groups, listErr := b.ListCollectorGroups()
		if listErr == nil {
			for _, g := range groups {
				if g.Name == name {
					return &g, nil
				}
			}
		}
		return nil, fmt.Errorf("collector group created but could not determine ID: %s", string(body))
	}
	return b.GetCollectorGroup(groupID)
}

func (b *Backend) UpdateCollectorGroup(groupID int, group map[string]interface{}) (*api.CollectorGroup, error) {
	if err := b.requireXSIAMWebapp("collector group update"); err != nil {
		return nil, err
	}
	group["groupId"] = groupID
	lockedFilter := map[string]interface{}{
		"AND": []interface{}{
			map[string]interface{}{
				"SEARCH_FIELD": "AGENT_STATUS",
				"SEARCH_TYPE":  "NEQ",
				"SEARCH_VALUE": "STATUS_050_UNINSTALLED",
			},
		},
	}
	group["locked"] = lockedFilter
	group["lockedFilter"] = lockedFilter
	if _, ok := group["filter"]; !ok {
		group["filter"] = map[string]interface{}{"AND": []interface{}{}}
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/scouter_agents/groups/update_group",
		map[string]interface{}{
			"request_data": group,
		})
	if err != nil {
		return nil, err
	}
	return b.GetCollectorGroup(groupID)
}

func (b *Backend) DeleteCollectorGroup(groupID int) error {
	if err := b.requireXSIAMWebapp("collector group deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/scouter_agents/groups/delete_group",
		map[string]interface{}{
			"request_data": map[string]interface{}{
				"groupId": groupID,
			},
		})
	return err
}

func parseCollectorGroup(d map[string]interface{}) api.CollectorGroup {
	group := api.CollectorGroup{
		Name:        getString(d, "NAME"),
		Description: getString(d, "DESCRIPTION"),
		Type:        getString(d, "TYPE"),
		CreatedBy:   getString(d, "CREATED_BY"),
		ModifiedBy:  getString(d, "MODIFIED_BY"),
	}
	if id, ok := d["GROUP_ID"].(float64); ok {
		group.GroupID = int(id)
	}
	if cnt, ok := d["COUNT"].(float64); ok {
		group.Count = int(cnt)
	}
	if f, ok := d["FILTER"]; ok && f != nil {
		if fBytes, err := json.Marshal(f); err == nil {
			group.Filter = string(fBytes)
		}
	}
	return group
}

// --- Collector Distributions ---
// Available on XSIAM only, requires webapp session.
// Create + Delete only (no update).

func (b *Backend) ListCollectorDistributions() ([]api.CollectorDistribution, error) {
	if err := b.requireXSIAMWebapp("collector distribution management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=SCOUTER_AGENT_DISTRIBUTIONS_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing collector distributions: %w", err)
	}
	var dists []api.CollectorDistribution
	for _, d := range resp.Reply.Data {
		dists = append(dists, api.CollectorDistribution{
			DistributionID: getString(d, "DIST_GUID"),
			Name:           getString(d, "DIST_NAME"),
			Description:    getString(d, "DIST_DESCRIPTION"),
			AgentVersion:   getString(d, "DIST_AGENT_VERSION"),
			Platform:       getString(d, "DIST_PLATFORM"),
			PackageType:    getString(d, "DIST_TYPE"),
			CreatedBy:      getString(d, "DIST_CREATED_BY"),
		})
	}
	return dists, nil
}

func (b *Backend) CreateCollectorDistribution(dist map[string]interface{}) (*api.CollectorDistribution, error) {
	if err := b.requireXSIAMWebapp("collector distribution creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/scouter_agents/distributions/create/",
		dist)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply string `json:"reply"` // UUID
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing collector distribution create response: %w", err)
	}
	distID := resp.Reply
	if distID == "" {
		return nil, fmt.Errorf("collector distribution created but no ID returned: %s", string(body))
	}
	// Read back by listing
	dists, err := b.ListCollectorDistributions()
	if err != nil {
		name, _ := dist["name"].(string)
		return &api.CollectorDistribution{
			DistributionID: distID,
			Name:           name,
		}, nil
	}
	for _, d := range dists {
		if d.DistributionID == distID {
			return &d, nil
		}
	}
	return &api.CollectorDistribution{DistributionID: distID}, nil
}

func (b *Backend) DeleteCollectorDistribution(distributionID string) error {
	if err := b.requireXSIAMWebapp("collector distribution deletion"); err != nil {
		return err
	}
	_, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/scouter_agents/distributions/delete/",
		map[string]interface{}{
			"distribution_id": distributionID,
		})
	return err
}

// --- Collector Profiles ---
// Available on XSIAM only, requires webapp session.
// Create-only (no update/delete API).

func (b *Backend) ListCollectorProfiles() ([]api.CollectorProfile, error) {
	if err := b.requireXSIAMWebapp("collector profile management"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=SCOUTER_AGENT_PROFILES_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	// Profiles grid returns {"reply": [...]} (array directly), not {"reply": {"DATA": [...]}}
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing collector profiles: %w", err)
	}
	var items []map[string]interface{}
	switch reply := raw["reply"].(type) {
	case []interface{}:
		for _, item := range reply {
			if m, ok := item.(map[string]interface{}); ok {
				items = append(items, m)
			}
		}
	case map[string]interface{}:
		if data, ok := reply["DATA"].([]interface{}); ok {
			for _, item := range data {
				if m, ok := item.(map[string]interface{}); ok {
					items = append(items, m)
				}
			}
		}
	}
	var profiles []api.CollectorProfile
	for _, d := range items {
		profile := api.CollectorProfile{
			Name:        getString(d, "PROFILE_NAME"),
			Description: getString(d, "PROFILE_DESCRIPTION"),
			Platform:    getString(d, "PROFILE_PLATFORM"),
			ProfileType: getString(d, "PROFILE_TYPE"),
			IsDefault:   getBool(d, "PROFILE_IS_DEFAULT"),
		}
		if id, ok := d["PROFILE_ID"].(float64); ok {
			profile.ProfileID = int(id)
		}
		if modules, ok := d["PROFILE_MODULES"].(map[string]interface{}); ok {
			if fb, ok := modules["filebeat"].(map[string]interface{}); ok {
				if yaml, ok := fb["yaml"].(map[string]interface{}); ok {
					if v, ok := yaml["value"].(string); ok {
						profile.Modules = v
					}
				}
			}
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func (b *Backend) CreateCollectorProfile(profile map[string]interface{}) (*api.CollectorProfile, error) {
	if err := b.requireXSIAMWebapp("collector profile creation"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/scouter_agents/profiles/add_profile",
		map[string]interface{}{
			"new_profile_data": profile,
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply interface{} `json:"reply"` // profileID (could be float64 or string)
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing collector profile create response: %w", err)
	}
	var profileID int
	switch v := resp.Reply.(type) {
	case float64:
		profileID = int(v)
	}
	// Read back from list
	name, _ := profile["PROFILE_NAME"].(string)
	profiles, err := b.ListCollectorProfiles()
	if err != nil {
		return &api.CollectorProfile{
			ProfileID: profileID,
			Name:      name,
		}, nil
	}
	for _, p := range profiles {
		if p.ProfileID == profileID || (profileID == 0 && p.Name == name) {
			return &p, nil
		}
	}
	return &api.CollectorProfile{ProfileID: profileID, Name: name}, nil
}

// --- Datasets ---
// Available on XSIAM only, requires webapp session.
// Read-only data source.

func (b *Backend) ListDatasets() ([]api.Dataset, error) {
	if err := b.requireXSIAMWebapp("dataset listing"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=DATASET_MANAGEMENT",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing datasets: %w", err)
	}
	var datasets []api.Dataset
	for _, d := range resp.Reply.Data {
		dataset := api.Dataset{
			Name:        getString(d, "DATASET_NAME"),
			Type:        getString(d, "DATASET_TYPE"),
			SourceQuery: getString(d, "SOURCE_QUERY"),
		}
		if id, ok := d["DATASET_ID"].(float64); ok {
			dataset.ID = int(id)
		}
		if size, ok := d["TOTAL_SIZE_BYTES"].(float64); ok {
			dataset.TotalSizeBytes = int64(size)
		}
		if events, ok := d["TOTAL_EVENTS_STORED"].(float64); ok {
			dataset.TotalEventsStored = int64(events)
		}
		datasets = append(datasets, dataset)
	}
	return datasets, nil
}

// --- Broker VMs ---
// Available on XSIAM only, requires webapp session.
// Read-only data source.

func (b *Backend) ListBrokerVMs() ([]api.BrokerVM, error) {
	if err := b.requireXSIAMWebapp("broker VM listing"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/broker/get_devices_for_agents_profiles",
		map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply []map[string]interface{} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing broker VMs: %w", err)
	}
	var vms []api.BrokerVM
	for _, d := range resp.Reply {
		vms = append(vms, api.BrokerVM{
			DeviceID:  getString(d, "device_id"),
			Name:      getString(d, "name"),
			Status:    getString(d, "status"),
			FQDN:      getString(d, "fqdn"),
			IsCluster: getBool(d, "is_cluster"),
		})
	}
	return vms, nil
}

// --- Collector Policies ---
// Available on XSIAM only, requires webapp session.
// Read-only data source.

func (b *Backend) ListCollectorPolicies() ([]api.CollectorPolicy, error) {
	if err := b.requireXSIAMWebapp("collector policy listing"); err != nil {
		return nil, err
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/get_data?type=grid&table_name=SCOUTER_AGENT_POLICY_TABLE",
		map[string]interface{}{
			"filter_data": map[string]interface{}{
				"sort":   []map[string]string{},
				"filter": map[string]interface{}{},
				"paging": map[string]int{"from": 0, "to": 500},
			},
		})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reply struct {
			Data []map[string]interface{} `json:"DATA"`
		} `json:"reply"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing collector policies: %w", err)
	}
	var policies []api.CollectorPolicy
	for _, d := range resp.Reply.Data {
		policy := api.CollectorPolicy{
			ID:        getString(d, "ID"),
			Name:      getString(d, "NAME"),
			Platform:  getString(d, "PLATFORM"),
			IsEnabled: getBool(d, "IS_ENABLED"),
		}
		if priority, ok := d["PRIORITY"].(float64); ok {
			policy.Priority = int(priority)
		}
		if targetID, ok := d["TARGET_ID"].(float64); ok {
			policy.TargetID = int(targetID)
		}
		if standardID, ok := d["STANDARD_ID"].(float64); ok {
			policy.StandardID = int(standardID)
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

// --- ASM Asset Removal ---
// Available on XSIAM only, requires webapp session.
// Fire-and-forget bulk removal.

func (b *Backend) BulkRemoveASMAssets(assets []map[string]string) (*api.ASMAssetRemoval, error) {
	if err := b.requireXSIAMWebapp("ASM asset removal"); err != nil {
		return nil, err
	}
	// Build CSV content
	csv := "AssetType,Asset\n"
	for _, a := range assets {
		csv += a["asset_type"] + "," + a["asset_name"] + "\n"
	}
	body, _, err := b.WebappClient.DoRequest(b.Ctx, "POST",
		"/api/webapp/asm_management/bulk_asset_removals",
		map[string]interface{}{
			"request_data": map[string]interface{}{
				"file_content": csv,
			},
		})
	if err != nil {
		return nil, err
	}
	result := &api.ASMAssetRemoval{}
	// Try to parse response for any details
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err == nil {
		if reply, ok := resp["reply"].(map[string]interface{}); ok {
			if removed, ok := reply["removed_assets"].([]interface{}); ok {
				for _, r := range removed {
					if s, ok := r.(string); ok {
						result.RemovedAssets = append(result.RemovedAssets, s)
					}
				}
			}
			if errors, ok := reply["errors"].([]interface{}); ok {
				for _, e := range errors {
					if s, ok := e.(string); ok {
						result.Errors = append(result.Errors, s)
					}
				}
			}
		}
	}
	// Populate removed assets from input if not returned
	if len(result.RemovedAssets) == 0 && len(result.Errors) == 0 {
		for _, a := range assets {
			result.RemovedAssets = append(result.RemovedAssets, a["asset_type"]+":"+a["asset_name"])
		}
	}
	return result, nil
}

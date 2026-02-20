package v8

import (
	"context"
	"encoding/json"
	"fmt"

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

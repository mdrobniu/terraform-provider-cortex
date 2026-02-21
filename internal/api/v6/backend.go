package v6

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"terraform-provider-cortex/internal/api"
	"terraform-provider-cortex/internal/client"
)

// Backend implements api.XSOARBackend for XSOAR 6.
type Backend struct {
	Client *client.Client
	Ctx    context.Context
}

// NewBackend creates a new V6 backend.
func NewBackend(c *client.Client) *Backend {
	return &Backend{
		Client: c,
		Ctx:    context.Background(),
	}
}

// --- Server ---

func (b *Backend) GetServerInfo() (*api.ServerInfo, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", "/about", nil)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing /about: %w", err)
	}
	info := &api.ServerInfo{
		Version:  getString(resp, "demistoVersion"),
		BuildNum: getString(resp, "buildNum"),
		MajorVer: 6,
	}
	return info, nil
}

func (b *Backend) GetServerConfig() (map[string]interface{}, int, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", "/system/config", nil)
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
	payload := map[string]interface{}{
		"data":  config,
		"version": version,
	}
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", "/system/config", payload)
	return err
}

// --- Marketplace ---

func (b *Backend) ListInstalledPacks() ([]api.Pack, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", "/contentpacks/metadata/installed", nil)
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
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/contentpacks/marketplace/search", payload)
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
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", "/contentpacks/marketplace/install", payload)
	return err
}

func (b *Backend) UninstallPack(id string) error {
	payload := map[string]interface{}{
		"IDs": []string{id},
	}
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", "/contentpacks/installed/delete", payload)
	return err
}

// --- Integration Instances ---

func (b *Backend) ListIntegrationConfigs() ([]api.IntegrationConfig, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/settings/integration/search", map[string]interface{}{
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
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/settings/integration/search", map[string]interface{}{
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
	body, _, err := b.Client.DoRequest(b.Ctx, "PUT", "/settings/integration", instance)
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
	body, _, err := b.Client.DoRequest(b.Ctx, "PUT", "/settings/integration", instance)
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
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", "/settings/integration/delete", payload)
	return err
}

// --- Roles ---

func (b *Backend) ListRoles() ([]api.Role, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", "/roles", nil)
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
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/roles", role)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing role response: %w", err)
	}
	result := &api.Role{
		ID:   getString(resp, "id"),
		Name: getString(resp, "name"),
	}
	if v, ok := resp["version"].(float64); ok {
		result.Version = int(v)
	}
	return result, nil
}

func (b *Backend) DeleteRole(id string) error {
	_, _, err := b.Client.DoRequest(b.Ctx, "DELETE", fmt.Sprintf("/roles/%s", id), nil)
	return err
}

// --- API Keys ---

func (b *Backend) ListAPIKeys() ([]api.APIKeyInfo, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", "/apikeys", nil)
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
	// V6 requires the caller to generate the API key value
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("generating API key: %w", err)
	}
	apiKey := strings.ToUpper(hex.EncodeToString(keyBytes))

	payload := map[string]interface{}{
		"name":   name,
		"apikey": apiKey,
	}
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/apikeys", payload)
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
		Key:  apiKey,
	}, nil
}

func (b *Backend) DeleteAPIKey(id string) error {
	_, _, err := b.Client.DoRequest(b.Ctx, "DELETE", "/apikeys/"+id, nil)
	return err
}

// --- Jobs ---

func (b *Backend) SearchJobs() ([]api.Job, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/jobs/search", map[string]interface{}{
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
	// XSOAR 6 requires a non-empty type field
	if t, ok := job["type"].(string); !ok || t == "" {
		job["type"] = "Unclassified"
	}
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/jobs", job)
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
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/jobs", job)
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
	_, _, err := b.Client.DoRequest(b.Ctx, "DELETE", "/jobs/"+id, nil)
	return err
}

// --- Preprocessing Rules ---

func (b *Backend) GetPreprocessingRules() ([]api.PreprocessingRule, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", "/preprocess/rules", nil)
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
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/preprocess/rule", rule)
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
	body, _, err := b.Client.DoRequest(b.Ctx, "PUT", "/preprocess/rule", rule)
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
	_, _, err := b.Client.DoRequest(b.Ctx, "DELETE", "/preprocess/rule/"+id, nil)
	return err
}

// --- Password Policy ---

func (b *Backend) GetPasswordPolicy() (*api.PasswordPolicy, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", "/settings/password-policy", nil)
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
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", "/settings/password-policy", policy)
	if err != nil {
		return nil, err
	}
	return b.GetPasswordPolicy()
}

// --- HA Groups ---

func (b *Backend) ListHAGroups() ([]api.HAGroup, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", "/ha-group", nil)
	if err != nil {
		return nil, err
	}
	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing HA groups: %w", err)
	}
	var groups []api.HAGroup
	for _, g := range raw {
		group := api.HAGroup{
			ID:                 getString(g, "id"),
			Name:               getString(g, "name"),
			ElasticsearchURL:   getString(g, "elasticsearchAddress"),
			ElasticIndexPrefix: getString(g, "elasticIndexPrefix"),
		}
		if ids, ok := g["accountIds"].([]interface{}); ok {
			for _, id := range ids {
				if s, ok := id.(string); ok {
					group.AccountIDs = append(group.AccountIDs, s)
				}
			}
		}
		if ids, ok := g["hostIds"].([]interface{}); ok {
			for _, id := range ids {
				if s, ok := id.(string); ok {
					group.HostIDs = append(group.HostIDs, s)
				}
			}
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (b *Backend) GetHAGroup(id string) (*api.HAGroup, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", fmt.Sprintf("/ha-group/%s", id), nil)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing HA group: %w", err)
	}
	group := &api.HAGroup{
		ID:                 getString(resp, "id"),
		Name:               getString(resp, "name"),
		ElasticsearchURL:   getString(resp, "elasticsearchAddress"),
		ElasticIndexPrefix: getString(resp, "elasticIndexPrefix"),
	}
	return group, nil
}

func (b *Backend) CreateHAGroup(group map[string]interface{}) (*api.HAGroup, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/ha-group", group)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing HA group response: %w", err)
	}
	return &api.HAGroup{
		ID:   getString(resp, "id"),
		Name: getString(resp, "name"),
	}, nil
}

func (b *Backend) DeleteHAGroup(id string) error {
	_, _, err := b.Client.DoRequest(b.Ctx, "DELETE", fmt.Sprintf("/ha-group/%s", id), nil)
	return err
}

// --- Hosts ---

func (b *Backend) GetHost(name string) (*api.Host, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", fmt.Sprintf("/host/%s", name), nil)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing host: %w", err)
	}
	return &api.Host{
		ID:        getString(resp, "id"),
		Name:      getString(resp, "name"),
		HAGroupID: getString(resp, "hostGroupId"),
		Status:    getString(resp, "status"),
	}, nil
}

func (b *Backend) DeleteHost(id string) error {
	_, _, err := b.Client.DoRequest(b.Ctx, "DELETE", fmt.Sprintf("/host/%s", id), nil)
	return err
}

// --- Accounts ---

func (b *Backend) ListAccounts() ([]api.Account, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", "/accounts", nil)
	if err != nil {
		return nil, err
	}
	var raw []map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing accounts: %w", err)
	}
	var accounts []api.Account
	for _, a := range raw {
		account := api.Account{
			ID:          getString(a, "id"),
			Name:        getString(a, "name"),
			DisplayName: getString(a, "displayName"),
			HostGroupID: getString(a, "hostGroupId"),
			Status:      getString(a, "status"),
		}
		if roles, ok := a["roles"].(map[string]interface{}); ok {
			for _, v := range roles {
				if arr, ok := v.([]interface{}); ok {
					for _, r := range arr {
						if s, ok := r.(string); ok {
							account.Roles = append(account.Roles, s)
						}
					}
				}
			}
		}
		if labels, ok := a["propagationLabels"].([]interface{}); ok {
			for _, l := range labels {
				if s, ok := l.(string); ok {
					account.PropagationLabels = append(account.PropagationLabels, s)
				}
			}
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func (b *Backend) GetAccount(name string) (*api.Account, error) {
	accName := name
	if !strings.HasPrefix(accName, "acc_") {
		accName = "acc_" + name
	}
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", fmt.Sprintf("/account/%s", accName), nil)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing account: %w", err)
	}
	return &api.Account{
		ID:          getString(resp, "id"),
		Name:        getString(resp, "name"),
		DisplayName: getString(resp, "displayName"),
		HostGroupID: getString(resp, "hostGroupId"),
		Status:      getString(resp, "status"),
	}, nil
}

func (b *Backend) CreateAccount(account map[string]interface{}) (*api.Account, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/account", account)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing account response: %w", err)
	}
	return &api.Account{
		ID:   getString(resp, "id"),
		Name: getString(resp, "name"),
	}, nil
}

func (b *Backend) UpdateAccount(name string, update map[string]interface{}) error {
	accName := name
	if !strings.HasPrefix(accName, "acc_") {
		accName = "acc_" + name
	}
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", fmt.Sprintf("/account/%s", accName), update)
	return err
}

func (b *Backend) DeleteAccount(name string) error {
	accName := name
	if !strings.HasPrefix(accName, "acc_") {
		accName = "acc_" + name
	}
	_, _, err := b.Client.DoRequest(b.Ctx, "DELETE", fmt.Sprintf("/account/%s", accName), nil)
	return err
}

// --- Credentials ---

func (b *Backend) ListCredentials() ([]api.Credential, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/settings/credentials", map[string]interface{}{
		"page": 0,
		"size": 500,
	})
	if err != nil {
		return nil, err
	}
	// Response is {"credentials": [...], "total": N}
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
	body, _, err := b.Client.DoRequest(b.Ctx, "PUT", "/settings/credentials", cred)
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
	return b.CreateCredential(cred)
}

func (b *Backend) DeleteCredential(id string) error {
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", "/settings/credentials/delete", map[string]interface{}{
		"id": id,
	})
	return err
}

// --- Exclusion List (Whitelist) ---

func (b *Backend) GetExclusionList() ([]api.ExclusionEntry, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", "/indicators/whitelisted", nil)
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
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/indicators/whitelist/update", entry)
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
	return b.AddExclusion(entry) // Same endpoint handles both create and update
}

func (b *Backend) RemoveExclusion(id string) error {
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", "/indicators/whitelist/remove", map[string]interface{}{
		"data": []string{id},
	})
	return err
}

// --- Backup Config ---

func (b *Backend) GetBackupConfig() (*api.BackupConfig, error) {
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", "/system/backup", nil)
	if err != nil {
		return nil, err
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing backup config: %w", err)
	}
	config := &api.BackupConfig{
		Enabled:      getBool(resp, "enabled"),
		ScheduleCron: getString(resp, "scheduleCron"),
		Path:         getString(resp, "path"),
	}
	if v, ok := resp["retentionDays"].(float64); ok {
		config.RetentionDays = int(v)
	}
	return config, nil
}

func (b *Backend) UpdateBackupConfig(config map[string]interface{}) (*api.BackupConfig, error) {
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", "/system/backup", config)
	if err != nil {
		return nil, err
	}
	return b.GetBackupConfig()
}

// --- External Storage ---
// Not available in XSOAR 6.

func (b *Backend) ListExternalStorage() ([]api.ExternalStorage, error) {
	return nil, fmt.Errorf("external storage management is not available on XSOAR 6")
}

func (b *Backend) CreateExternalStorage(storage map[string]interface{}) (*api.ExternalStorage, error) {
	return nil, fmt.Errorf("external storage management is not available on XSOAR 6")
}

func (b *Backend) UpdateExternalStorage(storage map[string]interface{}) (*api.ExternalStorage, error) {
	return nil, fmt.Errorf("external storage management is not available on XSOAR 6")
}

func (b *Backend) DeleteExternalStorage(storageID string) error {
	return fmt.Errorf("external storage management is not available on XSOAR 6")
}

// --- Backup Schedule ---
// Not available in XSOAR 6 (use backup_config resource instead).

func (b *Backend) ListBackupSchedules() ([]api.BackupSchedule, error) {
	return nil, fmt.Errorf("backup schedule management is not available on XSOAR 6; use backup_config resource instead")
}

func (b *Backend) CreateBackupSchedule(schedule map[string]interface{}) (*api.BackupSchedule, error) {
	return nil, fmt.Errorf("backup schedule management is not available on XSOAR 6; use backup_config resource instead")
}

func (b *Backend) DeleteBackupSchedule(scheduleID string) error {
	return fmt.Errorf("backup schedule management is not available on XSOAR 6; use backup_config resource instead")
}

// --- Security Settings ---
// Not available in XSOAR 6.

func (b *Backend) GetSecuritySettings() (*api.SecuritySettings, error) {
	return nil, fmt.Errorf("security settings management is not available on XSOAR 6")
}

func (b *Backend) UpdateSecuritySettings(settings map[string]interface{}) (*api.SecuritySettings, error) {
	return nil, fmt.Errorf("security settings management is not available on XSOAR 6")
}

// --- Lists ---

func (b *Backend) GetList(name string) (*api.List, error) {
	// Get metadata from /lists to find version
	body, _, err := b.Client.DoRequest(b.Ctx, "GET", "/lists", nil)
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
	dataBody, _, err := b.Client.DoRequestRaw(b.Ctx, "GET", "/lists/download/"+name, nil)
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
	body, _, err := b.Client.DoRequest(b.Ctx, "POST", "/lists/save", list)
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
	_, _, err := b.Client.DoRequest(b.Ctx, "POST", "/lists/delete", map[string]interface{}{
		"id": name,
	})
	return err
}

// --- Correlation Rules ---
// Not available on XSOAR 6.

func (b *Backend) ListCorrelationRules() ([]api.CorrelationRule, error) {
	return nil, fmt.Errorf("correlation rules are not available on XSOAR 6")
}

func (b *Backend) GetCorrelationRule(ruleID int) (*api.CorrelationRule, error) {
	return nil, fmt.Errorf("correlation rules are not available on XSOAR 6")
}

func (b *Backend) CreateCorrelationRule(rule map[string]interface{}) (*api.CorrelationRule, error) {
	return nil, fmt.Errorf("correlation rules are not available on XSOAR 6")
}

func (b *Backend) UpdateCorrelationRule(ruleID int, rule map[string]interface{}) (*api.CorrelationRule, error) {
	return nil, fmt.Errorf("correlation rules are not available on XSOAR 6")
}

func (b *Backend) DeleteCorrelationRule(ruleID int) error {
	return fmt.Errorf("correlation rules are not available on XSOAR 6")
}

// --- IOC Rules ---
// Not available on XSOAR 6.

func (b *Backend) ListIOCRules() ([]api.IOCRule, error) {
	return nil, fmt.Errorf("IOC rules are not available on XSOAR 6")
}

func (b *Backend) GetIOCRule(ruleID int) (*api.IOCRule, error) {
	return nil, fmt.Errorf("IOC rules are not available on XSOAR 6")
}

func (b *Backend) CreateIOCRule(rule map[string]interface{}) (*api.IOCRule, error) {
	return nil, fmt.Errorf("IOC rules are not available on XSOAR 6")
}

func (b *Backend) DeleteIOCRule(ruleID int) error {
	return fmt.Errorf("IOC rules are not available on XSOAR 6")
}

// --- EDL Config ---
// Not available on XSOAR 6.

func (b *Backend) GetEDLConfig() (*api.EDLConfig, error) {
	return nil, fmt.Errorf("EDL configuration is not available on XSOAR 6")
}

func (b *Backend) UpdateEDLConfig(config map[string]interface{}) (*api.EDLConfig, error) {
	return nil, fmt.Errorf("EDL configuration is not available on XSOAR 6")
}

// --- Vulnerability Scan Settings ---
// Not available on XSOAR 6.

func (b *Backend) GetVulnerabilityScanSettings() (*api.VulnerabilityScanSettings, error) {
	return nil, fmt.Errorf("vulnerability scan settings are not available on XSOAR 6")
}

func (b *Backend) UpdateVulnerabilityScanSettings(settings map[string]interface{}) (*api.VulnerabilityScanSettings, error) {
	return nil, fmt.Errorf("vulnerability scan settings are not available on XSOAR 6")
}

// --- Device Control Classes ---
// Not available on XSOAR 6.

func (b *Backend) ListDeviceControlClasses() ([]api.DeviceControlClass, error) {
	return nil, fmt.Errorf("device control classes are not available on XSOAR 6")
}

func (b *Backend) CreateDeviceControlClass(class map[string]interface{}) (*api.DeviceControlClass, error) {
	return nil, fmt.Errorf("device control classes are not available on XSOAR 6")
}

func (b *Backend) DeleteDeviceControlClass(identifier string) error {
	return fmt.Errorf("device control classes are not available on XSOAR 6")
}

// --- Custom Statuses ---
// Not available on XSOAR 6.

func (b *Backend) ListCustomStatuses() ([]api.CustomStatus, error) {
	return nil, fmt.Errorf("custom statuses are not available on XSOAR 6")
}

func (b *Backend) CreateCustomStatus(status map[string]interface{}) (*api.CustomStatus, error) {
	return nil, fmt.Errorf("custom statuses are not available on XSOAR 6")
}

func (b *Backend) DeleteCustomStatus(enumName string) error {
	return fmt.Errorf("custom statuses are not available on XSOAR 6")
}

// --- Agent Groups ---
// Not available on XSOAR 6.

func (b *Backend) ListAgentGroups() ([]api.AgentGroup, error) {
	return nil, fmt.Errorf("agent groups are not available on XSOAR 6")
}

func (b *Backend) GetAgentGroup(groupID int) (*api.AgentGroup, error) {
	return nil, fmt.Errorf("agent groups are not available on XSOAR 6")
}

func (b *Backend) CreateAgentGroup(group map[string]interface{}) (*api.AgentGroup, error) {
	return nil, fmt.Errorf("agent groups are not available on XSOAR 6")
}

func (b *Backend) UpdateAgentGroup(groupID int, group map[string]interface{}) (*api.AgentGroup, error) {
	return nil, fmt.Errorf("agent groups are not available on XSOAR 6")
}

func (b *Backend) DeleteAgentGroup(groupID int) error {
	return fmt.Errorf("agent groups are not available on XSOAR 6")
}

// --- Incident Domains ---
// Not available on XSOAR 6.

func (b *Backend) ListIncidentDomains() ([]api.IncidentDomain, error) {
	return nil, fmt.Errorf("incident domains are not available on XSOAR 6")
}

func (b *Backend) GetIncidentDomain(domainID int) (*api.IncidentDomain, error) {
	return nil, fmt.Errorf("incident domains are not available on XSOAR 6")
}

func (b *Backend) CreateIncidentDomain(domain map[string]interface{}) (*api.IncidentDomain, error) {
	return nil, fmt.Errorf("incident domains are not available on XSOAR 6")
}

func (b *Backend) UpdateIncidentDomain(domainID int, domain map[string]interface{}) (*api.IncidentDomain, error) {
	return nil, fmt.Errorf("incident domains are not available on XSOAR 6")
}

func (b *Backend) DeleteIncidentDomain(domainID int) error {
	return fmt.Errorf("incident domains are not available on XSOAR 6")
}

// --- TIM Rules ---
// Not available on XSOAR 6.

func (b *Backend) ListTIMRules() ([]api.TIMRule, error) {
	return nil, fmt.Errorf("TIM rules are not available on XSOAR 6")
}

func (b *Backend) GetTIMRule(ruleID int) (*api.TIMRule, error) {
	return nil, fmt.Errorf("TIM rules are not available on XSOAR 6")
}

func (b *Backend) CreateTIMRule(rule map[string]interface{}) (*api.TIMRule, error) {
	return nil, fmt.Errorf("TIM rules are not available on XSOAR 6")
}

func (b *Backend) UpdateTIMRule(ruleID int, rule map[string]interface{}) (*api.TIMRule, error) {
	return nil, fmt.Errorf("TIM rules are not available on XSOAR 6")
}

func (b *Backend) DeleteTIMRule(ruleID int) error {
	return fmt.Errorf("TIM rules are not available on XSOAR 6")
}

// --- Attack Surface Rules ---
// Not available on XSOAR 6.

func (b *Backend) ListAttackSurfaceRules() ([]api.AttackSurfaceRule, error) {
	return nil, fmt.Errorf("attack surface rules are not available on XSOAR 6")
}

func (b *Backend) GetAttackSurfaceRule(issueTypeID string) (*api.AttackSurfaceRule, error) {
	return nil, fmt.Errorf("attack surface rules are not available on XSOAR 6")
}

func (b *Backend) UpdateAttackSurfaceRule(issueTypeID string, rule map[string]interface{}) (*api.AttackSurfaceRule, error) {
	return nil, fmt.Errorf("attack surface rules are not available on XSOAR 6")
}

// --- BIOC Rules ---
// Not available on XSOAR 6.

func (b *Backend) ListBIOCRules() ([]api.BIOCRule, error) {
	return nil, fmt.Errorf("BIOC rules are not available on XSOAR 6")
}

func (b *Backend) GetBIOCRule(ruleID int) (*api.BIOCRule, error) {
	return nil, fmt.Errorf("BIOC rules are not available on XSOAR 6")
}

func (b *Backend) CreateBIOCRule(rule map[string]interface{}) (*api.BIOCRule, error) {
	return nil, fmt.Errorf("BIOC rules are not available on XSOAR 6")
}

func (b *Backend) UpdateBIOCRule(ruleID int, rule map[string]interface{}) (*api.BIOCRule, error) {
	return nil, fmt.Errorf("BIOC rules are not available on XSOAR 6")
}

func (b *Backend) DeleteBIOCRule(ruleID int) error {
	return fmt.Errorf("BIOC rules are not available on XSOAR 6")
}

// --- Rules Exceptions ---
// Not available on XSOAR 6.

func (b *Backend) ListRulesExceptions() ([]api.RulesException, error) {
	return nil, fmt.Errorf("rules exceptions are not available on XSOAR 6")
}

func (b *Backend) GetRulesException(ruleID int) (*api.RulesException, error) {
	return nil, fmt.Errorf("rules exceptions are not available on XSOAR 6")
}

func (b *Backend) CreateRulesException(rule map[string]interface{}) (*api.RulesException, error) {
	return nil, fmt.Errorf("rules exceptions are not available on XSOAR 6")
}

func (b *Backend) DeleteRulesException(ruleID int) error {
	return fmt.Errorf("rules exceptions are not available on XSOAR 6")
}

// --- Analytics Detectors ---
// Not available on XSOAR 6.

func (b *Backend) ListAnalyticsDetectors() ([]api.AnalyticsDetector, error) {
	return nil, fmt.Errorf("analytics detectors are not available on XSOAR 6")
}

func (b *Backend) GetAnalyticsDetector(globalRuleID string) (*api.AnalyticsDetector, error) {
	return nil, fmt.Errorf("analytics detectors are not available on XSOAR 6")
}

func (b *Backend) UpdateAnalyticsDetector(globalRuleID string, detector map[string]interface{}) (*api.AnalyticsDetector, error) {
	return nil, fmt.Errorf("analytics detectors are not available on XSOAR 6")
}

// --- FIM Rule Groups ---
// Not available on XSOAR 6.

func (b *Backend) ListFIMRuleGroups() ([]api.FIMRuleGroup, error) {
	return nil, fmt.Errorf("FIM rule groups are not available on XSOAR 6")
}

func (b *Backend) GetFIMRuleGroup(groupID int) (*api.FIMRuleGroup, error) {
	return nil, fmt.Errorf("FIM rule groups are not available on XSOAR 6")
}

func (b *Backend) CreateFIMRuleGroup(group map[string]interface{}) (*api.FIMRuleGroup, error) {
	return nil, fmt.Errorf("FIM rule groups are not available on XSOAR 6")
}

func (b *Backend) UpdateFIMRuleGroup(groupID int, group map[string]interface{}) (*api.FIMRuleGroup, error) {
	return nil, fmt.Errorf("FIM rule groups are not available on XSOAR 6")
}

func (b *Backend) DeleteFIMRuleGroup(groupID int) error {
	return fmt.Errorf("FIM rule groups are not available on XSOAR 6")
}

// --- FIM Rules ---
// Not available on XSOAR 6.

func (b *Backend) ListFIMRules() ([]api.FIMRule, error) {
	return nil, fmt.Errorf("FIM rules are not available on XSOAR 6")
}

func (b *Backend) GetFIMRule(ruleID int) (*api.FIMRule, error) {
	return nil, fmt.Errorf("FIM rules are not available on XSOAR 6")
}

func (b *Backend) CreateFIMRule(rule map[string]interface{}) (*api.FIMRule, error) {
	return nil, fmt.Errorf("FIM rules are not available on XSOAR 6")
}

func (b *Backend) UpdateFIMRule(ruleID int, rule map[string]interface{}) (*api.FIMRule, error) {
	return nil, fmt.Errorf("FIM rules are not available on XSOAR 6")
}

func (b *Backend) DeleteFIMRule(ruleID int) error {
	return fmt.Errorf("FIM rules are not available on XSOAR 6")
}

// --- Notification Rules ---
// Not available on XSOAR 6.

func (b *Backend) ListNotificationRules() ([]api.NotificationRule, error) {
	return nil, fmt.Errorf("notification rules are not available on XSOAR 6")
}

func (b *Backend) GetNotificationRule(ruleID int) (*api.NotificationRule, error) {
	return nil, fmt.Errorf("notification rules are not available on XSOAR 6")
}

func (b *Backend) CreateNotificationRule(rule map[string]interface{}) (*api.NotificationRule, error) {
	return nil, fmt.Errorf("notification rules are not available on XSOAR 6")
}

func (b *Backend) UpdateNotificationRule(ruleID int, rule map[string]interface{}) (*api.NotificationRule, error) {
	return nil, fmt.Errorf("notification rules are not available on XSOAR 6")
}

func (b *Backend) DeleteNotificationRule(ruleID int) error {
	return fmt.Errorf("notification rules are not available on XSOAR 6")
}

// --- Auto Upgrade Settings ---
// Not available on XSOAR 6.

func (b *Backend) GetAutoUpgradeSettings() (*api.AutoUpgradeSettings, error) {
	return nil, fmt.Errorf("auto upgrade settings are not available on XSOAR 6")
}

func (b *Backend) UpdateAutoUpgradeSettings(settings map[string]interface{}) (*api.AutoUpgradeSettings, error) {
	return nil, fmt.Errorf("auto upgrade settings are not available on XSOAR 6")
}

// --- Parsing Rules ---
// Not available on XSOAR 6.

func (b *Backend) GetParsingRules() (*api.ParsingRules, error) {
	return nil, fmt.Errorf("parsing rules are not available on XSOAR 6")
}

func (b *Backend) SaveParsingRules(text string, baseHash string) (*api.ParsingRules, error) {
	return nil, fmt.Errorf("parsing rules are not available on XSOAR 6")
}

// --- Data Modeling Rules ---
// Not available on XSOAR 6.

func (b *Backend) GetDataModelingRules() (*api.DataModelingRules, error) {
	return nil, fmt.Errorf("data modeling rules are not available on XSOAR 6")
}

func (b *Backend) SaveDataModelingRules(text string, baseHash string) (*api.DataModelingRules, error) {
	return nil, fmt.Errorf("data modeling rules are not available on XSOAR 6")
}

// --- Collector Groups ---
// Not available on XSOAR 6.

func (b *Backend) ListCollectorGroups() ([]api.CollectorGroup, error) {
	return nil, fmt.Errorf("collector groups are not available on XSOAR 6")
}

func (b *Backend) GetCollectorGroup(groupID int) (*api.CollectorGroup, error) {
	return nil, fmt.Errorf("collector groups are not available on XSOAR 6")
}

func (b *Backend) CreateCollectorGroup(group map[string]interface{}) (*api.CollectorGroup, error) {
	return nil, fmt.Errorf("collector groups are not available on XSOAR 6")
}

func (b *Backend) UpdateCollectorGroup(groupID int, group map[string]interface{}) (*api.CollectorGroup, error) {
	return nil, fmt.Errorf("collector groups are not available on XSOAR 6")
}

func (b *Backend) DeleteCollectorGroup(groupID int) error {
	return fmt.Errorf("collector groups are not available on XSOAR 6")
}

// --- Collector Distributions ---
// Not available on XSOAR 6.

func (b *Backend) ListCollectorDistributions() ([]api.CollectorDistribution, error) {
	return nil, fmt.Errorf("collector distributions are not available on XSOAR 6")
}

func (b *Backend) CreateCollectorDistribution(dist map[string]interface{}) (*api.CollectorDistribution, error) {
	return nil, fmt.Errorf("collector distributions are not available on XSOAR 6")
}

func (b *Backend) DeleteCollectorDistribution(distributionID string) error {
	return fmt.Errorf("collector distributions are not available on XSOAR 6")
}

// --- Collector Profiles ---
// Not available on XSOAR 6.

func (b *Backend) ListCollectorProfiles() ([]api.CollectorProfile, error) {
	return nil, fmt.Errorf("collector profiles are not available on XSOAR 6")
}

func (b *Backend) CreateCollectorProfile(profile map[string]interface{}) (*api.CollectorProfile, error) {
	return nil, fmt.Errorf("collector profiles are not available on XSOAR 6")
}

// --- Datasets ---
// Not available on XSOAR 6.

func (b *Backend) ListDatasets() ([]api.Dataset, error) {
	return nil, fmt.Errorf("datasets are not available on XSOAR 6")
}

// --- Broker VMs ---
// Not available on XSOAR 6.

func (b *Backend) ListBrokerVMs() ([]api.BrokerVM, error) {
	return nil, fmt.Errorf("broker VMs are not available on XSOAR 6")
}

// --- Collector Policies ---
// Not available on XSOAR 6.

func (b *Backend) ListCollectorPolicies() ([]api.CollectorPolicy, error) {
	return nil, fmt.Errorf("collector policies are not available on XSOAR 6")
}

// --- ASM Asset Removal ---
// Not available on XSOAR 6.

func (b *Backend) BulkRemoveASMAssets(assets []map[string]string) (*api.ASMAssetRemoval, error) {
	return nil, fmt.Errorf("ASM asset removal is not available on XSOAR 6")
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

	// Parse data array (parameters)
	if data, ok := im["data"].([]interface{}); ok {
		for _, d := range data {
			if dm, ok := d.(map[string]interface{}); ok {
				instance.Data = append(instance.Data, dm)
			}
		}
	}

	// Build config map from data
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


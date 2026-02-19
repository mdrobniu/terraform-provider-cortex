package api

// ServerInfo represents XSOAR server information.
type ServerInfo struct {
	Version        string
	MajorVer       int
	BuildNum       string
	DeploymentMode string // "saas", "opp", or "" (V6)
}

// IntegrationConfig represents an available integration type (brand).
type IntegrationConfig struct {
	ID            string
	Name          string
	Display       string
	Category      string
	Configuration []IntegrationParam
}

// IntegrationParam represents a single parameter in an integration configuration.
type IntegrationParam struct {
	Name         string
	Display      string
	DefaultValue string
	Type         int
	Required     bool
	Hidden       bool
	Options      []string
}

// IntegrationInstance represents a configured integration instance.
type IntegrationInstance struct {
	ID                string
	Version           int
	Name              string
	Brand             string
	Category          string
	Enabled           string
	Engine            string
	EngineGroup       string
	PropagationLabels []string
	IncomingMapperID  string
	OutgoingMapperID  string
	MappingID         string
	LogLevel          string
	IsIntegrationScript bool
	CanSample         bool
	Data              []map[string]interface{}
	ConfigMap         map[string]string
}

// Pack represents an installed marketplace pack.
type Pack struct {
	ID             string
	Name           string
	CurrentVersion string
}

// MarketplacePackInfo represents a pack available in the marketplace.
type MarketplacePackInfo struct {
	ID             string
	Name           string
	CurrentVersion string
	Description    string
}

// Role represents a user role with permissions.
type Role struct {
	ID          string
	Version     int
	Name        string
	Permissions map[string][]string
}

// APIKeyInfo represents an API key entry.
type APIKeyInfo struct {
	ID       string
	Name     string
	Key      string
	UserName string
}

// Job represents a scheduled job.
type Job struct {
	ID               string
	Version          int
	Name             string
	PlaybookID       string
	Type             string
	Scheduled        bool
	Cron             string
	Recurrent        bool
	Times            int
	StartDate        string
	EndingDate       string
	EndingType       string
	TimezoneOffset   float64
	Closing          bool
	ShouldTriggerNew bool
	Tags             []string
}

// PreprocessingRule represents a pre-processing rule.
type PreprocessingRule struct {
	ID               string
	Version          int
	Name             string
	Enabled          bool
	Action           string
	ScriptName       string
	NewEventFilters  interface{}
	ExistingEventsFilters interface{}
	LinkTo           string
}

// PasswordPolicy represents the password policy settings.
// Field names match the actual XSOAR API response.
type PasswordPolicy struct {
	ID                     string
	Version                int
	Enabled                bool
	MinPasswordLength      int
	MinLowercaseChars      int
	MinUppercaseChars      int
	MinDigitsOrSymbols     int
	PreventRepetition      bool
	ExpireAfter            int
	MaxFailedLoginAttempts int
	SelfUnlockAfterMinutes int
}

// HAGroup represents a High Availability group.
type HAGroup struct {
	ID                 string
	Name               string
	ElasticsearchURL   string
	ElasticIndexPrefix string
	AccountIDs         []string
	HostIDs            []string
}

// Host represents a server/engine host.
type Host struct {
	ID          string
	Name        string
	HAGroupID   string
	HAGroupName string
	Status      string
}

// Account represents a multi-tenant account.
type Account struct {
	ID                string
	Name              string
	DisplayName       string
	HostGroupID       string
	HostGroupName     string
	Roles             []string
	PropagationLabels []string
	Status            string
}

// Credential represents a stored credential.
type Credential struct {
	ID       string
	Version  int
	Name     string
	User     string
	Password string
	Comment  string
}

// ExclusionEntry represents an entry in the indicator exclusion list (whitelist).
type ExclusionEntry struct {
	ID      string
	Version int
	Value   string
	Type    string // "standard", "CIDR", or "regex"
	Reason  string
}

// BackupConfig represents backup configuration settings.
type BackupConfig struct {
	Enabled       bool
	ScheduleCron  string
	RetentionDays int
	Path          string
}

// ExternalStorage represents an external storage configuration (XSOAR 8 OPP only).
type ExternalStorage struct {
	StorageID         string
	Name              string
	StorageType       string // "nfs", "aws", or "s3compatible"
	ConnectionDetails map[string]string
}

// BackupSchedule represents a backup retention schedule (XSOAR 8 OPP only).
type BackupSchedule struct {
	ScheduleID      string
	StorageID       string
	RetentionPeriod int
	RelativePath    string
	HumanCron       map[string]interface{}
}

// SecuritySettings represents the security/authentication settings (XSOAR 8 OPP only).
type SecuritySettings struct {
	UserLoginExpiration    int64
	AutoLogoutEnabled      bool
	AutoLogoutTime         int64
	DashboardExpiration    int64
	ApprovedIPRanges       []string
	ApprovedDomains        []string
	TimeToInactiveUsers    int64
	InactiveUsersIsEnable  bool
	ApprovedMailingDomains []string
	ExternalIPMonitoring   bool
	LimitAPIAccess         bool
}

// XSOARBackend defines the interface each XSOAR version must implement.
type XSOARBackend interface {
	// Server
	GetServerInfo() (*ServerInfo, error)
	GetServerConfig() (map[string]interface{}, int, error)
	UpdateServerConfig(config map[string]string, version int) error

	// Marketplace
	ListInstalledPacks() ([]Pack, error)
	SearchMarketplacePacks(query string) ([]MarketplacePackInfo, error)
	InstallPacks(packs []Pack) error
	UninstallPack(id string) error

	// Integration Instances
	ListIntegrationConfigs() ([]IntegrationConfig, error)
	SearchIntegrationInstances() ([]IntegrationInstance, error)
	GetIntegrationInstance(name string) (*IntegrationInstance, error)
	CreateIntegrationInstance(instance map[string]interface{}) (*IntegrationInstance, error)
	UpdateIntegrationInstance(instance map[string]interface{}) (*IntegrationInstance, error)
	DeleteIntegrationInstance(id string) error

	// Roles
	ListRoles() ([]Role, error)
	CreateRole(role map[string]interface{}) (*Role, error)
	DeleteRole(id string) error

	// API Keys
	ListAPIKeys() ([]APIKeyInfo, error)
	CreateAPIKey(name string) (*APIKeyInfo, error)
	DeleteAPIKey(id string) error

	// Jobs
	SearchJobs() ([]Job, error)
	CreateJob(job map[string]interface{}) (*Job, error)
	UpdateJob(job map[string]interface{}) (*Job, error)
	DeleteJob(id string) error

	// Preprocessing Rules
	GetPreprocessingRules() ([]PreprocessingRule, error)
	CreatePreprocessingRule(rule map[string]interface{}) (*PreprocessingRule, error)
	UpdatePreprocessingRule(rule map[string]interface{}) (*PreprocessingRule, error)
	DeletePreprocessingRule(id string) error

	// Password Policy
	GetPasswordPolicy() (*PasswordPolicy, error)
	UpdatePasswordPolicy(policy map[string]interface{}) (*PasswordPolicy, error)

	// HA Groups
	ListHAGroups() ([]HAGroup, error)
	GetHAGroup(id string) (*HAGroup, error)
	CreateHAGroup(group map[string]interface{}) (*HAGroup, error)
	DeleteHAGroup(id string) error

	// Hosts
	GetHost(name string) (*Host, error)
	DeleteHost(id string) error

	// Accounts
	ListAccounts() ([]Account, error)
	GetAccount(name string) (*Account, error)
	CreateAccount(account map[string]interface{}) (*Account, error)
	UpdateAccount(name string, update map[string]interface{}) error
	DeleteAccount(name string) error

	// Credentials
	ListCredentials() ([]Credential, error)
	CreateCredential(cred map[string]interface{}) (*Credential, error)
	UpdateCredential(cred map[string]interface{}) (*Credential, error)
	DeleteCredential(id string) error

	// Exclusion List
	GetExclusionList() ([]ExclusionEntry, error)
	AddExclusion(entry map[string]interface{}) (*ExclusionEntry, error)
	UpdateExclusion(entry map[string]interface{}) (*ExclusionEntry, error)
	RemoveExclusion(id string) error

	// Backup Config
	GetBackupConfig() (*BackupConfig, error)
	UpdateBackupConfig(config map[string]interface{}) (*BackupConfig, error)

	// External Storage (XSOAR 8 OPP only, requires session auth)
	ListExternalStorage() ([]ExternalStorage, error)
	CreateExternalStorage(storage map[string]interface{}) (*ExternalStorage, error)
	UpdateExternalStorage(storage map[string]interface{}) (*ExternalStorage, error)
	DeleteExternalStorage(storageID string) error

	// Backup Schedule (XSOAR 8 OPP only, requires session auth)
	ListBackupSchedules() ([]BackupSchedule, error)
	CreateBackupSchedule(schedule map[string]interface{}) (*BackupSchedule, error)
	DeleteBackupSchedule(scheduleID string) error

	// Security Settings (XSOAR 8 OPP only, requires session auth)
	GetSecuritySettings() (*SecuritySettings, error)
	UpdateSecuritySettings(settings map[string]interface{}) (*SecuritySettings, error)
}

package api

// ServerInfo represents XSOAR server information.
type ServerInfo struct {
	Version        string
	MajorVer       int
	BuildNum       string
	DeploymentMode string // "saas", "opp", or "" (V6)
	ProductMode    string // "xsoar", "xsiam", or "" (V6)
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
	HumanCron        map[string]interface{} // XSIAM: {timePeriodType, timePeriod, days}
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

// List represents a stored list (IP lists, CSV tables, JSON config, etc.).
type List struct {
	ID      string
	Version int
	Name    string
	Type    string // "plain_text", "json", "html", "markdown", "css"
	Data    string
}

// CorrelationRule represents a correlation rule (XSIAM/XSOAR 8 SaaS, webapp API).
type CorrelationRule struct {
	RuleID          int
	Name            string
	Description     string
	Severity        string // "SEV_010_INFO", "SEV_020_LOW", "SEV_030_MEDIUM", "SEV_040_HIGH", "SEV_050_CRITICAL"
	Status          string // "ENABLED", "DISABLED"
	XQLQuery        string
	ExecutionMode   string // "SCHEDULED", "REALTIME"
	SearchWindow    string // "1 hours", "30 minutes", etc.
	SimpleSchedule  string // "10 minutes", "1 hours", etc.
	Dataset         string // "alerts", etc.
	Timezone        string
	AlertDomain     string // "DOMAIN_SECURITY", etc.
	AlertCategory   string // "INFILTRATION", etc.
	AlertName       string
	MappingStrategy string // "AUTO", "MANUAL"
	Action          string // "ALERTS"
}

// IOCRule represents an IOC (Indicator of Compromise) rule (XSIAM, webapp API).
type IOCRule struct {
	RuleID        int
	Severity      string // "SEV_010_INFO", "SEV_020_LOW", etc.
	Indicator     string
	IOCType       string // "IP", "DOMAIN_NAME", "HASH", "PATH", "FILENAME", "EMAIL_ADDRESS", "URL"
	Comment       string
	Status        string // "ENABLED", "DISABLED"
	IsDefaultTTL  bool
	TTL           int  // -1 = never expires
	Reputation    string
	Reliability   string
}

// EDLConfig represents the External Dynamic List configuration (XSIAM, singleton).
type EDLConfig struct {
	Enabled   bool
	Username  string
	Password  string
	URLIP     string
	URLDomain string
}

// VulnerabilityScanSettings represents vulnerability scan settings (XSIAM, singleton).
type VulnerabilityScanSettings struct {
	EULAAccepted          bool
	NewTestsEnabled       bool
	PauseTesting          bool
	RunTestsOnAllServices bool
	IntrusiveLevel        int
	TargetFilter          string
}

// DeviceControlClass represents a user-defined device control class (XSIAM).
type DeviceControlClass struct {
	Identifier string
	Type       string
}

// CustomStatus represents a custom alert/incident status (XSIAM).
type CustomStatus struct {
	EnumName   string
	PrettyName string
	Priority   int
	StatusType string // "status" or "resolution"
	CanDelete  bool
	CanReorder bool
}

// CustomStatusesResponse holds the full response from get_statuses, including the hash needed for updates.
type CustomStatusesResponse struct {
	Statuses           []CustomStatus
	ResolutionStatuses []CustomStatus
	CustomStatusHash   string
}

// AgentGroup represents an endpoint agent group (XSIAM).
type AgentGroup struct {
	GroupID     int
	Name        string
	Description string
	Type        string // "DYNAMIC" or "STATIC"
	Filter      string // JSON filter for dynamic groups
	Count       int
}

// IncidentDomain represents an incident domain/category (XSIAM).
type IncidentDomain struct {
	DomainID         int
	Name             string
	PrettyName       string
	Color            string
	Description      string
	IsDefault        bool
	Statuses         []string
	ResolvedStatuses []string
}

// TIMRule represents a Threat Intelligence Management rule (XSIAM).
type TIMRule struct {
	RuleID      int
	Name        string
	Type        string // "DETECTION"
	Severity    string
	Status      string // "ENABLED", "DISABLED"
	Description string
	Target      string // JSON filter/indicator values
}

// AttackSurfaceRule represents an attack surface management rule (XSIAM, system-defined).
type AttackSurfaceRule struct {
	IssueTypeID   string
	IssueTypeName string
	EnabledStatus string // "Enabled", "Disabled"
	Priority      string // "High", "Medium", "Low"
	Description   string
}

// BIOCRule represents a Behavioral Indicator of Compromise rule (XSIAM).
type BIOCRule struct {
	RuleID        int
	Name          string
	Severity      string
	Status        string // "ENABLED", "DISABLED"
	Category      string // "COLLECTION", "MALWARE", etc.
	Comment       string
	Source        string // "User" or "Palo Alto Networks"
	IsXQL         bool
	MitreTactic   []string
	MitreTechnique []string
	IndicatorText string // JSON complex filter
}

// RulesException represents an exception to detection rules (XSIAM).
type RulesException struct {
	RuleID      int
	Name        string
	Description string
	Status      string
	AlertID     string
	Filter      string // JSON filter
}

// AnalyticsDetector represents an analytics detection rule (XSIAM, system-defined).
type AnalyticsDetector struct {
	GlobalRuleID     string
	Name             string
	Description      string
	Severity         string
	Status           string // "ENABLED", "DISABLED"
	OriginalSeverity string
	Source           string // "Palo Alto Networks"
	MitreTactic      []string
	MitreTechnique   []string
}

// FIMRuleGroup represents a File Integrity Monitoring rule group (XSIAM).
type FIMRuleGroup struct {
	GroupID        int
	Name           string
	Description    string
	OSType         string // "WINDOWS", "LINUX", "MACOS"
	MonitoringMode string
}

// FIMRule represents a File Integrity Monitoring rule (XSIAM).
type FIMRule struct {
	RuleID           int
	Type             string // "FILE", "REGISTRY"
	Path             string
	Description      string
	GroupID          int
	MonitorAllEvents bool
}

// NotificationRule represents an alert notification/forwarding rule (XSIAM).
type NotificationRule struct {
	RuleID                int
	Name                  string
	Description           string
	ForwardType           string // "Alert", "Audit", etc.
	Filter                string // JSON alert filter
	EmailDistributionList []string
	EmailAggregation      int
	SyslogEnabled         bool
	Enabled               bool
}

// AutoUpgradeSettings represents the auto-upgrade global settings for XDR collectors (XSIAM).
type AutoUpgradeSettings struct {
	StartTime string   // upgrade window start (e.g. "02:00"), empty = anytime
	EndTime   string   // upgrade window end
	Days      []string // days of week, nil = all days
	BatchSize int      // agents per batch
}

// ParsingRules represents the user-defined parsing rules text and hash (XSIAM, singleton).
type ParsingRules struct {
	Text string
	Hash string
}

// DataModelingRules represents the user-defined data modeling rules text and hash (XSIAM, singleton).
type DataModelingRules struct {
	Text       string
	Hash       string
	LastUpdate string
}

// CollectorGroup represents an XDR collector group (XSIAM, SCOUTER_AGENT_GROUPS_TABLE).
type CollectorGroup struct {
	GroupID     int
	Name        string
	Description string
	Type        string // "STATIC" or "DYNAMIC"
	Filter      string // JSON filter for group membership
	Count       int
	CreatedBy   string
	ModifiedBy  string
}

// CollectorDistribution represents an XDR collector distribution package (XSIAM).
type CollectorDistribution struct {
	DistributionID string // UUID
	Name           string
	Description    string
	AgentVersion   string
	Platform       string // "AGENT_OS_WINDOWS", "AGENT_OS_LINUX"
	PackageType    string // "SCOUTER_INSTALLER"
	CreatedBy      string
}

// CollectorProfile represents an XDR collector profile (XSIAM).
type CollectorProfile struct {
	ProfileID   int
	Name        string
	Description string
	Platform    string // "AGENT_OS_WINDOWS", "AGENT_OS_LINUX"
	ProfileType string // "STANDARD"
	IsDefault   bool
	Modules     string // base64-encoded YAML
}

// Dataset represents a dataset in XSIAM (read-only, for data source).
type Dataset struct {
	ID                int
	Name              string
	Type              string // SYSTEM, LOOKUP, RAW, USER, SNAPSHOT, CORRELATION, SYSTEM_AUDIT
	TotalSizeBytes    int64
	TotalEventsStored int64
	SourceQuery       string
}

// BrokerVM represents a broker VM device in XSIAM (read-only, for data source).
type BrokerVM struct {
	DeviceID  string
	Name      string
	Status    string
	FQDN      string
	IsCluster bool
}

// CollectorPolicy represents a collector policy in XSIAM (read-only, for data source).
type CollectorPolicy struct {
	ID         string
	Name       string
	Platform   string
	Priority   int
	IsEnabled  bool
	TargetID   int
	StandardID int
}

// ASMAssetRemoval represents the result of a bulk ASM asset removal (XSIAM).
type ASMAssetRemoval struct {
	RemovedAssets []string
	Errors        []string
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

	// Lists
	GetList(name string) (*List, error)
	CreateList(list map[string]interface{}) (*List, error)
	UpdateList(list map[string]interface{}) (*List, error)
	DeleteList(name string) error

	// Correlation Rules (XSIAM/XSOAR 8 SaaS, requires webapp session)
	ListCorrelationRules() ([]CorrelationRule, error)
	GetCorrelationRule(ruleID int) (*CorrelationRule, error)
	CreateCorrelationRule(rule map[string]interface{}) (*CorrelationRule, error)
	UpdateCorrelationRule(ruleID int, rule map[string]interface{}) (*CorrelationRule, error)
	DeleteCorrelationRule(ruleID int) error

	// IOC Rules (XSIAM, requires webapp session)
	ListIOCRules() ([]IOCRule, error)
	GetIOCRule(ruleID int) (*IOCRule, error)
	CreateIOCRule(rule map[string]interface{}) (*IOCRule, error)
	DeleteIOCRule(ruleID int) error

	// EDL Config (XSIAM, singleton, requires webapp session)
	GetEDLConfig() (*EDLConfig, error)
	UpdateEDLConfig(config map[string]interface{}) (*EDLConfig, error)

	// Vulnerability Scan Settings (XSIAM, singleton, requires webapp session)
	GetVulnerabilityScanSettings() (*VulnerabilityScanSettings, error)
	UpdateVulnerabilityScanSettings(settings map[string]interface{}) (*VulnerabilityScanSettings, error)

	// Device Control Classes (XSIAM, requires webapp session)
	ListDeviceControlClasses() ([]DeviceControlClass, error)
	CreateDeviceControlClass(class map[string]interface{}) (*DeviceControlClass, error)
	DeleteDeviceControlClass(identifier string) error

	// Custom Statuses (XSIAM, requires webapp session)
	ListCustomStatuses() ([]CustomStatus, error)
	CreateCustomStatus(status map[string]interface{}) (*CustomStatus, error)
	DeleteCustomStatus(enumName string) error

	// Agent Groups (XSIAM, requires webapp session)
	ListAgentGroups() ([]AgentGroup, error)
	GetAgentGroup(groupID int) (*AgentGroup, error)
	CreateAgentGroup(group map[string]interface{}) (*AgentGroup, error)
	UpdateAgentGroup(groupID int, group map[string]interface{}) (*AgentGroup, error)
	DeleteAgentGroup(groupID int) error

	// Incident Domains (XSIAM, requires webapp session)
	ListIncidentDomains() ([]IncidentDomain, error)
	GetIncidentDomain(domainID int) (*IncidentDomain, error)
	CreateIncidentDomain(domain map[string]interface{}) (*IncidentDomain, error)
	UpdateIncidentDomain(domainID int, domain map[string]interface{}) (*IncidentDomain, error)
	DeleteIncidentDomain(domainID int) error

	// TIM Rules (XSIAM, requires webapp session)
	ListTIMRules() ([]TIMRule, error)
	GetTIMRule(ruleID int) (*TIMRule, error)
	CreateTIMRule(rule map[string]interface{}) (*TIMRule, error)
	UpdateTIMRule(ruleID int, rule map[string]interface{}) (*TIMRule, error)
	DeleteTIMRule(ruleID int) error

	// Attack Surface Rules (XSIAM, system-defined, requires webapp session)
	ListAttackSurfaceRules() ([]AttackSurfaceRule, error)
	GetAttackSurfaceRule(issueTypeID string) (*AttackSurfaceRule, error)
	UpdateAttackSurfaceRule(issueTypeID string, rule map[string]interface{}) (*AttackSurfaceRule, error)

	// BIOC Rules (XSIAM, requires webapp session)
	ListBIOCRules() ([]BIOCRule, error)
	GetBIOCRule(ruleID int) (*BIOCRule, error)
	CreateBIOCRule(rule map[string]interface{}) (*BIOCRule, error)
	UpdateBIOCRule(ruleID int, rule map[string]interface{}) (*BIOCRule, error)
	DeleteBIOCRule(ruleID int) error

	// Rules Exceptions (XSIAM, requires webapp session)
	ListRulesExceptions() ([]RulesException, error)
	GetRulesException(ruleID int) (*RulesException, error)
	CreateRulesException(rule map[string]interface{}) (*RulesException, error)
	DeleteRulesException(ruleID int) error

	// Analytics Detectors (XSIAM, system-defined, requires webapp session)
	ListAnalyticsDetectors() ([]AnalyticsDetector, error)
	GetAnalyticsDetector(globalRuleID string) (*AnalyticsDetector, error)
	UpdateAnalyticsDetector(globalRuleID string, detector map[string]interface{}) (*AnalyticsDetector, error)

	// FIM Rule Groups (XSIAM, requires webapp session)
	ListFIMRuleGroups() ([]FIMRuleGroup, error)
	GetFIMRuleGroup(groupID int) (*FIMRuleGroup, error)
	CreateFIMRuleGroup(group map[string]interface{}) (*FIMRuleGroup, error)
	UpdateFIMRuleGroup(groupID int, group map[string]interface{}) (*FIMRuleGroup, error)
	DeleteFIMRuleGroup(groupID int) error

	// FIM Rules (XSIAM, requires webapp session)
	ListFIMRules() ([]FIMRule, error)
	GetFIMRule(ruleID int) (*FIMRule, error)
	CreateFIMRule(rule map[string]interface{}) (*FIMRule, error)
	UpdateFIMRule(ruleID int, rule map[string]interface{}) (*FIMRule, error)
	DeleteFIMRule(ruleID int) error

	// Notification Rules (XSIAM, requires webapp session)
	ListNotificationRules() ([]NotificationRule, error)
	GetNotificationRule(ruleID int) (*NotificationRule, error)
	CreateNotificationRule(rule map[string]interface{}) (*NotificationRule, error)
	UpdateNotificationRule(ruleID int, rule map[string]interface{}) (*NotificationRule, error)
	DeleteNotificationRule(ruleID int) error

	// Auto Upgrade Settings (XSIAM, singleton, requires webapp session)
	GetAutoUpgradeSettings() (*AutoUpgradeSettings, error)
	UpdateAutoUpgradeSettings(settings map[string]interface{}) (*AutoUpgradeSettings, error)

	// Parsing Rules (XSIAM, singleton, hash-based optimistic lock, requires webapp session)
	GetParsingRules() (*ParsingRules, error)
	SaveParsingRules(text string, baseHash string) (*ParsingRules, error)

	// Data Modeling Rules (XSIAM, singleton, hash-based optimistic lock, requires webapp session)
	GetDataModelingRules() (*DataModelingRules, error)
	SaveDataModelingRules(text string, baseHash string) (*DataModelingRules, error)

	// Collector Groups (XSIAM, requires webapp session)
	ListCollectorGroups() ([]CollectorGroup, error)
	GetCollectorGroup(groupID int) (*CollectorGroup, error)
	CreateCollectorGroup(group map[string]interface{}) (*CollectorGroup, error)
	UpdateCollectorGroup(groupID int, group map[string]interface{}) (*CollectorGroup, error)
	DeleteCollectorGroup(groupID int) error

	// Collector Distributions (XSIAM, create+delete, requires webapp session)
	ListCollectorDistributions() ([]CollectorDistribution, error)
	CreateCollectorDistribution(dist map[string]interface{}) (*CollectorDistribution, error)
	DeleteCollectorDistribution(distributionID string) error

	// Collector Profiles (XSIAM, create-only, requires webapp session)
	ListCollectorProfiles() ([]CollectorProfile, error)
	CreateCollectorProfile(profile map[string]interface{}) (*CollectorProfile, error)

	// Datasets (XSIAM, read-only data source, requires webapp session)
	ListDatasets() ([]Dataset, error)

	// Broker VMs (XSIAM, read-only data source, requires webapp session)
	ListBrokerVMs() ([]BrokerVM, error)

	// Collector Policies (XSIAM, read-only data source, requires webapp session)
	ListCollectorPolicies() ([]CollectorPolicy, error)

	// ASM Asset Removal (XSIAM, fire-and-forget, requires webapp session)
	BulkRemoveASMAssets(assets []map[string]string) (*ASMAssetRemoval, error)
}

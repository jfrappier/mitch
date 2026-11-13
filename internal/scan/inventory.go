// Package scan reads a Vault cluster and builds an Inventory: a snapshot of
// its mounts, auth methods, plugins, policies, configuration and namespaces.
//
// The scan is read-only and never reads secret values.
package scan

import (
	"encoding/json"
	"time"
)

// Inventory is everything one scan found. It is what "mitch scan" prints as JSON.
type Inventory struct {
	// MitchVersion is the version of Mitch that ran the scan.
	MitchVersion string `json:"mitch_version"`

	// StartedAt and FinishedAt are when the scan ran, in UTC.
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`

	// VaultAddress is the Vault URL that was scanned.
	VaultAddress string `json:"vault_address"`

	// Health is the cluster's version, edition and seal status.
	Health Health `json:"health"`

	// SudoRequested is true when the scan ran with --sudo.
	SudoRequested bool `json:"sudo_requested"`

	// Preflight lists every grant the token was checked for, and the result.
	Preflight []PreflightResult `json:"preflight"`

	// Config is the sanitized server configuration, exactly as Vault returned it.
	Config json.RawMessage `json:"config,omitempty"`

	// VersionHistory lists every Vault version this cluster has run.
	VersionHistory []VersionHistoryEntry `json:"version_history"`

	// Plugins lists every plugin in the catalog.
	Plugins []Plugin `json:"plugins"`

	// PluginRuntimes lists container runtimes for plugins (only with --sudo).
	// null means "not collected"; an empty list means "collected, none found".
	PluginRuntimes []json.RawMessage `json:"plugin_runtimes"`

	// AuditDevices lists audit devices (only with --sudo).
	// null means "not collected"; an empty list means "collected, none found".
	AuditDevices []AuditDevice `json:"audit_devices"`

	// Namespaces holds the per-namespace results. The first entry is always
	// the root namespace, with path "".
	Namespaces []NamespaceInventory `json:"namespaces"`

	// Skipped lists checks that could not run, with the reason. A non-empty
	// list makes "mitch scan" exit with code 5 (partial scan).
	Skipped []SkippedCheck `json:"skipped"`

	// NotRequested lists checks that were left out on purpose, such as sudo
	// checks without --sudo. These do not change the exit code.
	NotRequested []NotRequestedCheck `json:"not_requested"`
}

// Health is the result of GET sys/health.
// Docs: https://developer.hashicorp.com/vault/api-docs/system/health
type Health struct {
	Version     string `json:"version"`
	Enterprise  bool   `json:"enterprise"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Standby     bool   `json:"standby"`
	ClusterName string `json:"cluster_name"`
	ClusterID   string `json:"cluster_id"`
}

// PreflightResult says whether the token has the grant one check needs.
type PreflightResult struct {
	Check     string   `json:"check"`
	Namespace string   `json:"namespace"`
	Path      string   `json:"path"`
	Required  []string `json:"required"`
	Granted   []string `json:"granted"`
	Allowed   bool     `json:"allowed"`
}

// VersionHistoryEntry is one Vault version from LIST sys/version-history.
// Docs: https://developer.hashicorp.com/vault/api-docs/system/version-history
type VersionHistoryEntry struct {
	Version            string `json:"version"`
	BuildDate          string `json:"build_date"`
	PreviousVersion    string `json:"previous_version"`
	TimestampInstalled string `json:"timestamp_installed"`
}

// Plugin is one entry from GET sys/plugins/catalog ("detailed" list).
// Docs: https://developer.hashicorp.com/vault/api-docs/system/plugins-catalog
type Plugin struct {
	Name              string `json:"name"`
	Type              string `json:"type"`
	Version           string `json:"version"`
	Builtin           bool   `json:"builtin"`
	DeprecationStatus string `json:"deprecation_status,omitempty"`
	OCIImage          string `json:"oci_image,omitempty"`
	Runtime           string `json:"runtime,omitempty"`

	// The fields below come from the sudo-only plugin detail read, and are
	// only filled for registered (not built-in) plugins when run with --sudo.
	SHA256  string   `json:"sha256,omitempty"`
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
}

// AuditDevice is one entry from GET sys/audit.
// Docs: https://developer.hashicorp.com/vault/api-docs/system/audit
type AuditDevice struct {
	Path        string            `json:"path"`
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Local       bool              `json:"local"`
	Options     map[string]string `json:"options"`
}

// NamespaceInventory holds what Mitch found in one namespace.
type NamespaceInventory struct {
	// Path is the full namespace path, such as "team-a/". Root is "".
	Path string `json:"path"`

	SecretsEngines []Mount  `json:"secrets_engines"`
	AuthMethods    []Mount  `json:"auth_methods"`
	ACLPolicies    []Policy `json:"acl_policies"`
}

// Mount is one secrets engine or auth method, from GET sys/mounts or GET sys/auth.
// Docs: https://developer.hashicorp.com/vault/api-docs/system/mounts
type Mount struct {
	Path                  string            `json:"path"`
	Type                  string            `json:"type"`
	Description           string            `json:"description"`
	Accessor              string            `json:"accessor"`
	UUID                  string            `json:"uuid"`
	Local                 bool              `json:"local"`
	SealWrap              bool              `json:"seal_wrap"`
	ExternalEntropyAccess bool              `json:"external_entropy_access"`
	Options               map[string]string `json:"options"`
	Config                MountConfig       `json:"config"`
	PluginVersion         string            `json:"plugin_version"`
	RunningPluginVersion  string            `json:"running_plugin_version"`
	RunningSHA256         string            `json:"running_sha256"`
	DeprecationStatus     string            `json:"deprecation_status,omitempty"`
}

// MountConfig is the "config" object of a mount. TTLs are in seconds.
type MountConfig struct {
	DefaultLeaseTTL int64  `json:"default_lease_ttl"`
	MaxLeaseTTL     int64  `json:"max_lease_ttl"`
	ForceNoCache    bool   `json:"force_no_cache"`
	TokenType       string `json:"token_type,omitempty"`
}

// Policy is one ACL policy and its HCL text.
// Docs: https://developer.hashicorp.com/vault/api-docs/system/policies
type Policy struct {
	Name string `json:"name"`
	Text string `json:"policy"`
}

// SkippedCheck is a check that could not run.
type SkippedCheck struct {
	Check     string `json:"check"`
	Namespace string `json:"namespace"`
	Path      string `json:"path"`

	// HTTPStatus is Vault's status code, or 0 when the check was skipped
	// because preflight showed the token lacks the grant.
	HTTPStatus int `json:"http_status"`

	Reason   string `json:"reason"`
	NextStep string `json:"next_step"`
}

// NotRequestedCheck is a check left out on purpose.
type NotRequestedCheck struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// Package checks lists every Vault endpoint Mitch calls and the exact
// permission each one needs.
//
// This list is the single source of truth for three things:
//
//  1. The preflight check, which asks Vault whether the token has each grant.
//  2. The "mitch policy" command, which prints the Vault policies to attach.
//  3. The docs, which describe the same policies.
//
// If Mitch starts calling a new endpoint, add it here first.
package checks

// Names of every check. They appear in logs, in the scan output, and in the
// list of skipped checks.
const (
	CheckOwnCapabilities = "own_capabilities"
	CheckMounts          = "secrets_engines"
	CheckAuthMethods     = "auth_methods"
	CheckPolicyList      = "acl_policy_list"
	CheckPolicyRead      = "acl_policy_read"
	CheckPlugins         = "plugin_catalog"
	CheckConfig          = "server_config"
	CheckVersionHistory  = "version_history"
	CheckNamespaces      = "namespaces"
	CheckAuditDevices    = "audit_devices"
	CheckPluginDetails   = "plugin_details"
	CheckPluginRuntimes  = "plugin_runtimes"
)

// Check is one thing Mitch reads from Vault, and the grant it needs.
type Check struct {
	// Name identifies the check, for example "secrets_engines".
	Name string

	// Description says in plain words what the check reads.
	Description string

	// PolicyPath is the path as written in the Vault policy. It may end in
	// a "*" glob when Mitch reads many paths under it.
	PolicyPath string

	// ProbePath is a concrete path Mitch asks sys/capabilities-self about
	// during preflight. For a glob PolicyPath it is an example path that the
	// glob covers.
	ProbePath string

	// Capabilities are the policy capabilities required, for example ["read"].
	Capabilities []string

	// RootNamespaceOnly is true for endpoints Vault only serves from the
	// root namespace.
	RootNamespaceOnly bool

	// EnterpriseOnly is true for endpoints that only exist in Vault Enterprise.
	EnterpriseOnly bool

	// NeedsSudo is true for endpoints that require the sudo capability.
	// These only run when the user passes --sudo.
	NeedsSudo bool

	// DocsURL links to the Vault API docs for the endpoint.
	DocsURL string
}

// All returns every check in the order Mitch runs them.
//
// Sudo and root-namespace requirements come from the linked HashiCorp API
// docs, checked against Vault 1.19.x and 2.x.
func All() []Check {
	return []Check{
		{
			Name:         CheckOwnCapabilities,
			Description:  "check which of these grants the token has (preflight)",
			PolicyPath:   "sys/capabilities-self",
			ProbePath:    "sys/capabilities-self",
			Capabilities: []string{"update"},
			DocsURL:      "https://developer.hashicorp.com/vault/api-docs/system/capabilities-self",
		},
		{
			Name:         CheckMounts,
			Description:  "list secrets engine mounts and their settings",
			PolicyPath:   "sys/mounts",
			ProbePath:    "sys/mounts",
			Capabilities: []string{"read"},
			DocsURL:      "https://developer.hashicorp.com/vault/api-docs/system/mounts",
		},
		{
			Name:         CheckAuthMethods,
			Description:  "list auth method mounts and their settings",
			PolicyPath:   "sys/auth",
			ProbePath:    "sys/auth",
			Capabilities: []string{"read"},
			DocsURL:      "https://developer.hashicorp.com/vault/api-docs/system/auth",
		},
		{
			Name:         CheckPolicyList,
			Description:  "list ACL policy names",
			PolicyPath:   "sys/policies/acl",
			ProbePath:    "sys/policies/acl",
			Capabilities: []string{"list"},
			DocsURL:      "https://developer.hashicorp.com/vault/api-docs/system/policies",
		},
		{
			Name:         CheckPolicyRead,
			Description:  "read the text of each ACL policy",
			PolicyPath:   "sys/policies/acl/*",
			ProbePath:    "sys/policies/acl/default",
			Capabilities: []string{"read"},
			DocsURL:      "https://developer.hashicorp.com/vault/api-docs/system/policies",
		},
		{
			Name:              CheckPlugins,
			Description:       "list plugins and whether each is built in or registered",
			PolicyPath:        "sys/plugins/catalog",
			ProbePath:         "sys/plugins/catalog",
			Capabilities:      []string{"read"},
			RootNamespaceOnly: true,
			DocsURL:           "https://developer.hashicorp.com/vault/api-docs/system/plugins-catalog",
		},
		{
			Name:              CheckConfig,
			Description:       "read the server configuration with sensitive fields removed",
			PolicyPath:        "sys/config/state/sanitized",
			ProbePath:         "sys/config/state/sanitized",
			Capabilities:      []string{"read"},
			RootNamespaceOnly: true,
			DocsURL:           "https://developer.hashicorp.com/vault/api-docs/system/config-state",
		},
		{
			Name:              CheckVersionHistory,
			Description:       "list the Vault versions this cluster has run",
			PolicyPath:        "sys/version-history",
			ProbePath:         "sys/version-history",
			Capabilities:      []string{"list"},
			RootNamespaceOnly: true,
			DocsURL:           "https://developer.hashicorp.com/vault/api-docs/system/version-history",
		},
		{
			Name:           CheckNamespaces,
			Description:    "list child namespaces",
			PolicyPath:     "sys/namespaces",
			ProbePath:      "sys/namespaces",
			Capabilities:   []string{"list"},
			EnterpriseOnly: true,
			DocsURL:        "https://developer.hashicorp.com/vault/api-docs/system/namespaces",
		},
		{
			Name:              CheckAuditDevices,
			Description:       "list audit devices",
			PolicyPath:        "sys/audit",
			ProbePath:         "sys/audit",
			Capabilities:      []string{"read", "sudo"},
			RootNamespaceOnly: true,
			NeedsSudo:         true,
			DocsURL:           "https://developer.hashicorp.com/vault/api-docs/system/audit",
		},
		{
			Name:              CheckPluginDetails,
			Description:       "read each registered plugin's sha256, command and args",
			PolicyPath:        "sys/plugins/catalog/*",
			ProbePath:         "sys/plugins/catalog/secret/kv",
			Capabilities:      []string{"read", "sudo"},
			RootNamespaceOnly: true,
			NeedsSudo:         true,
			DocsURL:           "https://developer.hashicorp.com/vault/api-docs/system/plugins-catalog",
		},
		{
			Name:              CheckPluginRuntimes,
			Description:       "list container runtimes registered for plugins",
			PolicyPath:        "sys/plugins/runtimes/catalog",
			ProbePath:         "sys/plugins/runtimes/catalog",
			Capabilities:      []string{"list", "sudo"},
			RootNamespaceOnly: true,
			NeedsSudo:         true,
			DocsURL:           "https://developer.hashicorp.com/vault/api-docs/system/plugins-runtimes-catalog",
		},
	}
}

// Find returns the check with the given name.
func Find(name string) (Check, bool) {
	for _, check := range All() {
		if check.Name == name {
			return check, true
		}
	}
	return Check{}, false
}

// HasCapabilities reports whether the capabilities Vault granted cover what
// the check needs. "root" grants everything; "deny" grants nothing.
func HasCapabilities(granted []string, required []string) bool {
	grantedSet := make(map[string]bool)
	for _, capability := range granted {
		grantedSet[capability] = true
	}

	if grantedSet["deny"] {
		return false
	}
	if grantedSet["root"] {
		return true
	}

	for _, capability := range required {
		if !grantedSet[capability] {
			return false
		}
	}
	return true
}

// Package report builds a readable summary of one saved scan: what is in
// Vault, counted and grouped, plus anything the scan could not read.
//
// It works only on a stored inventory. It never contacts Vault.
package report

import (
	"sort"
	"strings"
	"time"

	"github.com/jfrappier/mitch/internal/scan"
)

// rootNamespaceLabel is how the root namespace (path "") is shown.
const rootNamespaceLabel = "(root)"

// supportedStatus is the deprecation status Vault gives a plugin that is not
// deprecated. Any other non-empty status is reported.
// The statuses are supported, deprecated, pending removal and removed.
// Docs: https://developer.hashicorp.com/vault/docs/updates/deprecation
const supportedStatus = "supported"

// Report is the summary of one scan. It is what "mitch report --format json" prints.
type Report struct {
	Scan    ScanInfo `json:"scan"`
	Summary Summary  `json:"summary"`

	// MountTypes counts secrets engines and auth methods by type, across
	// every namespace.
	MountTypes []TypeCount `json:"mount_types"`

	SecretsEngines []MountRow `json:"secrets_engines"`
	AuthMethods    []MountRow `json:"auth_methods"`

	// KVCounts is null when the scan did not count KV secrets.
	KVCounts []KVRow `json:"kv_counts"`

	// RegisteredPlugins are plugins added to the catalog by hand. Built-in
	// plugins ship with Vault and are only counted, in BuiltinPlugins.
	RegisteredPlugins []PluginRow   `json:"registered_plugins"`
	BuiltinPlugins    []TypeCount   `json:"builtin_plugins"`
	Deprecated        []Deprecation `json:"deprecated"`

	ACLPolicies []PolicyRow `json:"acl_policies"`

	// AuditDevices is null when the scan ran without --sudo.
	AuditDevices []AuditRow `json:"audit_devices"`

	VersionHistory []scan.VersionHistoryEntry `json:"version_history"`

	// Skipped and NotRequested explain what the scan could not read, or
	// left out on purpose. Counts above leave these parts out.
	Skipped      []scan.SkippedCheck      `json:"skipped"`
	NotRequested []scan.NotRequestedCheck `json:"not_requested"`
}

// ScanInfo says which scan the report is about.
type ScanInfo struct {
	ID            string    `json:"id"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	MitchVersion  string    `json:"mitch_version"`
	VaultAddress  string    `json:"vault_address"`
	VaultVersion  string    `json:"vault_version"`
	Enterprise    bool      `json:"enterprise"`
	ClusterName   string    `json:"cluster_name"`
	SudoRequested bool      `json:"sudo_requested"`
}

// Summary holds the headline numbers.
type Summary struct {
	Namespaces     int `json:"namespaces"`
	SecretsEngines int `json:"secrets_engines"`
	AuthMethods    int `json:"auth_methods"`
	ACLPolicies    int `json:"acl_policies"`

	// KVSecrets and KVFolders add up every counted KV mount. KVComplete is
	// false when any mount could only be partly listed, which makes the
	// totals a lower bound. KVCounted is false when counting was turned off.
	KVCounted  bool `json:"kv_counted"`
	KVMounts   int  `json:"kv_mounts"`
	KVSecrets  int  `json:"kv_secrets"`
	KVFolders  int  `json:"kv_folders"`
	KVComplete bool `json:"kv_complete"`

	BuiltinPlugins    int `json:"builtin_plugins"`
	RegisteredPlugins int `json:"registered_plugins"`
	Deprecated        int `json:"deprecated"`

	SkippedChecks int `json:"skipped_checks"`
}

// TypeCount is how many items of one type there are.
type TypeCount struct {
	// Kind is "secrets engine", "auth method" or a plugin type such as "secret".
	Kind  string `json:"kind"`
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// MountRow is one secrets engine or auth method.
type MountRow struct {
	Namespace         string `json:"namespace"`
	Path              string `json:"path"`
	Type              string `json:"type"`
	PluginVersion     string `json:"plugin_version"`
	Description       string `json:"description"`
	DeprecationStatus string `json:"deprecation_status"`
}

// KVRow is the secret and folder count of one KV mount.
type KVRow struct {
	Namespace string `json:"namespace"`
	Mount     string `json:"mount"`
	KVVersion int    `json:"kv_version"`
	Secrets   int    `json:"secrets"`
	Folders   int    `json:"folders"`
	Complete  bool   `json:"complete"`
}

// PluginRow is one plugin registered in the catalog by hand.
type PluginRow struct {
	Type              string `json:"type"`
	Name              string `json:"name"`
	Version           string `json:"version"`
	SHA256            string `json:"sha256"`
	OCIImage          string `json:"oci_image"`
	DeprecationStatus string `json:"deprecation_status"`
}

// Deprecation is a mount, or a plugin registered by hand, whose status is
// not "supported".
type Deprecation struct {
	// Where is "catalog" for a catalog plugin, or the namespace of a mount.
	Where  string `json:"where"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// PolicyRow is one ACL policy. Only its name and size are shown; the full
// text is in "mitch export".
type PolicyRow struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Lines     int    `json:"lines"`
}

// AuditRow is one audit device.
type AuditRow struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

// Kinds used in TypeCount and Deprecation.
const (
	kindSecretsEngine = "secrets engine"
	kindAuthMethod    = "auth method"
	kindPlugin        = "plugin"
	whereCatalog      = "catalog"
)

// Build makes the report for one saved scan.
func Build(scanID string, inventory scan.Inventory) Report {
	built := Report{
		Scan: ScanInfo{
			ID:            scanID,
			StartedAt:     inventory.StartedAt,
			FinishedAt:    inventory.FinishedAt,
			MitchVersion:  inventory.MitchVersion,
			VaultAddress:  inventory.VaultAddress,
			VaultVersion:  inventory.Health.Version,
			Enterprise:    inventory.Health.Enterprise,
			ClusterName:   inventory.Health.ClusterName,
			SudoRequested: inventory.SudoRequested,
		},
		MountTypes:        []TypeCount{},
		SecretsEngines:    []MountRow{},
		AuthMethods:       []MountRow{},
		RegisteredPlugins: []PluginRow{},
		BuiltinPlugins:    []TypeCount{},
		Deprecated:        []Deprecation{},
		ACLPolicies:       []PolicyRow{},
		VersionHistory:    nonNil(inventory.VersionHistory),
		Skipped:           nonNil(inventory.Skipped),
		NotRequested:      nonNil(inventory.NotRequested),
	}

	addNamespaces(&built, inventory.Namespaces)
	addPlugins(&built, inventory.Plugins)
	addAuditDevices(&built, inventory.AuditDevices)

	built.MountTypes = countMountTypes(built.SecretsEngines, built.AuthMethods)
	built.Summary.Namespaces = len(inventory.Namespaces)
	built.Summary.SecretsEngines = len(built.SecretsEngines)
	built.Summary.AuthMethods = len(built.AuthMethods)
	built.Summary.ACLPolicies = len(built.ACLPolicies)
	built.Summary.RegisteredPlugins = len(built.RegisteredPlugins)
	built.Summary.Deprecated = len(built.Deprecated)
	built.Summary.SkippedChecks = len(built.Skipped)
	for _, builtin := range built.BuiltinPlugins {
		built.Summary.BuiltinPlugins += builtin.Count
	}

	return built
}

// addNamespaces adds every mount, KV count and policy, namespace by namespace.
func addNamespaces(built *Report, namespaces []scan.NamespaceInventory) {
	kvCollectedSomewhere := false
	built.Summary.KVComplete = true

	for _, namespace := range namespaces {
		label := namespaceLabel(namespace.Path)

		for _, mount := range namespace.SecretsEngines {
			built.SecretsEngines = append(built.SecretsEngines, mountRow(label, mount))
			addMountDeprecation(built, label, kindSecretsEngine, mount)
		}
		for _, mount := range namespace.AuthMethods {
			built.AuthMethods = append(built.AuthMethods, mountRow(label, mount))
			addMountDeprecation(built, label, kindAuthMethod, mount)
		}
		for _, policy := range namespace.ACLPolicies {
			built.ACLPolicies = append(built.ACLPolicies, PolicyRow{Namespace: label, Name: policy.Name, Lines: countLines(policy.Text)})
		}

		// null KV counts mean counting did not run in this namespace.
		if namespace.KVCounts == nil {
			continue
		}
		kvCollectedSomewhere = true
		if built.KVCounts == nil {
			built.KVCounts = []KVRow{}
		}
		for _, count := range namespace.KVCounts {
			built.KVCounts = append(built.KVCounts, KVRow{
				Namespace: label,
				Mount:     count.Mount,
				KVVersion: count.KVVersion,
				Secrets:   count.Secrets,
				Folders:   count.Folders,
				Complete:  count.Complete,
			})
			built.Summary.KVMounts++
			built.Summary.KVSecrets += count.Secrets
			built.Summary.KVFolders += count.Folders
			if !count.Complete {
				built.Summary.KVComplete = false
			}
		}
	}

	built.Summary.KVCounted = kvCollectedSomewhere
	if !kvCollectedSomewhere {
		built.Summary.KVComplete = false
	}
}

// addPlugins splits the catalog into registered plugins (listed one by one)
// and built-in plugins (counted by type).
func addPlugins(built *Report, plugins []scan.Plugin) {
	builtinByType := map[string]int{}

	for _, plugin := range plugins {
		// Vault ships some deprecated built-in plugins in every catalog, so
		// those only matter when a mount uses them (see addMountDeprecation).
		// A deprecated plugin someone registered by hand is always reported.
		if !plugin.Builtin && isDeprecated(plugin.DeprecationStatus) {
			name := plugin.Type + "/" + plugin.Name
			if plugin.Version != "" {
				name = name + "@" + plugin.Version
			}
			built.Deprecated = append(built.Deprecated, Deprecation{
				Where: whereCatalog, Kind: kindPlugin, Name: name, Status: plugin.DeprecationStatus,
			})
		}

		if plugin.Builtin {
			builtinByType[plugin.Type]++
			continue
		}
		built.RegisteredPlugins = append(built.RegisteredPlugins, PluginRow{
			Type:              plugin.Type,
			Name:              plugin.Name,
			Version:           plugin.Version,
			SHA256:            plugin.SHA256,
			OCIImage:          plugin.OCIImage,
			DeprecationStatus: plugin.DeprecationStatus,
		})
	}

	for _, pluginType := range sortedKeys(builtinByType) {
		built.BuiltinPlugins = append(built.BuiltinPlugins, TypeCount{Kind: kindPlugin, Type: pluginType, Count: builtinByType[pluginType]})
	}
	sort.Slice(built.RegisteredPlugins, func(i, j int) bool {
		left := built.RegisteredPlugins[i]
		right := built.RegisteredPlugins[j]
		return left.Type+"/"+left.Name+"@"+left.Version < right.Type+"/"+right.Name+"@"+right.Version
	})
}

// addAuditDevices copies audit devices. They stay null when not collected.
func addAuditDevices(built *Report, devices []scan.AuditDevice) {
	if devices == nil {
		return
	}
	built.AuditDevices = []AuditRow{}
	for _, device := range devices {
		built.AuditDevices = append(built.AuditDevices, AuditRow{Path: device.Path, Type: device.Type, Description: device.Description})
	}
}

// addMountDeprecation records a mount whose plugin is deprecated.
func addMountDeprecation(built *Report, namespace string, kind string, mount scan.Mount) {
	if !isDeprecated(mount.DeprecationStatus) {
		return
	}
	built.Deprecated = append(built.Deprecated, Deprecation{
		Where: namespace, Kind: kind, Name: mount.Path + " (" + mount.Type + ")", Status: mount.DeprecationStatus,
	})
}

// countMountTypes counts secrets engines and auth methods by type, most
// common first.
func countMountTypes(engines []MountRow, auths []MountRow) []TypeCount {
	counts := []TypeCount{}
	counts = append(counts, countByType(kindSecretsEngine, engines)...)
	counts = append(counts, countByType(kindAuthMethod, auths)...)
	return counts
}

// countByType counts mounts of one kind by type, most common first, then by name.
func countByType(kind string, mounts []MountRow) []TypeCount {
	byType := map[string]int{}
	for _, mount := range mounts {
		byType[mount.Type]++
	}
	counts := []TypeCount{}
	for _, mountType := range sortedKeys(byType) {
		counts = append(counts, TypeCount{Kind: kind, Type: mountType, Count: byType[mountType]})
	}
	sort.SliceStable(counts, func(i, j int) bool { return counts[i].Count > counts[j].Count })
	return counts
}

// mountRow copies the fields of a mount that the report shows.
func mountRow(namespace string, mount scan.Mount) MountRow {
	return MountRow{
		Namespace:         namespace,
		Path:              mount.Path,
		Type:              mount.Type,
		PluginVersion:     mount.PluginVersion,
		Description:       mount.Description,
		DeprecationStatus: mount.DeprecationStatus,
	}
}

// isDeprecated reports whether a deprecation status needs attention.
// An empty status means Vault did not report one.
func isDeprecated(status string) bool {
	return status != "" && status != supportedStatus
}

// countLines counts the lines in a policy, ignoring a trailing line break.
func countLines(text string) int {
	text = strings.TrimSuffix(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if text == "" {
		return 0
	}
	return strings.Count(text, "\n") + 1
}

// namespaceLabel shows the root namespace as "(root)" instead of "".
func namespaceLabel(path string) string {
	if path == "" {
		return rootNamespaceLabel
	}
	return path
}

// nonNil turns a null list into an empty one, so JSON output shows [] and
// scripts can loop over it without checking for null.
func nonNil[Item any](items []Item) []Item {
	if items == nil {
		return []Item{}
	}
	return items
}

// sortedKeys returns a map's keys in alphabetical order, so output is stable.
func sortedKeys[Value any](values map[string]Value) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

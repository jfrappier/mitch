// Package diff compares two saved scans and lists what changed between them.
//
// It works only on stored inventories. It never contacts Vault.
//
// Every list in an inventory is compared by a key that stays the same across
// scans: a mount by its path, a policy by its name, a plugin by its type,
// name and version, and so on. Each item is then reported as added, removed,
// or changed (with the fields that changed).
package diff

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/jfrappier/mitch/internal/scan"
)

// rootNamespaceLabel is how the root namespace (path "") is shown.
const rootNamespaceLabel = "(root)"

// Section names, as they appear in JSON output. Text output shows each with
// a heading from sectionTitles in text.go.
const (
	SectionVault          = "vault"
	SectionServerConfig   = "server_config"
	SectionPlugins        = "plugins"
	SectionPluginRuntimes = "plugin_runtimes"
	SectionAuditDevices   = "audit_devices"
	SectionNamespaces     = "namespaces"
	SectionSecretsEngines = "secrets_engines"
	SectionAuthMethods    = "auth_methods"
	SectionACLPolicies    = "acl_policies"
	SectionKVCounts       = "kv_counts"
)

// ScanRef identifies one of the two scans being compared.
type ScanRef struct {
	ID           string    `json:"id"`
	StartedAt    time.Time `json:"started_at"`
	VaultAddress string    `json:"vault_address"`
	VaultVersion string    `json:"vault_version"`
}

// Result is everything that changed between two scans.
type Result struct {
	From ScanRef `json:"from"`
	To   ScanRef `json:"to"`

	// Warnings explain why some differences may not be real changes, for
	// example when one scan skipped checks that the other one ran.
	Warnings []string `json:"warnings"`

	// Sections holds one entry per part of the inventory that changed.
	// Parts with no changes are left out.
	Sections []Section `json:"sections"`
}

// HasChanges reports whether anything changed between the two scans.
func (r Result) HasChanges() bool {
	return len(r.Sections) > 0
}

// Section is one part of the inventory, such as "secrets engines" in one
// namespace, with the items that changed in it.
type Section struct {
	// Namespace is the namespace label, or "" for parts that are not per
	// namespace (Vault health, plugins, audit devices, server config).
	Namespace string `json:"namespace,omitempty"`

	// Name says which part of the inventory this is, for example
	// "secrets_engines". The Section constants list every name.
	Name string `json:"name"`

	Added   []string     `json:"added"`
	Removed []string     `json:"removed"`
	Changed []ItemChange `json:"changed"`
}

// isEmpty reports whether the section has nothing to show.
func (s Section) isEmpty() bool {
	return len(s.Added) == 0 && len(s.Removed) == 0 && len(s.Changed) == 0
}

// ItemChange is one item that exists in both scans but is different.
type ItemChange struct {
	// Key names the item, for example a mount path or a policy name.
	Key string `json:"key"`

	// Fields lists each field that changed, with its old and new value.
	Fields []FieldChange `json:"fields,omitempty"`

	// TextLines is a line-by-line comparison of a policy's text. Each entry
	// starts with "- " (only in the old scan) or "+ " (only in the new scan).
	TextLines []string `json:"text_lines,omitempty"`
}

// FieldChange is one field whose value changed. Old or New is "(none)" when
// the field exists in only one of the scans. Values are shown as JSON.
type FieldChange struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// missingValue is shown when a field exists in only one of the two scans.
const missingValue = "(none)"

// Compare lists what changed from the "from" scan to the "to" scan.
func Compare(fromID string, from scan.Inventory, toID string, to scan.Inventory) (Result, error) {
	result := Result{
		From:     scanRef(fromID, from),
		To:       scanRef(toID, to),
		Warnings: comparabilityWarnings(fromID, from, toID, to),
		Sections: []Section{},
	}

	// Vault health: version, seal status, cluster name, and so on.
	healthSection, err := compareSingleObject(SectionVault, from.Health, to.Health)
	if err != nil {
		return Result{}, err
	}
	result.addSection(healthSection)

	// Server configuration. It is only collected when the token can read it,
	// so it can be missing from either scan.
	if from.Config != nil && to.Config != nil {
		configSection, err := compareSingleObject(SectionServerConfig, from.Config, to.Config)
		if err != nil {
			return Result{}, err
		}
		result.addSection(configSection)
	}

	pluginSection, err := compareItems(SectionPlugins, from.Plugins, to.Plugins, pluginKey)
	if err != nil {
		return Result{}, err
	}
	result.addSection(pluginSection)

	// Plugin runtimes and audit devices are only collected with --sudo.
	// null means "not collected", so compare them only when both scans have them.
	if from.PluginRuntimes != nil && to.PluginRuntimes != nil {
		runtimeSection, err := compareItems(SectionPluginRuntimes, from.PluginRuntimes, to.PluginRuntimes, pluginRuntimeKey)
		if err != nil {
			return Result{}, err
		}
		result.addSection(runtimeSection)
	}
	if from.AuditDevices != nil && to.AuditDevices != nil {
		auditSection, err := compareItems(SectionAuditDevices, from.AuditDevices, to.AuditDevices, auditDeviceKey)
		if err != nil {
			return Result{}, err
		}
		result.addSection(auditSection)
	}

	namespaceSections, err := compareNamespaces(from.Namespaces, to.Namespaces)
	if err != nil {
		return Result{}, err
	}
	for _, section := range namespaceSections {
		result.addSection(section)
	}

	return result, nil
}

// addSection keeps a section only if something in it changed.
func (r *Result) addSection(section Section) {
	if section.isEmpty() {
		return
	}
	r.Sections = append(r.Sections, section)
}

// scanRef builds the short description of a scan shown at the top of a diff.
func scanRef(id string, inventory scan.Inventory) ScanRef {
	return ScanRef{
		ID:           id,
		StartedAt:    inventory.StartedAt,
		VaultAddress: inventory.VaultAddress,
		VaultVersion: inventory.Health.Version,
	}
}

// comparabilityWarnings explains differences that may not be real changes.
func comparabilityWarnings(fromID string, from scan.Inventory, toID string, to scan.Inventory) []string {
	warnings := []string{}

	if from.VaultAddress != to.VaultAddress {
		warnings = append(warnings, fmt.Sprintf(
			"the scans are of different Vault addresses (%s and %s), so most differences are between two clusters, not changes over time",
			from.VaultAddress, to.VaultAddress))
	}

	// A skipped check leaves a gap in the inventory. Anything in that gap
	// looks removed (or added) even if it did not change in Vault.
	if len(from.Skipped) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"scan %s skipped %d check(s); items it could not read may show as added below", fromID, len(from.Skipped)))
	}
	if len(to.Skipped) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"scan %s skipped %d check(s); items it could not read may show as removed below", toID, len(to.Skipped)))
	}

	warnings = append(warnings, notCollectedWarning("server config", fromID, from.Config == nil, toID, to.Config == nil)...)
	warnings = append(warnings, notCollectedWarning("plugin runtimes", fromID, from.PluginRuntimes == nil, toID, to.PluginRuntimes == nil)...)
	warnings = append(warnings, notCollectedWarning("audit devices", fromID, from.AuditDevices == nil, toID, to.AuditDevices == nil)...)

	return warnings
}

// notCollectedWarning returns a warning when a part of the inventory is
// missing from one or both scans, because it then cannot be compared.
func notCollectedWarning(part string, fromID string, missingInFrom bool, toID string, missingInTo bool) []string {
	if missingInFrom && missingInTo {
		// Neither scan has it, so there is nothing to compare and nothing to warn about.
		return nil
	}
	if missingInFrom {
		return []string{fmt.Sprintf("%s were not collected in scan %s, so they were not compared", part, fromID)}
	}
	if missingInTo {
		return []string{fmt.Sprintf("%s were not collected in scan %s, so they were not compared", part, toID)}
	}
	return nil
}

// compareNamespaces compares every namespace, and the mounts, policies and
// KV counts inside each one.
func compareNamespaces(from []scan.NamespaceInventory, to []scan.NamespaceInventory) ([]Section, error) {
	sections := []Section{}

	// Namespaces that were added or removed.
	namespaceSection, err := compareItems(SectionNamespaces, from, to, namespaceKey)
	if err != nil {
		return nil, err
	}
	// Only the namespace list itself matters here. What changed inside a
	// namespace is shown in that namespace's own sections below.
	namespaceSection.Changed = []ItemChange{}
	sections = append(sections, namespaceSection)

	fromByPath := map[string]scan.NamespaceInventory{}
	for _, namespace := range from {
		fromByPath[namespace.Path] = namespace
	}

	for _, toNamespace := range to {
		fromNamespace, inBoth := fromByPath[toNamespace.Path]
		if !inBoth {
			continue
		}
		label := namespaceLabel(toNamespace.Path)

		engines, err := compareItems(SectionSecretsEngines, fromNamespace.SecretsEngines, toNamespace.SecretsEngines, mountKey)
		if err != nil {
			return nil, err
		}
		auths, err := compareItems(SectionAuthMethods, fromNamespace.AuthMethods, toNamespace.AuthMethods, mountKey)
		if err != nil {
			return nil, err
		}
		policies := comparePolicies(fromNamespace.ACLPolicies, toNamespace.ACLPolicies)

		perNamespace := []Section{engines, auths, policies}

		// KV counts are null when counting was turned off for a scan.
		if fromNamespace.KVCounts != nil && toNamespace.KVCounts != nil {
			counts, err := compareItems(SectionKVCounts, fromNamespace.KVCounts, toNamespace.KVCounts, kvCountKey)
			if err != nil {
				return nil, err
			}
			perNamespace = append(perNamespace, counts)
		}

		for _, section := range perNamespace {
			section.Namespace = label
			sections = append(sections, section)
		}
	}

	return sections, nil
}

// comparePolicies compares ACL policies by name, and shows a line-by-line
// comparison of the text of each policy that changed.
func comparePolicies(from []scan.Policy, to []scan.Policy) Section {
	section := Section{Name: SectionACLPolicies, Added: []string{}, Removed: []string{}, Changed: []ItemChange{}}

	fromByName := map[string]string{}
	for _, policy := range from {
		fromByName[policy.Name] = policy.Text
	}
	toByName := map[string]string{}
	for _, policy := range to {
		toByName[policy.Name] = policy.Text
	}

	for _, name := range sortedKeys(toByName) {
		oldText, inFrom := fromByName[name]
		if !inFrom {
			section.Added = append(section.Added, name)
			continue
		}
		newText := toByName[name]
		if oldText != newText {
			section.Changed = append(section.Changed, ItemChange{Key: name, TextLines: compareLines(oldText, newText)})
		}
	}
	for _, name := range sortedKeys(fromByName) {
		_, inTo := toByName[name]
		if !inTo {
			section.Removed = append(section.Removed, name)
		}
	}
	return section
}

// compareItems compares two lists of the same kind of item. keyOf returns
// the key that identifies an item across scans, and a label to show when the
// item was added or removed.
//
// Items that exist in both lists are compared field by field.
func compareItems[Item any](name string, from []Item, to []Item, keyOf func(Item) (key string, label string, err error)) (Section, error) {
	section := Section{Name: name, Added: []string{}, Removed: []string{}, Changed: []ItemChange{}}

	fromByKey, fromLabels, err := indexItems(name, from, keyOf)
	if err != nil {
		return Section{}, err
	}
	toByKey, toLabels, err := indexItems(name, to, keyOf)
	if err != nil {
		return Section{}, err
	}

	for _, key := range sortedKeys(toByKey) {
		oldItem, inFrom := fromByKey[key]
		if !inFrom {
			section.Added = append(section.Added, toLabels[key])
			continue
		}
		fields, err := compareFields(oldItem, toByKey[key])
		if err != nil {
			return Section{}, fmt.Errorf("comparing %s %q failed: %w", name, key, err)
		}
		if len(fields) > 0 {
			section.Changed = append(section.Changed, ItemChange{Key: key, Fields: fields})
		}
	}
	for _, key := range sortedKeys(fromByKey) {
		_, inTo := toByKey[key]
		if !inTo {
			section.Removed = append(section.Removed, fromLabels[key])
		}
	}
	return section, nil
}

// indexItems puts a list of items in a map by key. Two items with the same
// key would make the comparison wrong, so that is an error.
func indexItems[Item any](name string, items []Item, keyOf func(Item) (string, string, error)) (map[string]Item, map[string]string, error) {
	byKey := map[string]Item{}
	labels := map[string]string{}
	for _, item := range items {
		key, label, err := keyOf(item)
		if err != nil {
			return nil, nil, fmt.Errorf("reading the %s list failed: %w", name, err)
		}
		_, duplicate := byKey[key]
		if duplicate {
			return nil, nil, fmt.Errorf("the %s list has %q twice, so it cannot be compared", name, key)
		}
		byKey[key] = item
		labels[key] = label
	}
	return byKey, labels, nil
}

// compareSingleObject compares two values that are not lists, such as Vault
// health, and returns a section with one changed item when they differ.
func compareSingleObject(name string, from any, to any) (Section, error) {
	section := Section{Name: name, Added: []string{}, Removed: []string{}, Changed: []ItemChange{}}
	fields, err := compareFields(from, to)
	if err != nil {
		return Section{}, fmt.Errorf("comparing %s failed: %w", name, err)
	}
	if len(fields) > 0 {
		section.Changed = append(section.Changed, ItemChange{Key: name, Fields: fields})
	}
	return section, nil
}

// compareFields compares two values field by field.
//
// Both values are turned into JSON and then into a flat list of
// "field.subfield" = value pairs, so nested settings such as a mount's
// config.max_lease_ttl are compared one by one.
func compareFields(from any, to any) ([]FieldChange, error) {
	fromFields, err := flattenToFields(from)
	if err != nil {
		return nil, err
	}
	toFields, err := flattenToFields(to)
	if err != nil {
		return nil, err
	}

	allNames := map[string]bool{}
	for fieldName := range fromFields {
		allNames[fieldName] = true
	}
	for fieldName := range toFields {
		allNames[fieldName] = true
	}

	changes := []FieldChange{}
	for _, fieldName := range sortedKeys(allNames) {
		oldValue, inFrom := fromFields[fieldName]
		newValue, inTo := toFields[fieldName]
		if !inFrom {
			oldValue = missingValue
		}
		if !inTo {
			newValue = missingValue
		}
		if oldValue != newValue {
			changes = append(changes, FieldChange{Field: fieldName, Old: oldValue, New: newValue})
		}
	}
	return changes, nil
}

// flattenToFields turns a value into "field.subfield" = JSON value pairs.
// Lists are kept whole, as one JSON value, because their items have no
// stable names to compare by.
func flattenToFields(value any) (map[string]string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encoding the value as JSON failed: %w", err)
	}

	// UseNumber keeps numbers exactly as written, so 3600 does not become 3.6e+03.
	var decoded any
	decoder := json.NewDecoder(bytesReader(encoded))
	decoder.UseNumber()
	err = decoder.Decode(&decoded)
	if err != nil {
		return nil, fmt.Errorf("decoding the value from JSON failed: %w", err)
	}

	fields := map[string]string{}
	err = flattenInto(fields, "", decoded)
	if err != nil {
		return nil, err
	}
	return fields, nil
}

// flattenInto adds one value to fields under prefix. Objects are walked into;
// everything else is stored as compact JSON.
func flattenInto(fields map[string]string, prefix string, value any) error {
	object, isObject := value.(map[string]any)
	if isObject && len(object) > 0 {
		for key, child := range object {
			childName := key
			if prefix != "" {
				childName = prefix + "." + key
			}
			err := flattenInto(fields, childName, child)
			if err != nil {
				return err
			}
		}
		return nil
	}

	if prefix == "" {
		// A plain value with no field name, such as a raw JSON string.
		prefix = "value"
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encoding field %s as JSON failed: %w", prefix, err)
	}
	fields[prefix] = string(encoded)
	return nil
}

// Key functions: each returns the key that identifies an item across scans,
// and the label shown when the item is added or removed.

func mountKey(mount scan.Mount) (string, string, error) {
	return mount.Path, fmt.Sprintf("%s (%s)", mount.Path, mount.Type), nil
}

func kvCountKey(count scan.KVCount) (string, string, error) {
	return count.Mount, fmt.Sprintf("%s (%d secrets, %d folders)", count.Mount, count.Secrets, count.Folders), nil
}

func auditDeviceKey(device scan.AuditDevice) (string, string, error) {
	return device.Path, fmt.Sprintf("%s (%s)", device.Path, device.Type), nil
}

func namespaceKey(namespace scan.NamespaceInventory) (string, string, error) {
	label := namespaceLabel(namespace.Path)
	return label, label, nil
}

// pluginKey uses type, name and version, because Vault can register several
// versions of the same plugin at once.
func pluginKey(plugin scan.Plugin) (string, string, error) {
	key := plugin.Type + "/" + plugin.Name
	if plugin.Version != "" {
		key = key + "@" + plugin.Version
	}
	if plugin.Builtin {
		return key, key + " (built-in)", nil
	}
	return key, key + " (registered)", nil
}

// pluginRuntimeKey reads the type and name from a runtime, which is stored
// exactly as Vault returned it.
func pluginRuntimeKey(runtime json.RawMessage) (string, string, error) {
	var identity struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	err := json.Unmarshal(runtime, &identity)
	if err != nil {
		return "", "", fmt.Errorf("a plugin runtime is not a JSON object: %w", err)
	}
	key := identity.Type + "/" + identity.Name
	return key, key, nil
}

// namespaceLabel shows the root namespace as "(root)" instead of "".
func namespaceLabel(path string) string {
	if path == "" {
		return rootNamespaceLabel
	}
	return path
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

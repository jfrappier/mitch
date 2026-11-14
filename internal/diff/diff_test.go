package diff

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jfrappier/mitch/internal/scan"
)

// baseInventory returns a small inventory that tests copy and then change.
func baseInventory() scan.Inventory {
	return scan.Inventory{
		StartedAt:    time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC),
		VaultAddress: "http://127.0.0.1:8200",
		Health:       scan.Health{Version: "2.2.2", Initialized: true},
		Config:       json.RawMessage(`{"log_level":"info","listeners":[{"type":"tcp"}]}`),
		Plugins: []scan.Plugin{
			{Name: "kv", Type: "secret", Version: "v0.25.0+builtin", Builtin: true},
		},
		AuditDevices: nil,
		Namespaces: []scan.NamespaceInventory{
			{
				Path: "",
				SecretsEngines: []scan.Mount{
					{Path: "secret/", Type: "kv", Description: "app secrets", Options: map[string]string{"version": "2"},
						Config: scan.MountConfig{DefaultLeaseTTL: 0, MaxLeaseTTL: 0}},
					{Path: "old/", Type: "kv"},
				},
				AuthMethods: []scan.Mount{{Path: "token/", Type: "token"}},
				ACLPolicies: []scan.Policy{
					{Name: "app", Text: "path \"secret/data/app/*\" {\n  capabilities = [\"read\"]\n}\n"},
					{Name: "retired", Text: "path \"old/*\" {}\n"},
				},
				KVCounts: []scan.KVCount{{Mount: "secret/", KVVersion: 2, Secrets: 10, Folders: 2, Complete: true}},
			},
		},
		Skipped: []scan.SkippedCheck{},
	}
}

// cloneInventory deep-copies an inventory through JSON so changes to the copy
// never touch the original.
func cloneInventory(t *testing.T, inventory scan.Inventory) scan.Inventory {
	t.Helper()
	encoded, err := json.Marshal(inventory)
	if err != nil {
		t.Fatalf("encoding the inventory failed: %v", err)
	}
	var copied scan.Inventory
	err = json.Unmarshal(encoded, &copied)
	if err != nil {
		t.Fatalf("decoding the inventory failed: %v", err)
	}
	return copied
}

// findSection returns the section with this namespace and name, or fails the test.
func findSection(t *testing.T, result Result, namespace string, name string) Section {
	t.Helper()
	for _, section := range result.Sections {
		if section.Namespace == namespace && section.Name == name {
			return section
		}
	}
	t.Fatalf("no %q section for namespace %q in %+v", name, namespace, result.Sections)
	return Section{}
}

func TestIdenticalScansHaveNoChanges(t *testing.T) {
	from := baseInventory()
	to := cloneInventory(t, from)

	result, err := Compare("aaaa", from, "bbbb", to)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	if result.HasChanges() {
		t.Errorf("expected no changes, got %+v", result.Sections)
	}

	var text bytes.Buffer
	err = WriteMarkdown(&text, result)
	if err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}
	if !strings.Contains(text.String(), "No changes.") {
		t.Errorf("expected \"No changes.\" in:\n%s", text.String())
	}
}

func TestMountsAddedRemovedAndChanged(t *testing.T) {
	from := baseInventory()
	to := cloneInventory(t, from)
	root := &to.Namespaces[0]
	root.SecretsEngines = []scan.Mount{
		{Path: "secret/", Type: "kv", Description: "app secrets v2", Options: map[string]string{"version": "2"},
			Config: scan.MountConfig{DefaultLeaseTTL: 0, MaxLeaseTTL: 3600}},
		{Path: "pki/", Type: "pki"},
	}

	result, err := Compare("aaaa", from, "bbbb", to)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	engines := findSection(t, result, rootNamespaceLabel, SectionSecretsEngines)

	if !reflect.DeepEqual(engines.Added, []string{"pki/ (pki)"}) {
		t.Errorf("added: got %v", engines.Added)
	}
	if !reflect.DeepEqual(engines.Removed, []string{"old/ (kv)"}) {
		t.Errorf("removed: got %v", engines.Removed)
	}
	if len(engines.Changed) != 1 || engines.Changed[0].Key != "secret/" {
		t.Fatalf("expected secret/ to be changed, got %+v", engines.Changed)
	}
	expectedFields := []FieldChange{
		{Field: "config.max_lease_ttl", Old: "0", New: "3600"},
		{Field: "description", Old: `"app secrets"`, New: `"app secrets v2"`},
	}
	if !reflect.DeepEqual(engines.Changed[0].Fields, expectedFields) {
		t.Errorf("fields: got %+v, want %+v", engines.Changed[0].Fields, expectedFields)
	}
}

func TestPolicyTextChangesShowOnlyChangedLines(t *testing.T) {
	from := baseInventory()
	to := cloneInventory(t, from)
	root := &to.Namespaces[0]
	root.ACLPolicies = []scan.Policy{
		{Name: "app", Text: "path \"secret/data/app/*\" {\n  capabilities = [\"read\", \"list\"]\n}\n"},
		{Name: "new-team", Text: "path \"team/*\" {}\n"},
	}

	result, err := Compare("aaaa", from, "bbbb", to)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	policies := findSection(t, result, rootNamespaceLabel, SectionACLPolicies)

	if !reflect.DeepEqual(policies.Added, []string{"new-team"}) || !reflect.DeepEqual(policies.Removed, []string{"retired"}) {
		t.Errorf("added %v removed %v", policies.Added, policies.Removed)
	}
	expectedLines := []string{
		`-   capabilities = ["read"]`,
		`+   capabilities = ["read", "list"]`,
	}
	if len(policies.Changed) != 1 || !reflect.DeepEqual(policies.Changed[0].TextLines, expectedLines) {
		t.Errorf("expected only the capabilities line to change, got %+v", policies.Changed)
	}
}

func TestKVCountsHealthConfigAndPlugins(t *testing.T) {
	from := baseInventory()
	to := cloneInventory(t, from)
	to.Health.Version = "2.3.0"
	to.Config = json.RawMessage(`{"log_level":"debug","listeners":[{"type":"tcp"}]}`)
	to.Plugins = append(to.Plugins, scan.Plugin{Name: "my-auth", Type: "auth", Version: "v1.0.0"})
	to.Namespaces[0].KVCounts[0].Secrets = 12

	result, err := Compare("aaaa", from, "bbbb", to)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	health := findSection(t, result, "", SectionVault)
	if len(health.Changed) != 1 || !reflect.DeepEqual(health.Changed[0].Fields, []FieldChange{{Field: "version", Old: `"2.2.2"`, New: `"2.3.0"`}}) {
		t.Errorf("health: got %+v", health.Changed)
	}

	config := findSection(t, result, "", SectionServerConfig)
	if len(config.Changed) != 1 || !reflect.DeepEqual(config.Changed[0].Fields, []FieldChange{{Field: "log_level", Old: `"info"`, New: `"debug"`}}) {
		t.Errorf("config: got %+v", config.Changed)
	}

	plugins := findSection(t, result, "", SectionPlugins)
	if !reflect.DeepEqual(plugins.Added, []string{"auth/my-auth@v1.0.0 (registered)"}) {
		t.Errorf("plugins added: got %v", plugins.Added)
	}

	counts := findSection(t, result, rootNamespaceLabel, SectionKVCounts)
	if len(counts.Changed) != 1 || !reflect.DeepEqual(counts.Changed[0].Fields, []FieldChange{{Field: "secrets", Old: "10", New: "12"}}) {
		t.Errorf("kv counts: got %+v", counts.Changed)
	}
}

func TestNamespacesAddedAndRemoved(t *testing.T) {
	from := baseInventory()
	from.Namespaces = append(from.Namespaces, scan.NamespaceInventory{Path: "team-a/"})
	to := cloneInventory(t, baseInventory())
	to.Namespaces = append(to.Namespaces, scan.NamespaceInventory{Path: "team-b/"})

	result, err := Compare("aaaa", from, "bbbb", to)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	namespaces := findSection(t, result, "", SectionNamespaces)
	if !reflect.DeepEqual(namespaces.Added, []string{"team-b/"}) || !reflect.DeepEqual(namespaces.Removed, []string{"team-a/"}) {
		t.Errorf("added %v removed %v", namespaces.Added, namespaces.Removed)
	}
	if len(namespaces.Changed) != 0 {
		t.Errorf("the namespace list must not report changes inside namespaces, got %+v", namespaces.Changed)
	}
}

func TestWarningsForSkippedChecksAddressAndMissingParts(t *testing.T) {
	from := baseInventory()
	to := cloneInventory(t, from)
	to.VaultAddress = "https://vault.example.com:8200"
	to.Skipped = []scan.SkippedCheck{{Check: "acl_policies", HTTPStatus: 403}}
	to.AuditDevices = []scan.AuditDevice{{Path: "file/", Type: "file"}}
	to.Config = nil
	to.Namespaces[0].KVCounts = nil
	to.Namespaces[0].SecretsEngines = nil

	result, err := Compare("aaaa", from, "bbbb", to)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	allWarnings := strings.Join(result.Warnings, "\n")
	for _, expected := range []string{
		"different Vault addresses",
		"scan bbbb skipped 1 check(s)",
		"server config were not collected in scan bbbb",
		"audit devices were not collected in scan aaaa",
	} {
		if !strings.Contains(allWarnings, expected) {
			t.Errorf("warnings are missing %q:\n%s", expected, allWarnings)
		}
	}

	// Parts missing from one scan are not compared, so they must not show as removed.
	for _, section := range result.Sections {
		if section.Name == SectionServerConfig || section.Name == SectionAuditDevices || section.Name == SectionKVCounts {
			t.Errorf("%q was missing from one scan and must not be compared: %+v", section.Name, section)
		}
	}
}

func TestDuplicateKeysAreAnError(t *testing.T) {
	from := baseInventory()
	to := cloneInventory(t, from)
	to.Namespaces[0].SecretsEngines = append(to.Namespaces[0].SecretsEngines, scan.Mount{Path: "secret/", Type: "kv"})

	_, err := Compare("aaaa", from, "bbbb", to)
	if err == nil || !strings.Contains(err.Error(), `"secret/" twice`) {
		t.Errorf("expected a duplicate-key error, got %v", err)
	}
}

func TestPluginRuntimesComparedByTypeAndName(t *testing.T) {
	from := baseInventory()
	from.PluginRuntimes = []json.RawMessage{json.RawMessage(`{"name":"gvisor","type":"container","oci_runtime":"runsc"}`)}
	to := cloneInventory(t, from)
	to.PluginRuntimes = []json.RawMessage{json.RawMessage(`{"name":"gvisor","type":"container","oci_runtime":"runc"}`)}

	result, err := Compare("aaaa", from, "bbbb", to)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	runtimes := findSection(t, result, "", SectionPluginRuntimes)
	if len(runtimes.Changed) != 1 || runtimes.Changed[0].Key != "container/gvisor" {
		t.Errorf("expected container/gvisor to change, got %+v", runtimes)
	}

	// A runtime that is not a JSON object cannot be keyed.
	to.PluginRuntimes = []json.RawMessage{json.RawMessage(`"not an object"`)}
	_, err = Compare("aaaa", from, "bbbb", to)
	if err == nil || !strings.Contains(err.Error(), "plugin runtime") {
		t.Errorf("expected a plugin runtime error, got %v", err)
	}
}

func TestWriteMarkdownShowsEveryKindOfChange(t *testing.T) {
	from := baseInventory()
	to := cloneInventory(t, from)
	to.Skipped = []scan.SkippedCheck{{Check: "audit_devices"}}
	to.Namespaces[0].SecretsEngines = to.Namespaces[0].SecretsEngines[:1]
	to.Namespaces[0].SecretsEngines[0].Description = "changed"
	to.Namespaces[0].ACLPolicies[0].Text = "path \"x\" {}\n"
	to.Namespaces[0].AuthMethods = append(to.Namespaces[0].AuthMethods, scan.Mount{Path: "userpass/", Type: "userpass"})

	result, err := Compare("aaaa", from, "bbbb", to)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	var text bytes.Buffer
	err = WriteMarkdown(&text, result)
	if err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}
	output := text.String()
	for _, expected := range []string{
		"- From scan: aaaa (2026-11-13 09:00:00 UTC, Vault 2.2.2)",
		"## Warnings\n\n- scan bbbb skipped 1 check(s)",
		"## Secrets engines in namespace (root)\n\n```diff\n",
		"\n- old/ (kv)\n",
		"\n~ secret/\n",
		`    description: "app secrets" -> "changed"`,
		"## Auth methods in namespace (root)",
		"\n+ userpass/ (userpass)\n",
		"## ACL policies in namespace (root)",
		`  + path "x" {}`,
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("text output is missing %q:\n%s", expected, output)
		}
	}
}

func TestCompareLines(t *testing.T) {
	cases := []struct {
		name     string
		oldText  string
		newText  string
		expected []string
	}{
		{"same", "a\nb\n", "a\nb", []string{}},
		{"line added at end", "a\n", "a\nb\n", []string{"+ b"}},
		{"line removed at start", "a\nb\n", "b\n", []string{"- a"}},
		{"line replaced", "a\nb\nc", "a\nx\nc", []string{"- b", "+ x"}},
		{"windows line endings", "a\r\nb\r\n", "a\nb\n", []string{}},
		{"from empty", "", "a\n", []string{"+ a"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := compareLines(testCase.oldText, testCase.newText)
			if !reflect.DeepEqual(got, testCase.expected) {
				t.Errorf("got %q, want %q", got, testCase.expected)
			}
		})
	}
}

func TestCompareLinesFallsBackForHugeTexts(t *testing.T) {
	oldText := strings.Repeat("old line\n", 2001)
	newText := strings.Repeat("new line\n", 2001)
	got := compareLines(oldText, newText)
	if len(got) != 4002 || got[0] != "- old line" || got[4001] != "+ new line" {
		t.Errorf("expected every old line removed then every new line added, got %d lines", len(got))
	}
}

func TestResultJSONHasStableEmptyLists(t *testing.T) {
	from := baseInventory()
	to := cloneInventory(t, from)
	to.Namespaces[0].AuthMethods = append(to.Namespaces[0].AuthMethods, scan.Mount{Path: "userpass/", Type: "userpass"})

	result, err := Compare("aaaa", from, "bbbb", to)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	if strings.Contains(string(encoded), "null") {
		t.Errorf("lists must be [] not null, so scripts can loop over them:\n%s", encoded)
	}
}

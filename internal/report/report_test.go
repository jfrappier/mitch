package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jfrappier/mitch/internal/scan"
)

// sampleInventory returns an inventory with two namespaces, a registered
// plugin, a deprecated mount and one skipped check.
func sampleInventory() scan.Inventory {
	return scan.Inventory{
		MitchVersion:  "test",
		StartedAt:     time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC),
		FinishedAt:    time.Date(2026, 11, 13, 9, 0, 2, 0, time.UTC),
		VaultAddress:  "http://127.0.0.1:8200",
		Health:        scan.Health{Version: "2.2.2", Enterprise: true, ClusterName: "vault-cluster-1"},
		SudoRequested: false,
		VersionHistory: []scan.VersionHistoryEntry{
			{Version: "2.2.2", TimestampInstalled: "2026-11-01T00:00:00Z", BuildDate: "2026-10-20T00:00:00Z"},
		},
		Plugins: []scan.Plugin{
			{Name: "kv", Type: "secret", Version: "v0.25.0+builtin", Builtin: true, DeprecationStatus: "supported"},
			{Name: "pki", Type: "secret", Version: "v2.2.2+builtin.vault", Builtin: true, DeprecationStatus: "supported"},
			{Name: "userpass", Type: "auth", Builtin: true, DeprecationStatus: "supported"},
			{Name: "app-id", Type: "auth", Builtin: true, DeprecationStatus: "removed"},
			{Name: "my-db", Type: "database", Version: "v1.0.0", Builtin: false},
			{Name: "old-auth", Type: "auth", Version: "v0.1.0", Builtin: false, DeprecationStatus: "pending removal"},
		},
		AuditDevices: nil,
		Namespaces: []scan.NamespaceInventory{
			{
				Path: "",
				SecretsEngines: []scan.Mount{
					{Path: "secret/", Type: "kv", Description: "app | team secrets"},
					{Path: "kv1/", Type: "kv"},
					{Path: "pki/", Type: "pki", DeprecationStatus: "deprecated"},
				},
				AuthMethods: []scan.Mount{{Path: "token/", Type: "token"}},
				ACLPolicies: []scan.Policy{{Name: "app", Text: "path \"a\" {}\npath \"b\" {}\n"}},
				KVCounts: []scan.KVCount{
					{Mount: "secret/", KVVersion: 2, Secrets: 10, Folders: 3, Complete: true},
					{Mount: "kv1/", KVVersion: 1, Secrets: 4, Folders: 0, Complete: false},
				},
			},
			{
				Path:           "team-a/",
				SecretsEngines: []scan.Mount{{Path: "secret/", Type: "kv"}},
				AuthMethods:    []scan.Mount{},
				ACLPolicies:    []scan.Policy{},
				KVCounts:       []scan.KVCount{{Mount: "secret/", KVVersion: 2, Secrets: 1, Folders: 0, Complete: true}},
			},
		},
		Skipped: []scan.SkippedCheck{
			{Check: "kv_secret_count", Namespace: "", Path: "kv1/", HTTPStatus: 403, Reason: "permission denied", NextStep: "run mitch policy"},
		},
		NotRequested: []scan.NotRequestedCheck{{Check: "audit_devices", Reason: "needs --sudo"}},
	}
}

func TestBuildSummary(t *testing.T) {
	built := Build("abcd", sampleInventory())

	expected := Summary{
		Namespaces:        2,
		SecretsEngines:    4,
		AuthMethods:       1,
		ACLPolicies:       1,
		KVCounted:         true,
		KVMounts:          3,
		KVSecrets:         15,
		KVFolders:         3,
		KVComplete:        false,
		BuiltinPlugins:    4,
		RegisteredPlugins: 2,
		Deprecated:        2,
		SkippedChecks:     1,
	}
	if built.Summary != expected {
		t.Errorf("summary:\ngot  %+v\nwant %+v", built.Summary, expected)
	}
	if built.Scan.ID != "abcd" || built.Scan.VaultVersion != "2.2.2" || !built.Scan.Enterprise {
		t.Errorf("scan info: got %+v", built.Scan)
	}
}

func TestBuildGroupsMountsAndPlugins(t *testing.T) {
	built := Build("abcd", sampleInventory())

	expectedTypes := []TypeCount{
		{Kind: "secrets engine", Type: "kv", Count: 3},
		{Kind: "secrets engine", Type: "pki", Count: 1},
		{Kind: "auth method", Type: "token", Count: 1},
	}
	if !reflect.DeepEqual(built.MountTypes, expectedTypes) {
		t.Errorf("mount types:\ngot  %+v\nwant %+v", built.MountTypes, expectedTypes)
	}

	expectedBuiltin := []TypeCount{
		{Kind: "plugin", Type: "auth", Count: 2},
		{Kind: "plugin", Type: "secret", Count: 2},
	}
	if !reflect.DeepEqual(built.BuiltinPlugins, expectedBuiltin) {
		t.Errorf("built-in plugins:\ngot  %+v\nwant %+v", built.BuiltinPlugins, expectedBuiltin)
	}
	if len(built.RegisteredPlugins) != 2 || built.RegisteredPlugins[0].Name != "old-auth" || built.RegisteredPlugins[1].Name != "my-db" {
		t.Errorf("registered plugins: got %+v", built.RegisteredPlugins)
	}

	expectedDeprecated := []Deprecation{
		{Where: "(root)", Kind: "secrets engine", Name: "pki/ (pki)", Status: "deprecated"},
		{Where: "catalog", Kind: "plugin", Name: "auth/old-auth@v0.1.0", Status: "pending removal"},
	}
	if !reflect.DeepEqual(built.Deprecated, expectedDeprecated) {
		t.Errorf("deprecated:\ngot  %+v\nwant %+v", built.Deprecated, expectedDeprecated)
	}

	if len(built.ACLPolicies) != 1 || built.ACLPolicies[0].Lines != 2 {
		t.Errorf("policies: got %+v", built.ACLPolicies)
	}
	if len(built.KVCounts) != 3 || built.KVCounts[2].Namespace != "team-a/" {
		t.Errorf("kv counts: got %+v", built.KVCounts)
	}
}

func TestBuildWithNothingCollected(t *testing.T) {
	inventory := scan.Inventory{Namespaces: []scan.NamespaceInventory{{Path: ""}}}
	built := Build("abcd", inventory)

	if built.KVCounts != nil || built.Summary.KVCounted || built.Summary.KVComplete {
		t.Errorf("KV counts must be marked as not counted, got %+v / %+v", built.KVCounts, built.Summary)
	}
	if built.AuditDevices != nil {
		t.Errorf("audit devices must stay null when not collected, got %+v", built.AuditDevices)
	}

	// Every list except the "not collected" ones must be [] in JSON, never null.
	encoded, err := json.Marshal(built)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	withoutNullable := strings.NewReplacer(`"kv_counts":null`, "", `"audit_devices":null`, "").Replace(string(encoded))
	if strings.Contains(withoutNullable, "null") {
		t.Errorf("unexpected null in:\n%s", encoded)
	}

	var markdown bytes.Buffer
	err = WriteMarkdown(&markdown, built)
	if err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}
	for _, expected := range []string{
		"| KV secrets | not counted |",
		"Not counted in this scan",
		"Not checked. Reading audit devices needs --sudo.",
		"## Secrets engines\n\nNone found.",
	} {
		if !strings.Contains(markdown.String(), expected) {
			t.Errorf("Markdown is missing %q:\n%s", expected, markdown.String())
		}
	}
}

func TestWriteMarkdown(t *testing.T) {
	inventory := sampleInventory()
	inventory.AuditDevices = []scan.AuditDevice{}
	built := Build("abcd", inventory)

	var markdown bytes.Buffer
	err := WriteMarkdown(&markdown, built)
	if err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}
	output := markdown.String()

	for _, expected := range []string{
		"# Mitch report",
		"- Scan: abcd",
		"- Version: 2.2.2 (Enterprise)",
		"- Cluster: vault-cluster-1",
		"| KV secrets | at least 15, in 3 mount(s) |",
		"| Plugins (built-in / registered) | 4 / 2 |",
		"## Scan gaps",
		"| kv_secret_count | (root) | kv1/ | 403 | permission denied | run mitch policy |",
		"| audit_devices | needs --sudo |",
		"| secrets engine | kv | 3 |",
		`| (root) | secret/ | kv | - | app \| team secrets |`,
		"| (root) | kv1/ | v1 | 4 | 0 | no, counts are a lower bound |",
		"| database | my-db | v1.0.0 | (needs --sudo) | - |",
		"| catalog | plugin | auth/old-auth@v0.1.0 | pending removal |",
		"| (root) | app | 2 |",
		"None. Vault is not writing an audit log.",
		"| 2.2.2 | 2026-11-01T00:00:00Z | 2026-10-20T00:00:00Z |",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("Markdown is missing %q:\n%s", expected, output)
		}
	}
}

func TestEscapeCells(t *testing.T) {
	got := escapeCells([]string{"a|b", "line\nbreak", `back\slash`, ""})
	want := []string{`a\|b`, "line break", `back\\slash`, "-"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCountLines(t *testing.T) {
	cases := map[string]int{"": 0, "a": 1, "a\n": 1, "a\nb": 2, "a\r\nb\r\n": 2}
	for text, expected := range cases {
		if got := countLines(text); got != expected {
			t.Errorf("countLines(%q) = %d, want %d", text, got, expected)
		}
	}
}

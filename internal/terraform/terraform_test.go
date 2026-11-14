package terraform

import (
	"strings"
	"testing"
	"time"

	"github.com/jfrappier/mitch/internal/scan"
)

// sampleInventory has a root namespace, a nested Enterprise namespace and an
// audit device, so every kind of resource is written.
func sampleInventory() scan.Inventory {
	return scan.Inventory{
		StartedAt:    time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC),
		VaultAddress: "https://vault.example.com:8200",
		AuditDevices: []scan.AuditDevice{
			{Path: "file/", Type: "file", Description: "main log", Options: map[string]string{"file_path": "/var/log/vault.log"}},
		},
		Namespaces: []scan.NamespaceInventory{
			{
				Path: "",
				SecretsEngines: []scan.Mount{
					{Path: "sys/", Type: "system"},
					{Path: "identity/", Type: "identity"},
					{Path: "cubbyhole/", Type: "cubbyhole"},
					{Path: "agent-registry/", Type: "agent_registry"},
					{Path: "secret/", Type: "kv", Description: `team "a" ${x}`, Options: map[string]string{"version": "2"},
						Config: scan.MountConfig{DefaultLeaseTTL: 60, MaxLeaseTTL: 3600}, SealWrap: true},
				},
				AuthMethods: []scan.Mount{
					{Path: "token/", Type: "token"},
					{Path: "userpass/", Type: "userpass", Local: true, Config: scan.MountConfig{DefaultLeaseTTL: 3600, TokenType: "default-service"}},
				},
				ACLPolicies: []scan.Policy{
					{Name: "root"},
					{Name: "app/../escape", Text: "path \"secret/*\" {\n  capabilities = [\"read\"]\n}"},
				},
			},
			{
				Path:           "team-a/",
				SecretsEngines: []scan.Mount{{Path: "secret/", Type: "kv"}},
				AuthMethods:    []scan.Mount{},
				ACLPolicies:    []scan.Policy{{Name: "default", Text: "path \"x\" {}\n"}},
			},
			{
				Path:           "team-a/dev/",
				SecretsEngines: []scan.Mount{},
				AuthMethods:    []scan.Mount{},
				ACLPolicies:    []scan.Policy{},
			},
		},
	}
}

func generateSample(t *testing.T) Result {
	t.Helper()
	result, err := Generate("abcd", sampleInventory())
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	return result
}

func requireContains(t *testing.T, result Result, file string, expected ...string) {
	t.Helper()
	content, found := result.Files[file]
	if !found {
		t.Fatalf("file %s was not written; files: %v", file, fileNames(result))
	}
	for _, text := range expected {
		if !strings.Contains(string(content), text) {
			t.Errorf("%s is missing %q:\n%s", file, text, content)
		}
	}
}

func fileNames(result Result) []string {
	names := []string{}
	for name := range result.Files {
		names = append(names, name)
	}
	return names
}

func TestCounts(t *testing.T) {
	result := generateSample(t)
	expected := Counts{Namespaces: 2, SecretsEngines: 2, AuthMethods: 1, Policies: 2, AuditDevices: 1}
	if result.Counts != expected {
		t.Errorf("counts:\ngot  %+v\nwant %+v", result.Counts, expected)
	}
}

func TestBuiltInMountsAndRootPolicyAreSkipped(t *testing.T) {
	result := generateSample(t)
	for _, content := range result.Files {
		for _, unexpected := range []string{`"sys"`, `"identity"`, `"cubbyhole"`, `"agent-registry"`, `"token"`, `"root"`} {
			if strings.Contains(string(content), unexpected) {
				t.Errorf("built-in %s must not be managed:\n%s", unexpected, content)
			}
		}
	}
}

func TestSecretsEngine(t *testing.T) {
	result := generateSample(t)
	requireContains(t, result, fileMounts,
		`resource "vault_mount" "mount_secret" {`,
		`  path                      = "secret"`,
		`  description               = "team \"a\" $${x}"`,
		`  default_lease_ttl_seconds = 60`,
		`  max_lease_ttl_seconds     = 3600`,
		`  seal_wrap                 = true`,
		`    "version" = "2"`,
		`resource "vault_mount" "team_a_mount_secret" {`,
		`  provider = vault.ns_team_a`,
	)
}

func TestAuthMethodWithTune(t *testing.T) {
	result := generateSample(t)
	requireContains(t, result, fileAuth,
		`resource "vault_auth_backend" "auth_userpass" {`,
		`  local = true`,
		`    default_lease_ttl = "1h"`,
		`    token_type        = "default-service"`,
	)
}

func TestPoliciesLiveInTheirOwnFiles(t *testing.T) {
	result := generateSample(t)

	// The name has a slash and "..", which must never escape the folder.
	requireContains(t, result, "policies/root/app_.._escape.hcl", `capabilities = ["read"]`)
	requireContains(t, result, filePolicies,
		`  name   = "app/../escape"`,
		`  policy = file("${path.module}/policies/root/app_.._escape.hcl")`,
		`  policy   = file("${path.module}/policies/team-a/default.hcl")`,
	)
	// The file must hold exactly Vault's text, with no line break added,
	// or "terraform plan" shows a change to the policy.
	content := string(result.Files["policies/root/app_.._escape.hcl"])
	expected := "path \"secret/*\" {\n  capabilities = [\"read\"]\n}"
	if content != expected {
		t.Errorf("policy file must be exactly Vault's text:\ngot  %q\nwant %q", content, expected)
	}
}

func TestNamespacesUseTheirParentProvider(t *testing.T) {
	result := generateSample(t)
	requireContains(t, result, fileProviders,
		`provider "vault" {}`,
		"  alias     = \"ns_team_a\"\n  namespace = \"team-a\"",
		"  alias     = \"ns_team_a_dev\"\n  namespace = \"team-a/dev\"",
	)
	requireContains(t, result, fileNamespaces,
		"resource \"vault_namespace\" \"namespace_team_a\" {\n  path = \"team-a\"\n}",
		"resource \"vault_namespace\" \"namespace_team_a_dev\" {\n  provider = vault.ns_team_a\n  path     = \"dev\"\n}",
	)
}

func TestImportBlocks(t *testing.T) {
	result := generateSample(t)
	requireContains(t, result, fileImports,
		"import {\n  to = vault_mount.mount_secret\n  id = \"secret\"\n}",
		"import {\n  provider = vault.ns_team_a\n  to       = vault_mount.team_a_mount_secret\n  id       = \"secret\"\n}",
		"import {\n  to = vault_policy.policy_app_escape\n  id = \"app/../escape\"\n}",
		"import {\n  provider = vault.ns_team_a\n  to       = vault_namespace.namespace_team_a_dev\n  id       = \"dev\"\n}",
		"import {\n  to = vault_audit.audit_file\n  id = \"file\"\n}",
	)
}

func TestAuditDevice(t *testing.T) {
	result := generateSample(t)
	requireContains(t, result, fileAudit,
		`resource "vault_audit" "audit_file" {`,
		`    "file_path" = "/var/log/vault.log"`,
	)
}

func TestAuditDevicesNotCollected(t *testing.T) {
	inventory := sampleInventory()
	inventory.AuditDevices = nil
	inventory.Skipped = []scan.SkippedCheck{{Check: "acl_policy_list", Namespace: "team-a/", Reason: "permission denied"}}

	result, err := Generate("abcd", inventory)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if _, written := result.Files[fileAudit]; written {
		t.Error("no audit file must be written when audit devices were not collected")
	}
	joined := strings.Join(result.Skipped, "\n")
	for _, expected := range []string{"audit devices: not collected", "acl_policy_list in namespace team-a/"} {
		if !strings.Contains(joined, expected) {
			t.Errorf("skipped notes are missing %q:\n%s", expected, joined)
		}
	}
}

func TestDuplicateNamesGetANumber(t *testing.T) {
	inventory := scan.Inventory{Namespaces: []scan.NamespaceInventory{{
		Path: "",
		SecretsEngines: []scan.Mount{
			{Path: "team-a/", Type: "kv"},
			{Path: "team_a/", Type: "kv"},
		},
	}}}
	result, err := Generate("abcd", inventory)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	requireContains(t, result, fileMounts, `"mount_team_a"`, `"mount_team_a_2"`)
}

func TestTwoPoliciesWithTheSameFileNameFail(t *testing.T) {
	inventory := scan.Inventory{Namespaces: []scan.NamespaceInventory{{
		Path:        "",
		ACLPolicies: []scan.Policy{{Name: "a/b"}, {Name: "a_b"}},
	}}}
	_, err := Generate("abcd", inventory)
	if err == nil || !strings.Contains(err.Error(), "same file name") {
		t.Errorf("expected a file-name clash error, got %v", err)
	}
}

func TestQuote(t *testing.T) {
	cases := map[string]string{
		`plain`:           `"plain"`,
		`a "quoted" word`: `"a \"quoted\" word"`,
		`back\slash`:      `"back\\slash"`,
		"line\nbreak\t":   `"line\nbreak\t"`,
		"bell\a":          `"bell\u0007"`,
		`${var}`:          `"$${var}"`,
		`%{if}`:           `"%%{if}"`,
	}
	for input, expected := range cases {
		if got := quote(input); got != expected {
			t.Errorf("quote(%q) = %s, want %s", input, got, expected)
		}
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"secret":        "secret",
		"Team-A/KV":     "team_a_kv",
		"1password":     "n_1password",
		"///":           "unnamed",
		"ünïcode mount": "n_code_mount",
	}
	for input, expected := range cases {
		if got := sanitizeName(input); got != expected {
			t.Errorf("sanitizeName(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestProviderDuration(t *testing.T) {
	// These match util.ShortDur in the Vault provider.
	cases := map[int64]string{
		1:     "1s",
		90:    "1m30s",
		600:   "10m",
		3600:  "1h",
		5400:  "1h30m",
		14400: "4h",
		3661:  "1h1m1s",
	}
	for seconds, expected := range cases {
		if got := providerDuration(seconds); got != expected {
			t.Errorf("providerDuration(%d) = %q, want %q", seconds, got, expected)
		}
	}
}

func TestAlignEquals(t *testing.T) {
	input := "a {\n  x = 1\n  long_name = 2\n\n  y = 3\n  map = {\n    \"k\" = \"v\"\n  }\n}"
	expected := "a {\n  x         = 1\n  long_name = 2\n\n  y = 3\n  map = {\n    \"k\" = \"v\"\n  }\n}"
	if got := alignEquals(input); got != expected {
		t.Errorf("got:\n%s\nwant:\n%s", got, expected)
	}
}

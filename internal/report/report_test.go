package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jfrappier/mitch/internal/drift"
	"github.com/jfrappier/mitch/internal/scan"
	"github.com/jfrappier/mitch/internal/terraform"
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
	built := Build("abcd", sampleInventory(), nil)

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
		// No --repo, so the one MITCH-GIT-001 finding.
		Findings: FindingCounts{High: 1},
	}
	if built.Summary != expected {
		t.Errorf("summary:\ngot  %+v\nwant %+v", built.Summary, expected)
	}
	if built.Scan.ID != "abcd" || built.Scan.VaultVersion != "2.2.2" || !built.Scan.Enterprise {
		t.Errorf("scan info: got %+v", built.Scan)
	}
}

func TestBuildGroupsMountsAndPlugins(t *testing.T) {
	built := Build("abcd", sampleInventory(), nil)

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
	built := Build("abcd", inventory, nil)

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
	built := Build("abcd", inventory, nil)

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

func TestBuildFindings(t *testing.T) {
	inventory := scan.Inventory{Namespaces: []scan.NamespaceInventory{
		{
			Path:           "",
			SecretsEngines: []scan.Mount{{Path: "secret/", Type: "kv"}},
			ACLPolicies: []scan.Policy{
				{Name: "admin", Text: "path \"*\" {\n  capabilities = [\"read\", \"sudo\"]\n}"},
				{Name: "broken", Text: "path {"},
			},
		},
		{
			Path:        "team-a/",
			ACLPolicies: []scan.Policy{{Name: "old", Text: "path \"old-kv/*\" {\n  capabilities = [\"read\"]\n}"}},
		},
	}}
	inventory.Skipped = []scan.SkippedCheck{{Check: "secrets_engines", Namespace: "team-a/", Reason: "permission denied"}}

	built := Build("abcd", inventory, nil)

	// The critical policy finding comes first, then the high "no git
	// repository" finding, because no --repo was given.
	if len(built.Findings) != 2 || built.Findings[0].Rule != "MITCH-POL-001" || built.Findings[0].Namespace != "(root)" {
		t.Errorf("expected MITCH-POL-001 in (root) first, got %+v", built.Findings)
	}
	if len(built.Findings) == 2 && (built.Findings[1].Rule != drift.RuleNoRepo || built.Findings[1].Namespace != "(all)") {
		t.Errorf("expected MITCH-GIT-001 in (all) second, got %+v", built.Findings)
	}
	expectedCounts := FindingCounts{Critical: 1, High: 1}
	if built.Summary.Findings != expectedCounts {
		t.Errorf("finding counts: got %+v, want %+v", built.Summary.Findings, expectedCounts)
	}
	if len(built.PoliciesNotAnalyzed) != 1 || built.PoliciesNotAnalyzed[0].Policy != "broken" || built.PoliciesNotAnalyzed[0].Namespace != "(root)" {
		t.Errorf("expected the broken policy as not analyzed, got %+v", built.PoliciesNotAnalyzed)
	}
	if !reflect.DeepEqual(built.UnknownMountCheckSkipped, []string{"team-a/"}) {
		t.Errorf("expected the missing-mount check skipped in team-a/, got %v", built.UnknownMountCheckSkipped)
	}
	if built.CountFindingsAtOrAbove("critical") != 1 || built.CountFindingsAtOrAbove("low") != 2 {
		t.Errorf("CountFindingsAtOrAbove is wrong for %+v", built.Findings)
	}

	var markdown bytes.Buffer
	err := WriteMarkdown(&markdown, built)
	if err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}
	for _, expected := range []string{
		"## Findings",
		"| critical | MITCH-POL-001 | (root) | admin | * | - | 1 |",
		"| high | MITCH-GIT-001 | (all) | - | - | - | - | no git repository was given",
		"| Findings (critical / high / medium / low) | 1 / 1 / 0 / 0 |",
		"## Git comparison\n\nNo git checkout was given (--repo)",
		"| (root) | broken |",
		"were not checked in these namespaces, because the scan could not list their mounts: team-a/",
	} {
		if !strings.Contains(markdown.String(), expected) {
			t.Errorf("Markdown is missing %q:\n%s", expected, markdown.String())
		}
	}
}

func TestBuildWithNoFindingsSaysNone(t *testing.T) {
	inventory := sampleInventory()
	built := Build("abcd", inventory, repoFromMitchTerraform(t, inventory))
	if built.Findings == nil || built.PoliciesNotAnalyzed == nil || built.UnknownMountCheckSkipped == nil {
		t.Errorf("finding lists must be [] in JSON, not null: %+v", built)
	}
	if built.Git.NotChecked == nil || built.Git.NotCompared == nil {
		t.Errorf("git lists must be [] in JSON, not null: %+v", built.Git)
	}
	var markdown bytes.Buffer
	err := WriteMarkdown(&markdown, built)
	if err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}
	if !strings.Contains(markdown.String(), "## Findings\n\nRules and fixes are explained in docs/findings.md.\n\nNone found.") {
		t.Errorf("expected an empty findings section:\n%s", markdown.String())
	}
}

// repoFromMitchTerraform writes what "mitch terraform" makes for inventory
// into a temporary folder and reads it back, so it matches Vault exactly.
func repoFromMitchTerraform(t *testing.T, inventory scan.Inventory) *drift.Repo {
	t.Helper()
	generated, err := terraform.Generate("abcd", inventory)
	if err != nil {
		t.Fatalf("terraform.Generate failed: %v", err)
	}
	folder := t.TempDir()
	for name, content := range generated.Files {
		full := filepath.Join(folder, filepath.FromSlash(name))
		err = os.MkdirAll(filepath.Dir(full), 0o700)
		if err != nil {
			t.Fatalf("creating the folder for %s failed: %v", name, err)
		}
		err = os.WriteFile(full, content, 0o600)
		if err != nil {
			t.Fatalf("writing %s failed: %v", name, err)
		}
	}
	repo, err := drift.ReadRepo(folder)
	if err != nil {
		t.Fatalf("drift.ReadRepo failed: %v", err)
	}
	return &repo
}

func TestBuildWithRepo(t *testing.T) {
	inventory := sampleInventory()
	folder := t.TempDir()
	// git has policy "app" with other text, and a mount Vault does not
	// have. It does not manage anything else, and one mount path comes
	// from a variable, so Mitch cannot work it out.
	files := map[string]string{
		"policies.tf": "resource \"vault_policy\" \"app\" {\n  name   = \"app\"\n  policy = \"path \\\"c\\\" {}\\n\"\n}\n",
		"mounts.tf": "resource \"vault_mount\" \"gone\" {\n  path = \"gone\"\n  type = \"kv\"\n}\n\n" +
			"variable \"name\" {}\n\nresource \"vault_auth_backend\" \"dynamic\" {\n  path = var.name\n  type = \"userpass\"\n}\n",
	}
	for name, content := range files {
		err := os.WriteFile(filepath.Join(folder, name), []byte(content), 0o600)
		if err != nil {
			t.Fatalf("writing %s failed: %v", name, err)
		}
	}
	repo, err := drift.ReadRepo(folder)
	if err != nil {
		t.Fatalf("drift.ReadRepo failed: %v", err)
	}

	built := Build("abcd", inventory, &repo)

	if !built.Git.RepoGiven || built.Git.Path != folder || built.Git.FilesRead != 2 || built.Git.Resources != 2 {
		t.Errorf("git section: got %+v", built.Git)
	}
	if len(built.Git.NotChecked) != 1 || built.Git.NotChecked[0].Address != "vault_auth_backend.dynamic" {
		t.Errorf("expected vault_auth_backend.dynamic as not checked, got %+v", built.Git.NotChecked)
	}

	rules := []string{}
	for _, finding := range built.Findings {
		rules = append(rules, finding.Severity+" "+finding.Rule+" "+finding.Namespace+" "+finding.Policy+finding.Path)
		if finding.Rule == drift.RuleNoRepo {
			t.Errorf("MITCH-GIT-001 must not appear when --repo was given")
		}
	}
	// High first. The auth method path is unknown, so the auth methods in
	// Vault (token/ is built in anyway) are not reported as not in git.
	expected := []string{
		"high MITCH-GIT-002 (root) app",
		"medium MITCH-GIT-007 (root) gone/",
		"medium MITCH-GIT-006 (root) kv1/",
		"medium MITCH-GIT-006 (root) pki/",
		"medium MITCH-GIT-006 (root) secret/",
		"medium MITCH-GIT-006 team-a/ secret/",
	}
	if !reflect.DeepEqual(rules, expected) {
		t.Errorf("findings:\ngot  %q\nwant %q", rules, expected)
	}
	if built.Summary.Findings != (FindingCounts{High: 1, Medium: 5}) {
		t.Errorf("finding counts: got %+v", built.Summary.Findings)
	}
	if built.Findings[0].File != "policies.tf" || built.Findings[0].Line != 1 {
		t.Errorf("a git finding must name its file and line, got %+v", built.Findings[0])
	}

	var markdown bytes.Buffer
	err = WriteMarkdown(&markdown, built)
	if err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}
	for _, want := range []string{
		"| high | MITCH-GIT-002 | (root) | app | - | policies.tf | 1 |",
		"## Git comparison\n\n- Checkout: " + folder,
		"- Terraform files read: 2",
		"- Vault resources found: 2",
		"| vault_auth_backend.dynamic | mounts.tf | 8 |",
		"Not compared:",
	} {
		if !strings.Contains(markdown.String(), want) {
			t.Errorf("Markdown is missing %q:\n%s", want, markdown.String())
		}
	}
}

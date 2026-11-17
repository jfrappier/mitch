package drift

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/jfrappier/mitch/internal/checks"
	"github.com/jfrappier/mitch/internal/scan"
	"github.com/jfrappier/mitch/internal/terraform"
)

// sampleInventory has a root namespace and a child namespace, each with a
// policy, a secrets engine and an auth method, plus Vault's built-ins.
func sampleInventory() scan.Inventory {
	return scan.Inventory{Namespaces: []scan.NamespaceInventory{
		{
			Path: "",
			SecretsEngines: []scan.Mount{
				{Path: "sys/", Type: "system"}, {Path: "identity/", Type: "identity"}, {Path: "cubbyhole/", Type: "cubbyhole"},
				{Path: "secret/", Type: "kv", Options: map[string]string{"version": "2"}},
			},
			AuthMethods: []scan.Mount{{Path: "token/", Type: "token"}, {Path: "userpass/", Type: "userpass"}},
			ACLPolicies: []scan.Policy{
				{Name: "root"},
				{Name: "default", Text: "path \"sys/capabilities-self\" {\n  capabilities = [\"update\"]\n}"},
				{Name: "app", Text: "path \"secret/data/app/*\" {\n  capabilities = [\"read\"]\n}"},
			},
		},
		{
			Path:           "team-a/",
			SecretsEngines: []scan.Mount{{Path: "kv/", Type: "kv"}},
			AuthMethods:    []scan.Mount{{Path: "approle/", Type: "approle"}},
			ACLPolicies:    []scan.Policy{{Name: "reader", Text: "path \"kv/*\" {\n  capabilities = [\"read\"]\n}"}},
		},
	}}
}

// writeFiles writes files into a new folder and returns its path.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	folder := t.TempDir()
	for name, content := range files {
		full := filepath.Join(folder, filepath.FromSlash(name))
		err := os.MkdirAll(filepath.Dir(full), 0o700)
		if err != nil {
			t.Fatalf("creating %s failed: %v", name, err)
		}
		err = os.WriteFile(full, []byte(content), 0o600)
		if err != nil {
			t.Fatalf("writing %s failed: %v", name, err)
		}
	}
	return folder
}

// readAndCompare reads a checkout and compares it with an inventory.
func readAndCompare(t *testing.T, folder string, inventory scan.Inventory) (Repo, Result) {
	t.Helper()
	repo, err := ReadRepo(folder)
	if err != nil {
		t.Fatalf("ReadRepo failed: %v", err)
	}
	return repo, Compare(repo, inventory)
}

// rulesFound lists "rule namespace object" for each finding, sorted.
func rulesFound(result Result) []string {
	found := []string{}
	for _, finding := range result.Findings {
		// Leave the namespace out when it is the root (empty), so the
		// expected strings in the tests never hold a double space.
		parts := []string{finding.Rule}
		if finding.Namespace != "" {
			parts = append(parts, finding.Namespace)
		}
		parts = append(parts, finding.Policy+finding.Path)
		found = append(found, strings.Join(parts, " "))
	}
	sort.Strings(found)
	return found
}

func requireRules(t *testing.T, result Result, expected ...string) {
	t.Helper()
	got := rulesFound(result)
	if len(got) == 0 && len(expected) == 0 {
		return
	}
	sort.Strings(expected)
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("findings:\ngot  %q\nwant %q\nfull: %+v", got, expected, result.Findings)
	}
}

// TestTerraformFromMitchHasNoDrift is the round trip: the Terraform that
// "mitch terraform" writes for a scan must compare as identical to it.
func TestTerraformFromMitchHasNoDrift(t *testing.T) {
	inventory := sampleInventory()
	generated, err := terraform.Generate("abcd", inventory)
	if err != nil {
		t.Fatalf("terraform.Generate failed: %v", err)
	}
	files := map[string]string{}
	for name, content := range generated.Files {
		files[name] = string(content)
	}
	folder := writeFiles(t, files)

	repo, result := readAndCompare(t, folder, inventory)
	if len(repo.NotChecked) != 0 {
		t.Errorf("everything mitch terraform writes must be checked: %+v", repo.NotChecked)
	}
	requireRules(t, result)
	if len(result.NotCompared) != 0 {
		t.Errorf("nothing should be left out: %v", result.NotCompared)
	}
	// default, app, reader, secret/, kv/, userpass/, approle/.
	if len(repo.Resources) != 7 {
		t.Errorf("expected 7 resources, got %d: %+v", len(repo.Resources), repo.Resources)
	}
}

func TestEveryKindOfDrift(t *testing.T) {
	folder := writeFiles(t, map[string]string{
		"main.tf": `
resource "vault_policy" "app" {
  name   = "app"
  policy = <<EOT
path "secret/data/app/*" {
  capabilities = ["read", "update"]
}
EOT
}

resource "vault_policy" "gone" {
  name   = "gone"
  policy = "path \"x\" { capabilities = [\"read\"] }"
}

resource "vault_mount" "secret" {
  path = "secret"
  type = "pki"
}

resource "vault_mount" "old" {
  path = "old"
  type = "kv"
}
`,
	})
	inventory := sampleInventory()
	inventory.Namespaces = inventory.Namespaces[:1]

	_, result := readAndCompare(t, folder, inventory)
	requireRules(t, result,
		RulePolicyTextDiffers+" app",
		RulePolicyNotInVault+" gone",
		RuleMountTypeDiffers+" secret/",
		RuleMountNotInVault+" old/",
		RuleMountNotInGit+" userpass/",
	)
	for _, finding := range result.Findings {
		if finding.Rule == RulePolicyTextDiffers && (finding.File != "main.tf" || finding.Line != 2) {
			t.Errorf("the finding must point at main.tf line 2, got %s:%d", finding.File, finding.Line)
		}
	}
}

func TestPolicyDifferingOnlyInWhitespace(t *testing.T) {
	folder := writeFiles(t, map[string]string{
		"policies/app.hcl": "path \"secret/data/app/*\" {\n  capabilities = [\"read\"]\n}\n",
		"main.tf": `
resource "vault_policy" "app" {
  name   = "app"
  policy = file("${path.module}/policies/app.hcl")
}
`,
	})
	inventory := scan.Inventory{Namespaces: []scan.NamespaceInventory{{Path: "", ACLPolicies: sampleInventory().Namespaces[0].ACLPolicies}}}
	_, result := readAndCompare(t, folder, inventory)
	requireRules(t, result, RulePolicyWhitespace+" app")
}

func TestNamespacesFromProviderAndResource(t *testing.T) {
	folder := writeFiles(t, map[string]string{
		"providers.tf": `
provider "vault" {}
provider "vault" {
  alias     = "team"
  namespace = "team-a"
}
`,
		"main.tf": `
resource "vault_policy" "reader" {
  provider = vault.team
  name     = "reader"
  policy   = "path \"kv/*\" {\n  capabilities = [\"read\"]\n}"
}

resource "vault_mount" "kv" {
  namespace = "team-a"
  path      = "kv"
  type      = "kv"
}

resource "vault_auth_backend" "approle" {
  provider = vault.team
  type     = "approle"
}
`,
	})
	inventory := sampleInventory()
	inventory.Namespaces = inventory.Namespaces[1:]
	_, result := readAndCompare(t, folder, inventory)
	requireRules(t, result)
}

func TestValuesMitchCannotWorkOut(t *testing.T) {
	folder := writeFiles(t, map[string]string{
		"main.tf": `
variable "name" {}

resource "vault_policy" "from_variable" {
  name   = var.name
  policy = "x"
}

resource "vault_policy" "text_from_variable" {
  name   = "app"
  policy = var.name
}

resource "vault_mount" "many" {
  for_each = toset(["a", "b"])
  path     = each.key
  type     = "kv"
}

resource "vault_auth_backend" "ldap" {
  type = "ldap"
}

resource "vault_ldap_auth_backend" "ldap" {
  path = vault_auth_backend.ldap.path
}
`,
	})
	inventory := scan.Inventory{Namespaces: []scan.NamespaceInventory{{
		Path:           "",
		SecretsEngines: []scan.Mount{{Path: "a/", Type: "kv"}},
		AuthMethods:    []scan.Mount{{Path: "ldap/", Type: "ldap"}},
		ACLPolicies:    []scan.Policy{{Name: "app", Text: "anything"}, {Name: "other", Text: "x"}},
	}}}
	repo, result := readAndCompare(t, folder, inventory)

	reasons := []string{}
	for _, gap := range repo.NotChecked {
		reasons = append(reasons, gap.Address)
	}
	sort.Strings(reasons)
	expected := []string{"vault_mount.many", "vault_policy.from_variable", "vault_policy.text_from_variable"}
	if !reflect.DeepEqual(reasons, expected) {
		t.Errorf("not checked:\ngot  %v\nwant %v", reasons, expected)
	}
	// The reference to another resource's path was worked out.
	foundReference := false
	for _, resource := range repo.Resources {
		if resource.Address == "vault_ldap_auth_backend.ldap" && resource.Name == "ldap/" {
			foundReference = true
		}
	}
	if !foundReference {
		t.Errorf("vault_ldap_auth_backend.ldap must resolve to ldap/: %+v", repo.Resources)
	}
	// "other" and "a/" might be the unknown resources, so they are not
	// reported; the text of "app" is unknown, so it is not compared.
	requireRules(t, result)
	if len(result.NotCompared) < 2 {
		t.Errorf("the gaps must be explained: %v", result.NotCompared)
	}
}

func TestScanGapsAreNotReportedAsDrift(t *testing.T) {
	folder := writeFiles(t, map[string]string{
		"main.tf": `
resource "vault_policy" "app" {
  name   = "app"
  policy = "x"
}
resource "vault_mount" "secret" {
  namespace = "team-b"
  path      = "secret"
  type      = "kv"
}
`,
	})
	inventory := scan.Inventory{
		Namespaces: []scan.NamespaceInventory{{Path: ""}},
		Skipped: []scan.SkippedCheck{
			{Check: checks.CheckPolicyList, Namespace: ""},
			{Check: checks.CheckNamespaces, Namespace: ""},
		},
	}
	_, result := readAndCompare(t, folder, inventory)
	requireRules(t, result)
	joined := strings.Join(result.NotCompared, "\n")
	for _, expected := range []string{"ACL policys in namespace (root)", "could not list every namespace"} {
		if !strings.Contains(joined, expected) {
			t.Errorf("not compared is missing %q:\n%s", expected, joined)
		}
	}
}

func TestPolicyTextNotReadByTheScan(t *testing.T) {
	folder := writeFiles(t, map[string]string{"main.tf": "resource \"vault_policy\" \"app\" {\n  name   = \"app\"\n  policy = \"x\"\n}\n"})
	inventory := scan.Inventory{Namespaces: []scan.NamespaceInventory{{Path: "", ACLPolicies: []scan.Policy{{Name: "app"}}}}}
	_, result := readAndCompare(t, folder, inventory)
	requireRules(t, result)
	if len(result.NotCompared) != 1 || !strings.Contains(result.NotCompared[0], "could not read it") {
		t.Errorf("expected the unread policy text to be explained: %v", result.NotCompared)
	}
}

func TestDefaultPathsAndJSON(t *testing.T) {
	folder := writeFiles(t, map[string]string{
		"auth.tf": `
resource "vault_github_auth_backend" "github" {
  organization = "example"
}
resource "vault_aws_secret_backend" "aws" {}
`,
		"mounts.tf.json": `{"resource": {"vault_mount": {"kv": {"path": "kv", "type": "kv"}}}}`,
	})
	inventory := scan.Inventory{Namespaces: []scan.NamespaceInventory{{
		Path:           "",
		SecretsEngines: []scan.Mount{{Path: "aws/", Type: "aws"}, {Path: "kv/", Type: "kv"}},
		AuthMethods:    []scan.Mount{{Path: "github/", Type: "github"}},
	}}}
	repo, result := readAndCompare(t, folder, inventory)
	requireRules(t, result)
	if repo.FilesRead != 2 {
		t.Errorf("expected 2 files read, got %d", repo.FilesRead)
	}
}

func TestFileOutsideTheCheckoutIsRefused(t *testing.T) {
	outside := writeFiles(t, map[string]string{"secret.hcl": "path \"x\" {}"})
	folder := writeFiles(t, map[string]string{
		"main.tf": "resource \"vault_policy\" \"app\" {\n  name   = \"app\"\n  policy = file(\"" + filepath.ToSlash(filepath.Join(outside, "secret.hcl")) + "\")\n}\n",
	})
	repo, err := ReadRepo(folder)
	if err != nil {
		t.Fatalf("ReadRepo failed: %v", err)
	}
	if len(repo.NotChecked) != 1 || !strings.Contains(repo.NotChecked[0].Reason, "points outside --repo") {
		t.Errorf("file() outside the checkout must be refused: %+v", repo.NotChecked)
	}
}

func TestReadRepoErrorsAreLoud(t *testing.T) {
	broken := writeFiles(t, map[string]string{"main.tf": "resource \"vault_policy\" \"app\" {\n"})
	_, err := ReadRepo(broken)
	if err == nil || !strings.Contains(err.Error(), "main.tf:") {
		t.Errorf("a broken file must fail with its name and line, got %v", err)
	}
	// A broken file is a problem in the Terraform, not in the --repo path.
	var pathError *PathError
	if errors.As(err, &pathError) {
		t.Errorf("a broken file must not be a PathError: %v", err)
	}

	_, err = ReadRepo(filepath.Join(t.TempDir(), "missing"))
	if err == nil || !strings.Contains(err.Error(), "--repo") || !errors.As(err, &pathError) {
		t.Errorf("a missing folder must fail with a PathError naming --repo, got %v", err)
	}

	file := filepath.Join(writeFiles(t, map[string]string{"a.tf": ""}), "a.tf")
	_, err = ReadRepo(file)
	if err == nil || !strings.Contains(err.Error(), "is not a folder") || !errors.As(err, &pathError) {
		t.Errorf("a file instead of a folder must fail with a PathError, got %v", err)
	}
}

func TestSkippedFoldersAndUnknownProvider(t *testing.T) {
	folder := writeFiles(t, map[string]string{
		".terraform/modules/x/main.tf": "resource \"vault_mount\" \"x\" {\n  path = \"x\"\n  type = \"kv\"\n}\n",
		"main.tf":                      "resource \"vault_mount\" \"y\" {\n  provider = vault.missing\n  path     = \"y\"\n  type     = \"kv\"\n}\n",
	})
	repo, err := ReadRepo(folder)
	if err != nil {
		t.Fatalf("ReadRepo failed: %v", err)
	}
	if repo.FilesRead != 1 {
		t.Errorf(".terraform must be skipped; files read: %d", repo.FilesRead)
	}
	if len(repo.NotChecked) != 1 || !strings.Contains(repo.NotChecked[0].Reason, "vault.missing is not defined") {
		t.Errorf("an unknown provider alias must be not checked: %+v", repo.NotChecked)
	}
}

func TestNoRepoFinding(t *testing.T) {
	finding := NoRepoFinding()
	if finding.Rule != RuleNoRepo || finding.Severity != "high" || !strings.Contains(finding.Message, "--repo") {
		t.Errorf("unexpected no-repo finding: %+v", finding)
	}
}

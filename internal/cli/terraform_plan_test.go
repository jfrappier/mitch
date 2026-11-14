//go:build integration && terraform

// This test runs the Terraform that Mitch generates through a real
// "terraform init" and "terraform plan" against a Vault dev server, and
// checks the plan only imports: nothing added or destroyed, and no change
// that would reach Vault.
//
// It needs the integration settings (see integration_test.go) plus:
//
//	MITCH_TEST_TERRAFORM   path to a terraform binary (1.5 or later)
//
// One change is expected and allowed: the provider's "disable_remount"
// setting on vault_auth_backend. It exists only in Terraform (Vault has no such
// setting), import leaves it empty in state, and the config default is false,
// so every imported auth method plans "+ disable_remount = false". Applying it
// only writes Terraform state and makes no call to Vault. The test reads the
// plan as JSON and fails on any other change.
// Source: https://github.com/hashicorp/terraform-provider-vault/blob/v5.13.0/internal/provider/schema_util.go
//
// "terraform init" downloads the hashicorp/vault provider from the
// Terraform registry. Run it with:
//
//	go test -tags "integration terraform" -count=1 -run TestTerraform ./internal/cli/
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/jfrappier/mitch/internal/exitcode"
)

// planSummary matches the last line of a plan, for example
// "Plan: 12 to import, 0 to add, 0 to change, 0 to destroy."
var planSummary = regexp.MustCompile(`Plan: (\d+) to import, (\d+) to add, (\d+) to change, (\d+) to destroy\.`)

// summaryCounts matches the count line "mitch terraform" prints.
var summaryCounts = regexp.MustCompile(`(\d+) namespace\(s\), (\d+) secrets engine\(s\), (\d+) auth method\(s\), (\d+) policy\(ies\), (\d+) audit device\(s\)`)

func TestTerraformPlanOnlyImports(t *testing.T) {
	terraformBinary := os.Getenv("MITCH_TEST_TERRAFORM")
	if terraformBinary == "" {
		t.Fatal("MITCH_TEST_TERRAFORM must be the path to a terraform binary to run this test")
	}
	vault := setUpVault(t)
	rootToken := os.Getenv("MITCH_TEST_VAULT_ROOT_TOKEN")

	// Configuration with non-default settings, so the plan proves they are
	// written the way the provider reads them back.
	err := vault.root.Sys().Mount("tf-plan-kv", &vaultapi.MountInput{
		Type:        "kv",
		Description: `team "a" ${not_a_template}`,
		Config: vaultapi.MountConfigInput{
			MaxLeaseTTL:               "2h",
			DefaultLeaseTTL:           "1h",
			ForceNoCache:              true,
			ListingVisibility:         "unauth",
			PassthroughRequestHeaders: []string{"X-Team", "X-Request-Source"},
			AllowedResponseHeaders:    []string{"X-Answer"},
			AuditNonHMACRequestKeys:   []string{"team"},
			AuditNonHMACResponseKeys:  []string{"team", "owner"},
		},
		Options: map[string]string{"version": "2"},
	})
	if err != nil {
		t.Fatalf("enabling the tf-plan-kv mount failed: %v", err)
	}
	t.Cleanup(func() { _ = vault.root.Sys().Unmount("tf-plan-kv") })

	err = vault.root.Sys().EnableAuthWithOptions("tf-plan-userpass", &vaultapi.EnableAuthOptions{
		Type:        "userpass",
		Description: "people",
		Config: vaultapi.MountConfigInput{
			DefaultLeaseTTL:           "1h",
			MaxLeaseTTL:               "4h",
			ListingVisibility:         "unauth",
			PassthroughRequestHeaders: []string{"X-Team"},
			AllowedResponseHeaders:    []string{"X-Answer", "X-Other"},
			AuditNonHMACRequestKeys:   []string{"username"},
			AuditNonHMACResponseKeys:  []string{"policies"},
		},
	})
	if err != nil {
		t.Fatalf("enabling the tf-plan-userpass auth method failed: %v", err)
	}
	t.Cleanup(func() { _ = vault.root.Sys().DisableAuth("tf-plan-userpass") })

	err = vault.root.Sys().PutPolicy("tf-plan", "path \"tf-plan-kv/data/*\" {\n  capabilities = [\"read\"]\n}\n")
	if err != nil {
		t.Fatalf("writing the tf-plan policy failed: %v", err)
	}
	t.Cleanup(func() { _ = vault.root.Sys().DeletePolicy("tf-plan") })

	// Scan with the root token and --sudo, so audit devices are included too.
	testDatabase(t)
	exitCode, _, stderr := runForTest("init")
	if exitCode != exitcode.Success {
		t.Fatalf("init failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	t.Setenv("VAULT_ADDR", vault.address)
	t.Setenv("VAULT_TOKEN", rootToken)
	t.Setenv("VAULT_NAMESPACE", "")
	exitCode, _, stderr = runForTest("scan", "--sudo", "--kv=false")
	if exitCode != exitcode.Success {
		t.Fatalf("scan failed: exit %d\nstderr: %s", exitCode, stderr)
	}

	outputDirectory := filepath.Join(t.TempDir(), "vault-terraform")
	exitCode, stdout, stderr := runForTest("terraform", "--output-dir", outputDirectory)
	if exitCode != exitcode.Success {
		t.Fatalf("mitch terraform failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	expectedImports := 0
	counts := summaryCounts.FindStringSubmatch(stdout)
	if counts == nil {
		t.Fatalf("could not read the resource counts from:\n%s", stdout)
	}
	for _, count := range counts[1:] {
		number, _ := strconv.Atoi(count)
		expectedImports += number
	}

	runTerraformBinary(t, terraformBinary, outputDirectory, "fmt", "-check", "-recursive", "-no-color")
	runTerraformBinary(t, terraformBinary, outputDirectory, "init", "-input=false", "-no-color")
	runTerraformBinary(t, terraformBinary, outputDirectory, "validate", "-no-color")
	planOutput := runTerraformBinary(t, terraformBinary, outputDirectory, "plan", "-input=false", "-no-color", "-out=plan.tfplan")

	summary := planSummary.FindStringSubmatch(planOutput)
	if summary == nil {
		t.Fatalf("the plan has no summary line:\n%s", planOutput)
	}
	if summary[2] != "0" || summary[4] != "0" {
		t.Errorf("the plan must not add or destroy anything, but it shows %s to add, %s to destroy:\n%s", summary[2], summary[4], planOutput)
	}
	if summary[1] != strconv.Itoa(expectedImports) {
		t.Errorf("expected %d imports (one per generated resource), the plan shows %s:\n%s", expectedImports, summary[1], planOutput)
	}

	// Every change must be only the Terraform-only disable_remount setting.
	planJSON := runTerraformBinary(t, terraformBinary, outputDirectory, "show", "-json", "-no-color", "plan.tfplan")
	for _, problem := range unexpectedPlanChanges(t, planJSON) {
		t.Errorf("unexpected change in the plan: %s\n%s", problem, planOutput)
	}
}

// plannedChanges is the part of "terraform show -json" this test reads.
// Docs: https://developer.hashicorp.com/terraform/internals/json-format
type plannedChanges struct {
	ResourceChanges []struct {
		Address string `json:"address"`
		Type    string `json:"type"`
		Change  struct {
			Actions []string               `json:"actions"`
			Before  map[string]interface{} `json:"before"`
			After   map[string]interface{} `json:"after"`
		} `json:"change"`
	} `json:"resource_changes"`
}

// unexpectedPlanChanges lists every planned change other than an import
// ("no-op") or a vault_auth_backend update where disable_remount is the only
// attribute that differs.
func unexpectedPlanChanges(t *testing.T, planJSON string) []string {
	t.Helper()
	var plan plannedChanges
	err := json.Unmarshal([]byte(planJSON), &plan)
	if err != nil {
		t.Fatalf("could not read the plan JSON: %v", err)
	}

	problems := []string{}
	for _, resource := range plan.ResourceChanges {
		actions := strings.Join(resource.Change.Actions, ",")
		if actions == "no-op" {
			continue
		}
		if actions != "update" || resource.Type != "vault_auth_backend" {
			problems = append(problems, resource.Address+" plans "+actions)
			continue
		}
		for _, name := range changedAttributes(resource.Change.Before, resource.Change.After) {
			if name != "disable_remount" {
				problems = append(problems, resource.Address+" changes "+name)
			}
		}
	}
	return problems
}

// changedAttributes names the top-level attributes whose values differ
// between before and after. The values are compared as JSON text.
func changedAttributes(before map[string]interface{}, after map[string]interface{}) []string {
	names := map[string]bool{}
	for name := range before {
		names[name] = true
	}
	for name := range after {
		names[name] = true
	}
	changed := []string{}
	for name := range names {
		beforeText, _ := json.Marshal(before[name])
		afterText, _ := json.Marshal(after[name])
		if string(beforeText) != string(afterText) {
			changed = append(changed, name)
		}
	}
	return changed
}

// runTerraformBinary runs one terraform command in directory and fails the test,
// with the full output, if it exits non-zero.
func runTerraformBinary(t *testing.T, binary string, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command(binary, arguments...) //nolint:gosec // the binary and arguments come from this test
	command.Dir = directory
	command.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if err != nil {
		t.Fatalf("terraform %s failed: %v\n%s", strings.Join(arguments, " "), err, output.String())
	}
	return output.String()
}

//go:build integration && terraform

// This test runs the Terraform that Mitch generates through a real
// "terraform init" and "terraform plan" against a Vault dev server, and
// checks the plan only imports: nothing added, changed or destroyed.
//
// It needs the integration settings (see integration_test.go) plus:
//
//	MITCH_TEST_TERRAFORM   path to a terraform binary (1.5 or later)
//
// "terraform init" downloads the hashicorp/vault provider from the
// Terraform registry. Run it with:
//
//	go test -tags "integration terraform" -count=1 -run TestTerraform ./internal/cli/
package cli

import (
	"bytes"
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
		Config:      vaultapi.MountConfigInput{MaxLeaseTTL: "2h", DefaultLeaseTTL: "1h"},
		Options:     map[string]string{"version": "2"},
	})
	if err != nil {
		t.Fatalf("enabling the tf-plan-kv mount failed: %v", err)
	}
	t.Cleanup(func() { _ = vault.root.Sys().Unmount("tf-plan-kv") })

	err = vault.root.Sys().EnableAuthWithOptions("tf-plan-userpass", &vaultapi.EnableAuthOptions{
		Type:        "userpass",
		Description: "people",
		Config:      vaultapi.MountConfigInput{DefaultLeaseTTL: "1h", MaxLeaseTTL: "4h"},
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
	planOutput := runTerraformBinary(t, terraformBinary, outputDirectory, "plan", "-input=false", "-no-color")

	summary := planSummary.FindStringSubmatch(planOutput)
	if summary == nil {
		t.Fatalf("the plan has no summary line:\n%s", planOutput)
	}
	if summary[2] != "0" || summary[3] != "0" || summary[4] != "0" {
		t.Errorf("the plan must only import, but it shows %s to add, %s to change, %s to destroy:\n%s", summary[2], summary[3], summary[4], planOutput)
	}
	if summary[1] != strconv.Itoa(expectedImports) {
		t.Errorf("expected %d imports (one per generated resource), the plan shows %s:\n%s", expectedImports, summary[1], planOutput)
	}
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

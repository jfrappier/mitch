package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jfrappier/mitch/internal/exitcode"
)

// inventoryForTerraform has one user mount, one auth method and one policy.
const inventoryForTerraform = `{"vault_address":"http://127.0.0.1:8200","namespaces":[{"path":"",` +
	`"secrets_engines":[{"path":"sys/","type":"system"},{"path":"team/","type":"kv","options":{"version":"2"}}],` +
	`"auth_methods":[{"path":"token/","type":"token"},{"path":"userpass/","type":"userpass"}],` +
	`"acl_policies":[{"name":"root","policy":""},{"name":"app","policy":"path \"team/*\" {\n  capabilities = [\"read\"]\n}\n"}]}]}`

func TestTerraformWritesFiles(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	scanID := saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), inventoryForTerraform)

	outputDirectory := filepath.Join(t.TempDir(), "vault-terraform")
	exitCode, stdout, stderr := runForTest("terraform", "--output-dir", outputDirectory)
	if exitCode != exitcode.Success {
		t.Fatalf("terraform failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	for _, expected := range []string{"scan " + scanID, "1 secrets engine(s), 1 auth method(s), 1 policy(ies)", "terraform init"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("summary is missing %q:\n%s", expected, stdout)
		}
	}
	for _, expected := range []string{"written as plain text", "audit devices: not collected"} {
		if !strings.Contains(stderr, expected) {
			t.Errorf("log is missing %q:\n%s", expected, stderr)
		}
	}

	for _, name := range []string{"versions.tf", "providers.tf", "secrets_engines.tf", "auth_methods.tf", "policies.tf", "imports.tf", "policies/root/app.hcl"} {
		fullPath := filepath.Join(outputDirectory, filepath.FromSlash(name))
		info, err := os.Stat(fullPath)
		if err != nil {
			t.Errorf("expected %s to be written: %v", name, err)
			continue
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != outputFileMode {
			t.Errorf("%s has mode %o, want %o", name, info.Mode().Perm(), outputFileMode)
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(outputDirectory, "policies", "root"))
		if err != nil || info.Mode().Perm() != outputDirectoryMode {
			t.Errorf("the policies folder must have mode %o: %v %v", outputDirectoryMode, info, err)
		}
	}
}

func TestTerraformRefusesANonEmptyFolder(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), inventoryForTerraform)

	outputDirectory := t.TempDir()
	existing := filepath.Join(outputDirectory, "main.tf")
	err := os.WriteFile(existing, []byte("# mine\n"), 0o600)
	if err != nil {
		t.Fatalf("writing %s failed: %v", existing, err)
	}

	exitCode, _, stderr := runForTest("terraform", "--output-dir", outputDirectory)
	if exitCode != exitcode.UsageError || !strings.Contains(stderr, "is not empty") {
		t.Errorf("expected exit %d refusing a non-empty folder, got exit %d\nstderr: %s", exitcode.UsageError, exitCode, stderr)
	}
	content, err := os.ReadFile(existing)
	if err != nil || string(content) != "# mine\n" {
		t.Errorf("the existing file must be untouched, got %q, %v", content, err)
	}
}

func TestTerraformErrors(t *testing.T) {
	cases := []struct {
		name      string
		setUp     func(t *testing.T, path string)
		arguments []string
		exitCode  int
		message   string
	}{
		{"no output dir", nil, []string{"terraform"}, exitcode.UsageError, "--output-dir is required"},
		{"no scans", func(t *testing.T, path string) { runForTest("init") }, []string{"terraform", "--output-dir", "OUT"}, exitcode.GeneralError, "this needs 1"},
		{"unknown scan", func(t *testing.T, path string) { runForTest("init") }, []string{"terraform", "--output-dir", "OUT", "--scan", "0000000000000000"}, exitcode.UsageError, "0000000000000000"},
		{"no database", nil, []string{"terraform", "--output-dir", "OUT"}, exitcode.GeneralError, "mitch init"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := testDatabase(t)
			if testCase.setUp != nil {
				testCase.setUp(t, path)
			}
			arguments := []string{}
			for _, argument := range testCase.arguments {
				if argument == "OUT" {
					argument = filepath.Join(t.TempDir(), "out")
				}
				arguments = append(arguments, argument)
			}
			exitCode, _, stderr := runForTest(arguments...)
			if exitCode != testCase.exitCode || !strings.Contains(stderr, testCase.message) {
				t.Errorf("expected exit %d with %q, got exit %d\nstderr: %s", testCase.exitCode, testCase.message, exitCode, stderr)
			}
		})
	}
}

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfrappier/mitch/internal/exitcode"
)

func TestPolicyPrintsBasePolicy(t *testing.T) {
	exitCode, stdout, _ := runForTest("policy")

	if exitCode != exitcode.Success {
		t.Errorf("expected exit code %d, got %d", exitcode.Success, exitCode)
	}
	if !strings.Contains(stdout, `path "sys/mounts"`) || strings.Contains(stdout, `"sudo"`) {
		t.Errorf("expected the base policy without sudo, got:\n%s", stdout)
	}
}

func TestPolicySudoPrintsAddOn(t *testing.T) {
	exitCode, stdout, _ := runForTest("policy", "--sudo")

	if exitCode != exitcode.Success {
		t.Errorf("expected exit code %d, got %d", exitcode.Success, exitCode)
	}
	if !strings.Contains(stdout, `path "sys/audit"`) || !strings.Contains(stdout, `"sudo"`) {
		t.Errorf("expected the sudo add-on policy, got:\n%s", stdout)
	}
}

func TestPolicyKVMountsPrintsKVPolicy(t *testing.T) {
	exitCode, stdout, stderr := runForTest("policy", "--kv2-mount", "secret", "--kv1-mount", "/legacy/")

	if exitCode != exitcode.Success {
		t.Fatalf("expected exit code %d, got %d\nstderr: %s", exitcode.Success, exitCode, stderr)
	}
	if !strings.Contains(stdout, `path "secret/metadata/*"`) || !strings.Contains(stdout, `path "legacy/*"`) {
		t.Errorf("expected list blocks for both mounts, got:\n%s", stdout)
	}
	if strings.Contains(stdout, `path "sys/mounts"`) {
		t.Errorf("the KV policy must not include the base policy, got:\n%s", stdout)
	}
}

func TestPolicyRejectsBadInput(t *testing.T) {
	cases := [][]string{
		{"policy", "--kv2-mount", "secret/*"},
		{"policy", "--kv2-mount", ""},
		{"policy", "--sudo", "--kv2-mount", "secret"},
		{"policy", "extra"},
	}
	for _, arguments := range cases {
		exitCode, stdout, stderr := runForTest(arguments...)
		if exitCode != exitcode.UsageError {
			t.Errorf("%v: expected exit code %d, got %d", arguments, exitcode.UsageError, exitCode)
		}
		if stdout != "" {
			t.Errorf("%v: must print no policy on bad input, got:\n%s", arguments, stdout)
		}
		if stderr == "" {
			t.Errorf("%v: expected an error message on stderr", arguments)
		}
	}
}

func TestScanWithoutTokenFailsLoudly(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	t.Setenv("HOME", t.TempDir()) // so a ~/.vault-token file on the test machine is not used

	exitCode, _, stderr := runForTest("scan")

	if exitCode != exitcode.GeneralError {
		t.Errorf("expected exit code %d, got %d", exitcode.GeneralError, exitCode)
	}
	if !strings.Contains(stderr, "VAULT_TOKEN") {
		t.Errorf("expected the error to name VAULT_TOKEN, got %q", stderr)
	}
}

func TestScanUnreachableVaultFailsLoudly(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "test-token")
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:1") // nothing listens on port 1
	t.Setenv("VAULT_MAX_RETRIES", "0")

	exitCode, _, stderr := runForTest("scan")

	if exitCode != exitcode.GeneralError {
		t.Errorf("expected exit code %d, got %d", exitcode.GeneralError, exitCode)
	}
	if !strings.Contains(stderr, "scan failed") || !strings.Contains(stderr, "VAULT_ADDR") {
		t.Errorf("expected a scan failure that mentions VAULT_ADDR, got %q", stderr)
	}
}

func TestScanRejectsExtraArguments(t *testing.T) {
	exitCode, _, stderr := runForTest("scan", "http://vault.example.com")

	if exitCode != exitcode.UsageError {
		t.Errorf("expected exit code %d, got %d", exitcode.UsageError, exitCode)
	}
	if !strings.Contains(stderr, "unexpected argument") {
		t.Errorf("expected an unexpected-argument error, got %q", stderr)
	}
}

func TestWriteOutputCreatesOwnerOnlyFile(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "inventory.json")

	// Create the file with loose permissions first, to check they get tightened.
	err := os.WriteFile(outputPath, []byte("old"), 0o644)
	if err != nil {
		t.Fatalf("creating the test file failed: %v", err)
	}

	context := runContext{stdout: os.Stdout, stderr: os.Stderr, logger: testLogger(t)}

	err = writeOutput(context, outputPath, []byte("{}\n"))
	if err != nil {
		t.Fatalf("writeOutput failed: %v", err)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("reading the file info failed: %v", err)
	}
	if info.Mode().Perm() != outputFileMode {
		t.Errorf("expected mode %o, got %o", outputFileMode, info.Mode().Perm())
	}

	content, _ := os.ReadFile(outputPath)
	if string(content) != "{}\n" {
		t.Errorf("expected the old content to be replaced, got %q", content)
	}
}

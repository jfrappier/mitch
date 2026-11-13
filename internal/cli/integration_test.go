//go:build integration

// Integration tests run Mitch against a real Vault dev server.
//
// They only build with the "integration" tag, and they fail (not skip) when
// the Vault settings below are missing, so a misconfigured CI run is loud.
//
//	MITCH_TEST_VAULT_ADDR        for example http://127.0.0.1:8200
//	MITCH_TEST_VAULT_ROOT_TOKEN  the dev server's root token
//
// Run them with:
//
//	go test -tags integration -count=1 ./internal/cli/
//
// See docs/development.md for how to start a Vault dev server.
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/jfrappier/mitch/internal/checks"
	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/scan"
)

// integrationVault holds a root client for setting up test fixtures.
type integrationVault struct {
	address string
	root    *vaultapi.Client
}

// setUpVault connects with the root token and loads Mitch's two policies.
func setUpVault(t *testing.T) integrationVault {
	t.Helper()

	address := os.Getenv("MITCH_TEST_VAULT_ADDR")
	rootToken := os.Getenv("MITCH_TEST_VAULT_ROOT_TOKEN")
	if address == "" || rootToken == "" {
		t.Fatal("MITCH_TEST_VAULT_ADDR and MITCH_TEST_VAULT_ROOT_TOKEN must be set to run integration tests")
	}

	config := vaultapi.DefaultConfig()
	config.Address = address
	rootClient, err := vaultapi.NewClient(config)
	if err != nil {
		t.Fatalf("creating the root Vault client failed: %v", err)
	}
	rootClient.SetToken(rootToken)

	err = rootClient.Sys().PutPolicy(checks.BasePolicyName, checks.RenderBasePolicy())
	if err != nil {
		t.Fatalf("writing the %s policy failed: %v", checks.BasePolicyName, err)
	}
	err = rootClient.Sys().PutPolicy(checks.SudoPolicyName, checks.RenderSudoPolicy())
	if err != nil {
		t.Fatalf("writing the %s policy failed: %v", checks.SudoPolicyName, err)
	}

	return integrationVault{address: address, root: rootClient}
}

// createToken makes a token with exactly the given policies (no default policy).
func (v integrationVault) createToken(t *testing.T, policies ...string) string {
	t.Helper()

	secret, err := v.root.Auth().Token().Create(&vaultapi.TokenCreateRequest{
		Policies:        policies,
		NoDefaultPolicy: true,
		TTL:             "10m",
	})
	if err != nil {
		t.Fatalf("creating a token with policies %v failed: %v", policies, err)
	}
	return secret.Auth.ClientToken
}

// runScanAs runs "mitch scan" with the given token and returns the exit code,
// the parsed inventory (if one was written) and the log output.
func (v integrationVault) runScanAs(t *testing.T, token string, extraArguments ...string) (int, *scan.Inventory, string) {
	t.Helper()

	t.Setenv("VAULT_ADDR", v.address)
	t.Setenv("VAULT_TOKEN", token)
	t.Setenv("VAULT_NAMESPACE", "")

	outputPath := filepath.Join(t.TempDir(), "inventory.json")
	arguments := append([]string{"scan", "--output", outputPath}, extraArguments...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Run(arguments, &stdout, &stderr)

	content, err := os.ReadFile(outputPath)
	if err != nil {
		return exitCode, nil, stderr.String()
	}

	var inventory scan.Inventory
	err = json.Unmarshal(content, &inventory)
	if err != nil {
		t.Fatalf("the inventory is not valid JSON: %v", err)
	}
	return exitCode, &inventory, stderr.String()
}

func TestScanWithBasePolicy(t *testing.T) {
	vault := setUpVault(t)
	token := vault.createToken(t, checks.BasePolicyName)

	exitCode, inventory, logs := vault.runScanAs(t, token)

	if exitCode != exitcode.Success {
		t.Fatalf("expected exit code %d, got %d\nlogs:\n%s", exitcode.Success, exitCode, logs)
	}
	if len(inventory.Skipped) != 0 {
		t.Errorf("expected no skipped checks, got %+v", inventory.Skipped)
	}
	if inventory.Health.Version == "" {
		t.Error("expected the Vault version to be recorded")
	}
	if len(inventory.Plugins) == 0 {
		t.Error("expected the plugin catalog to be read")
	}
	if len(inventory.VersionHistory) == 0 {
		t.Error("expected the version history to be read")
	}
	if len(inventory.Config) == 0 {
		t.Error("expected the sanitized config to be read")
	}
	if inventory.AuditDevices != nil {
		t.Error("audit devices must not be collected without --sudo")
	}

	root := inventory.Namespaces[0]
	if root.Path != "" {
		t.Errorf("expected the first namespace to be root, got %q", root.Path)
	}
	if !hasMount(root.SecretsEngines, "secret/") {
		t.Errorf("expected the dev server's secret/ mount, got %+v", root.SecretsEngines)
	}
	if !hasMount(root.AuthMethods, "token/") {
		t.Errorf("expected the token/ auth method, got %+v", root.AuthMethods)
	}
	if !hasPolicyWithText(root.ACLPolicies, checks.BasePolicyName) {
		t.Errorf("expected policy %q with its text, got %+v", checks.BasePolicyName, root.ACLPolicies)
	}
}

func TestScanWithSudoFlagButNoSudoPolicy(t *testing.T) {
	vault := setUpVault(t)
	token := vault.createToken(t, checks.BasePolicyName)

	exitCode, inventory, logs := vault.runScanAs(t, token, "--sudo")

	if exitCode != exitcode.PartialScan {
		t.Fatalf("expected exit code %d, got %d\nlogs:\n%s", exitcode.PartialScan, exitCode, logs)
	}

	skippedNames := map[string]bool{}
	for _, skipped := range inventory.Skipped {
		skippedNames[skipped.Check] = true
	}
	for _, expected := range []string{checks.CheckAuditDevices, checks.CheckPluginDetails, checks.CheckPluginRuntimes} {
		if !skippedNames[expected] {
			t.Errorf("expected check %q to be skipped, got %+v", expected, inventory.Skipped)
		}
	}
	if !strings.Contains(logs, "check skipped") {
		t.Errorf("expected a loud log line for each skipped check\nlogs:\n%s", logs)
	}
}

func TestScanWithSudoFlagAndSudoPolicy(t *testing.T) {
	vault := setUpVault(t)
	token := vault.createToken(t, checks.BasePolicyName, checks.SudoPolicyName)

	exitCode, inventory, logs := vault.runScanAs(t, token, "--sudo")

	if exitCode != exitcode.Success {
		t.Fatalf("expected exit code %d, got %d\nlogs:\n%s", exitcode.Success, exitCode, logs)
	}
	if inventory.AuditDevices == nil {
		t.Error("expected audit devices to be collected (an empty list is fine)")
	}
	if inventory.PluginRuntimes == nil {
		t.Error("expected plugin runtimes to be collected (an empty list is fine)")
	}
}

func TestScanWithNoPermissionsRecordsEverySkip(t *testing.T) {
	vault := setUpVault(t)

	// A policy that grants nothing Mitch needs, so even preflight is denied.
	err := vault.root.Sys().PutPolicy("mitch-test-nothing", `path "secret/nothing" { capabilities = ["deny"] }`)
	if err != nil {
		t.Fatalf("writing the test policy failed: %v", err)
	}
	token := vault.createToken(t, "mitch-test-nothing")

	exitCode, inventory, logs := vault.runScanAs(t, token)

	if exitCode != exitcode.PartialScan {
		t.Fatalf("expected exit code %d, got %d\nlogs:\n%s", exitcode.PartialScan, exitCode, logs)
	}
	for _, skipped := range inventory.Skipped {
		if skipped.HTTPStatus != 403 {
			t.Errorf("expected HTTP 403 for skipped check %q, got %d", skipped.Check, skipped.HTTPStatus)
		}
	}
	if !strings.Contains(logs, "preflight unavailable") {
		t.Errorf("expected a warning that preflight was unavailable\nlogs:\n%s", logs)
	}
}

func TestScanWithInvalidTokenFailsLoudly(t *testing.T) {
	vault := setUpVault(t)

	exitCode, _, logs := vault.runScanAs(t, "not-a-real-token")

	// sys/health needs no token, so the scan starts; every later call is
	// denied, which is recorded per check.
	if exitCode != exitcode.PartialScan {
		t.Fatalf("expected exit code %d, got %d\nlogs:\n%s", exitcode.PartialScan, exitCode, logs)
	}
	if !strings.Contains(logs, "http_status=403") {
		t.Errorf("expected HTTP 403 in the logs\nlogs:\n%s", logs)
	}
}

func hasMount(mounts []scan.Mount, path string) bool {
	for _, mount := range mounts {
		if mount.Path == path {
			return true
		}
	}
	return false
}

func hasPolicyWithText(policies []scan.Policy, name string) bool {
	for _, policy := range policies {
		if policy.Name == name && policy.Text != "" {
			return true
		}
	}
	return false
}

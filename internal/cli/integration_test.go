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
	arguments := append([]string{"scan", "--no-save", "--output", outputPath}, extraArguments...)

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

	// KV counting needs its own policy; it is tested separately below.
	exitCode, inventory, logs := vault.runScanAs(t, token, "--kv=false")

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
	if root.KVCounts != nil {
		t.Errorf("expected kv_counts to be null with --kv=false, got %+v", root.KVCounts)
	}
}

func TestScanWithSudoFlagButNoSudoPolicy(t *testing.T) {
	vault := setUpVault(t)
	token := vault.createToken(t, checks.BasePolicyName)

	exitCode, inventory, logs := vault.runScanAs(t, token, "--sudo", "--kv=false")

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

	exitCode, inventory, logs := vault.runScanAs(t, token, "--sudo", "--kv=false")

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

// Test KV mounts. Each KV test recreates them, so earlier runs don't matter.
const (
	testKV1Mount = "mitch-it-kv1/"
	testKV2Mount = "mitch-it-kv2/"

	// hiddenFolder is a folder name that must never appear in logs or output.
	hiddenFolder = "hidden-folder-name"
)

// setUpKVMounts creates two KV mounts with known contents:
//
//	mitch-it-kv1/ (KV v1): one, f/two                                 -> 2 secrets, 1 folder
//	mitch-it-kv2/ (KV v2): top (soft-deleted), app/db, app/api,
//	                       hidden-folder-name/x                       -> 4 secrets, 2 folders
func (v integrationVault) setUpKVMounts(t *testing.T) {
	t.Helper()

	mounts := map[string]string{testKV1Mount: "1", testKV2Mount: "2"}
	for mountPath, kvVersion := range mounts {
		// Unmounting a path that does not exist succeeds, so this clears
		// leftovers from an earlier run.
		err := v.root.Sys().Unmount(mountPath)
		if err != nil {
			t.Fatalf("removing old mount %s failed: %v", mountPath, err)
		}
		err = v.root.Sys().Mount(mountPath, &vaultapi.MountInput{Type: "kv", Options: map[string]string{"version": kvVersion}})
		if err != nil {
			t.Fatalf("enabling KV v%s at %s failed: %v", kvVersion, mountPath, err)
		}
		t.Cleanup(func() {
			_ = v.root.Sys().Unmount(mountPath)
		})
	}

	// KV v1 writes go straight to the path.
	for _, secretPath := range []string{"one", "f/two"} {
		_, err := v.root.Logical().Write(testKV1Mount+secretPath, map[string]any{"value": "x"})
		if err != nil {
			t.Fatalf("writing %s%s failed: %v", testKV1Mount, secretPath, err)
		}
	}

	// KV v2 writes go to <mount>/data/<path>, wrapped in "data".
	for _, secretPath := range []string{"top", "app/db", "app/api", hiddenFolder + "/x"} {
		_, err := v.root.Logical().Write(testKV2Mount+"data/"+secretPath, map[string]any{"data": map[string]any{"value": "x"}})
		if err != nil {
			t.Fatalf("writing %sdata/%s failed: %v", testKV2Mount, secretPath, err)
		}
	}

	// Soft-delete "top": its metadata stays, so it is still counted.
	_, err := v.root.Logical().Delete(testKV2Mount + "data/top")
	if err != nil {
		t.Fatalf("soft-deleting %sdata/top failed: %v", testKV2Mount, err)
	}
}

// allKVMounts returns every KV mount in the root namespace, so tests can
// grant list on all of them and expect a clean scan.
func (v integrationVault) allKVMounts(t *testing.T) []checks.KVMount {
	t.Helper()

	mounts, err := v.root.Sys().ListMounts()
	if err != nil {
		t.Fatalf("listing mounts failed: %v", err)
	}

	kvMounts := []checks.KVMount{}
	for mountPath, mount := range mounts {
		if mount.Type != "kv" {
			continue
		}
		kvVersion := 1
		if mount.Options["version"] == "2" {
			kvVersion = 2
		}
		kvMounts = append(kvMounts, checks.KVMount{Path: mountPath, Version: kvVersion})
	}
	return kvMounts
}

// kvCount finds one mount's count in the root namespace.
func kvCount(t *testing.T, inventory *scan.Inventory, mountPath string) scan.KVCount {
	t.Helper()
	for _, count := range inventory.Namespaces[0].KVCounts {
		if count.Mount == mountPath {
			return count
		}
	}
	t.Fatalf("no kv_counts entry for %s; got %+v", mountPath, inventory.Namespaces[0].KVCounts)
	return scan.KVCount{}
}

func TestScanCountsKVSecrets(t *testing.T) {
	vault := setUpVault(t)
	vault.setUpKVMounts(t)

	err := vault.root.Sys().PutPolicy(checks.KVPolicyName, checks.RenderKVPolicy(vault.allKVMounts(t)))
	if err != nil {
		t.Fatalf("writing the %s policy failed: %v", checks.KVPolicyName, err)
	}
	token := vault.createToken(t, checks.BasePolicyName, checks.KVPolicyName)

	exitCode, inventory, logs := vault.runScanAs(t, token)

	if exitCode != exitcode.Success {
		t.Fatalf("expected exit code %d, got %d\nskipped: %+v\nlogs:\n%s", exitcode.Success, exitCode, inventory.Skipped, logs)
	}

	expectedV1 := scan.KVCount{Mount: testKV1Mount, KVVersion: 1, Secrets: 2, Folders: 1, Complete: true}
	if got := kvCount(t, inventory, testKV1Mount); got != expectedV1 {
		t.Errorf("KV v1: expected %+v, got %+v", expectedV1, got)
	}
	expectedV2 := scan.KVCount{Mount: testKV2Mount, KVVersion: 2, Secrets: 4, Folders: 2, Complete: true}
	if got := kvCount(t, inventory, testKV2Mount); got != expectedV2 {
		t.Errorf("KV v2: expected %+v, got %+v", expectedV2, got)
	}
}

func TestScanKVWithoutKVPolicyIsPartial(t *testing.T) {
	vault := setUpVault(t)
	vault.setUpKVMounts(t)
	token := vault.createToken(t, checks.BasePolicyName)

	exitCode, inventory, logs := vault.runScanAs(t, token)

	if exitCode != exitcode.PartialScan {
		t.Fatalf("expected exit code %d, got %d\nlogs:\n%s", exitcode.PartialScan, exitCode, logs)
	}
	if got := kvCount(t, inventory, testKV2Mount); got.Complete {
		t.Errorf("expected an incomplete count without the KV policy, got %+v", got)
	}
	if !strings.Contains(logs, "mitch policy --kv2-mount "+testKV2Mount) {
		t.Errorf("expected the exact policy command in the logs\nlogs:\n%s", logs)
	}
}

func TestScanKVPartialPolicyIsIncompleteAndRedacted(t *testing.T) {
	vault := setUpVault(t)
	vault.setUpKVMounts(t)

	// Grant list on every KV mount except one folder of the test KV v2 mount:
	// the top of the mount and app/ only.
	otherMounts := []checks.KVMount{}
	for _, mount := range vault.allKVMounts(t) {
		if mount.Path != testKV2Mount {
			otherMounts = append(otherMounts, mount)
		}
	}
	partialPolicy := checks.RenderKVPolicy(otherMounts) +
		`path "` + testKV2Mount + `metadata/" { capabilities = ["list"] }` + "\n" +
		`path "` + testKV2Mount + `metadata/app/*" { capabilities = ["list"] }` + "\n"
	err := vault.root.Sys().PutPolicy("mitch-test-kv-partial", partialPolicy)
	if err != nil {
		t.Fatalf("writing the partial KV policy failed: %v", err)
	}
	token := vault.createToken(t, checks.BasePolicyName, "mitch-test-kv-partial")

	exitCode, inventory, logs := vault.runScanAs(t, token)

	if exitCode != exitcode.PartialScan {
		t.Fatalf("expected exit code %d, got %d\nlogs:\n%s", exitcode.PartialScan, exitCode, logs)
	}

	// top, app/db and app/api are counted; hidden-folder-name/ is found but cannot be listed.
	expected := scan.KVCount{Mount: testKV2Mount, KVVersion: 2, Secrets: 3, Folders: 2, Complete: false}
	if got := kvCount(t, inventory, testKV2Mount); got != expected {
		t.Errorf("expected %+v, got %+v", expected, got)
	}

	foundSkip := false
	for _, skipped := range inventory.Skipped {
		if skipped.Check == checks.CheckKVCount && skipped.Path == testKV2Mount+"metadata/*" && skipped.HTTPStatus == 403 {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Errorf("expected a 403 skip for %smetadata/*, got %+v", testKV2Mount, inventory.Skipped)
	}

	encoded, _ := json.Marshal(inventory)
	if strings.Contains(logs, hiddenFolder) || strings.Contains(string(encoded), hiddenFolder) {
		t.Errorf("folder name %q leaked into the logs or the inventory\nlogs:\n%s", hiddenFolder, logs)
	}
}

func TestScanSavesEncryptedAndExportsBack(t *testing.T) {
	vault := setUpVault(t)
	token := vault.createToken(t, checks.BasePolicyName)
	databasePath := testDatabase(t)

	exitCode, _, stderr := runForTest("init")
	if exitCode != exitcode.Success {
		t.Fatalf("init failed: exit %d\nstderr: %s", exitCode, stderr)
	}

	t.Setenv("VAULT_ADDR", vault.address)
	t.Setenv("VAULT_TOKEN", token)
	t.Setenv("VAULT_NAMESPACE", "")

	exitCode, stdout, stderr := runForTest("scan", "--kv=false")
	if exitCode != exitcode.Success {
		t.Fatalf("scan failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	scanID := strings.TrimSpace(stdout)
	if len(scanID) != 16 || strings.Contains(stdout, "{") {
		t.Fatalf("a saved scan must print only its id, got %q", stdout)
	}

	// The Vault address is in the inventory, so it must not appear in the file in the clear.
	raw, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatalf("reading the database file failed: %v", err)
	}
	if bytes.Contains(raw, []byte(vault.address)) || bytes.Contains(raw, []byte(checks.BasePolicyName)) {
		t.Error("scan data appears in the database file in the clear")
	}

	exitCode, stdout, stderr = runForTest("export", "--scan", scanID)
	if exitCode != exitcode.Success {
		t.Fatalf("export failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	var inventory scan.Inventory
	err = json.Unmarshal([]byte(stdout), &inventory)
	if err != nil {
		t.Fatalf("the export is not valid JSON: %v", err)
	}
	if inventory.VaultAddress != vault.address || !hasMount(inventory.Namespaces[0].SecretsEngines, "secret/") {
		t.Errorf("the export does not match the scan: address %q, mounts %+v", inventory.VaultAddress, inventory.Namespaces[0].SecretsEngines)
	}
}

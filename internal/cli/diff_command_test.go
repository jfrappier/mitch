package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfrappier/mitch/internal/diff"
	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/store"
)

// saveTestScan stores an inventory directly, without contacting Vault, and
// returns its id. Each call uses a later start time so the order is known.
func saveTestScan(t *testing.T, path string, startedAt time.Time, inventoryJSON string) string {
	t.Helper()
	opened, err := store.Open(context.Background(), path, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = opened.Close() }()

	scanID, err := opened.SaveScan(context.Background(), startedAt, startedAt.Add(time.Second), []byte(inventoryJSON))
	if err != nil {
		t.Fatalf("SaveScan failed: %v", err)
	}
	return scanID
}

// inventoryWithPolicy is a minimal saved inventory with one ACL policy.
func inventoryWithPolicy(policyName string) string {
	return `{"vault_address":"http://127.0.0.1:8200","health":{"version":"2.2.2"},` +
		`"namespaces":[{"path":"","secrets_engines":[],"auth_methods":[],` +
		`"acl_policies":[{"name":"` + policyName + `","policy":"path \"x\" {}"}],"kv_counts":null}]}`
}

func TestDiffComparesTheTwoNewestScans(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")

	start := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	saveTestScan(t, path, start, inventoryWithPolicy("oldest"))
	middleID := saveTestScan(t, path, start.Add(time.Hour), inventoryWithPolicy("middle"))
	newestID := saveTestScan(t, path, start.Add(2*time.Hour), inventoryWithPolicy("newest"))

	exitCode, stdout, stderr := runForTest("diff")
	if exitCode != exitcode.Success {
		t.Fatalf("diff failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	for _, expected := range []string{
		"Comparing scan " + middleID,
		"with scan " + newestID,
		"ACL policies in namespace (root)",
		"  + newest",
		"  - middle",
	} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("diff output is missing %q:\n%s", expected, stdout)
		}
	}
	if strings.Contains(stdout, "oldest") {
		t.Errorf("the oldest scan must not be part of the default diff:\n%s", stdout)
	}
	if !strings.Contains(stderr, "plain text") {
		t.Errorf("expected the plain-text warning, got:\n%s", stderr)
	}
}

func TestDiffFromToAndJSON(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")

	start := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	firstID := saveTestScan(t, path, start, inventoryWithPolicy("first"))
	saveTestScan(t, path, start.Add(time.Hour), inventoryWithPolicy("second"))
	thirdID := saveTestScan(t, path, start.Add(2*time.Hour), inventoryWithPolicy("third"))

	outputPath := filepath.Join(t.TempDir(), "diff.json")
	exitCode, _, stderr := runForTest("diff", "--from", firstID, "--to", thirdID, "--format", "json", "--output", outputPath)
	if exitCode != exitcode.Success {
		t.Fatalf("diff failed: exit %d\nstderr: %s", exitCode, stderr)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading the diff file failed: %v", err)
	}
	var result diff.Result
	err = json.Unmarshal(content, &result)
	if err != nil {
		t.Fatalf("the diff is not valid JSON: %v\n%s", err, content)
	}
	if result.From.ID != firstID || result.To.ID != thirdID {
		t.Errorf("expected %s -> %s, got %s -> %s", firstID, thirdID, result.From.ID, result.To.ID)
	}
	if len(result.Sections) != 1 || result.Sections[0].Name != diff.SectionACLPolicies ||
		result.Sections[0].Added[0] != "third" || result.Sections[0].Removed[0] != "first" {
		t.Errorf("unexpected sections: %+v", result.Sections)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm() != outputFileMode {
		t.Errorf("expected file mode %o, got %o", outputFileMode, info.Mode().Perm())
	}
}

func TestDiffNeedsTwoScans(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), inventoryWithPolicy("only"))

	exitCode, _, stderr := runForTest("diff")
	if exitCode != exitcode.GeneralError || !strings.Contains(stderr, "at least two saved scans") {
		t.Errorf("expected exit %d naming the need for two scans, got exit %d\nstderr: %s", exitcode.GeneralError, exitCode, stderr)
	}
}

func TestDiffUnknownScanIsAUsageError(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	knownID := saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), inventoryWithPolicy("only"))

	exitCode, _, stderr := runForTest("diff", "--from", knownID, "--to", "0000000000000000")
	if exitCode != exitcode.UsageError || !strings.Contains(stderr, "0000000000000000") {
		t.Errorf("expected exit %d naming the unknown id, got exit %d\nstderr: %s", exitcode.UsageError, exitCode, stderr)
	}
}

func TestDiffBadFlagsFailBeforeOpeningTheDatabase(t *testing.T) {
	// No database exists, so reaching the store would fail differently.
	testDatabase(t)

	cases := []struct {
		name      string
		arguments []string
		message   string
	}{
		{"bad format", []string{"diff", "--format", "yaml"}, `--format must be "text" or "json"`},
		{"only from", []string{"diff", "--from", "abc"}, "give both --from and --to"},
		{"only to", []string{"diff", "--to", "abc"}, "give both --from and --to"},
		{"same scan", []string{"diff", "--from", "abc", "--to", "abc"}, "the same scan"},
		{"extra argument", []string{"diff", "extra"}, "unexpected argument"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			exitCode, _, stderr := runForTest(testCase.arguments...)
			if exitCode != exitcode.UsageError || !strings.Contains(stderr, testCase.message) {
				t.Errorf("expected exit %d with %q, got exit %d\nstderr: %s", exitcode.UsageError, testCase.message, exitCode, stderr)
			}
		})
	}
}

func TestDiffWithoutDatabaseFails(t *testing.T) {
	testDatabase(t)

	exitCode, _, stderr := runForTest("diff")
	if exitCode != exitcode.GeneralError || !strings.Contains(stderr, "mitch init") {
		t.Errorf("expected exit %d telling the user to run mitch init, got exit %d\nstderr: %s", exitcode.GeneralError, exitCode, stderr)
	}
}

func TestDiffDamagedInventoryFailsLoudly(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	start := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	saveTestScan(t, path, start, inventoryWithPolicy("fine"))
	saveTestScan(t, path, start.Add(time.Hour), `{"namespaces":"not a list"}`)

	exitCode, _, stderr := runForTest("diff")
	if exitCode != exitcode.GeneralError || !strings.Contains(stderr, "not a valid inventory") {
		t.Errorf("expected exit %d for a damaged inventory, got exit %d\nstderr: %s", exitcode.GeneralError, exitCode, stderr)
	}
}

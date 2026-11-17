package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/report"
)

func TestReportShowsNewestScanAsMarkdown(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	start := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	saveTestScan(t, path, start, inventoryWithPolicy("older-policy"))
	newestID := saveTestScan(t, path, start.Add(time.Hour), inventoryWithPolicy("newest-policy"))

	exitCode, stdout, stderr := runForTest("report")
	if exitCode != exitcode.Success {
		t.Fatalf("report failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	for _, expected := range []string{"# Mitch report", "- Scan: " + newestID, "| (root) | newest-policy | 1 |"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("report is missing %q:\n%s", expected, stdout)
		}
	}
	if strings.Contains(stdout, "older-policy") {
		t.Errorf("the default report must use the newest scan:\n%s", stdout)
	}
	if !strings.Contains(stderr, "plain text") {
		t.Errorf("expected the plain-text warning, got:\n%s", stderr)
	}
}

func TestReportSavesJSONAndShowsMarkdown(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	start := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	olderID := saveTestScan(t, path, start, inventoryWithPolicy("older-policy"))
	saveTestScan(t, path, start.Add(time.Hour), inventoryWithPolicy("newest-policy"))

	outputPath := filepath.Join(t.TempDir(), "report.json")
	exitCode, stdout, stderr := runForTest("report", "--scan", olderID, "--output", outputPath)
	if exitCode != exitcode.Success {
		t.Fatalf("report failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	if !strings.HasPrefix(stdout, "# Mitch report") {
		t.Errorf("expected Markdown in the terminal, got:\n%s", stdout)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading the report file failed: %v", err)
	}
	var built report.Report
	err = json.Unmarshal(content, &built)
	if err != nil {
		t.Fatalf("the .json file is not JSON: %v\n%s", err, content)
	}
	if built.Scan.ID != olderID || len(built.ACLPolicies) != 1 || built.ACLPolicies[0].Name != "older-policy" {
		t.Errorf("the saved report is for the wrong scan: %+v", built)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm() != outputFileMode {
		t.Errorf("expected file mode %o, got %o", outputFileMode, info.Mode().Perm())
	}
}

func TestReportFormatJSONPrintsJSON(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), inventoryWithPolicy("only"))

	exitCode, stdout, stderr := runForTest("report", "--format", "json")
	if exitCode != exitcode.Success {
		t.Fatalf("report failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	var built report.Report
	err := json.Unmarshal([]byte(stdout), &built)
	if err != nil {
		t.Fatalf("--format json must print JSON: %v\n%s", err, stdout)
	}
	if built.Summary.ACLPolicies != 1 {
		t.Errorf("expected 1 policy in the summary, got %+v", built.Summary)
	}
}

func TestReportWarnsOnPartialScan(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	partial := `{"namespaces":[{"path":""}],"skipped":[{"check":"acl_policies","http_status":403,"reason":"permission denied"}]}`
	saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), partial)

	exitCode, stdout, stderr := runForTest("report")
	if exitCode != exitcode.Success {
		t.Fatalf("report failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "## Scan gaps") || !strings.Contains(stderr, "report is incomplete") {
		t.Errorf("expected scan gaps and an incomplete warning\nstdout: %s\nstderr: %s", stdout, stderr)
	}
}

// inventoryWithRootLikePolicy has one policy that grants sudo on every path,
// which is a critical finding (MITCH-POL-001).
func inventoryWithRootLikePolicy() string {
	return inventoryWithOnePolicy("*", `"read", "sudo"`)
}

// inventoryWithMissingMountPolicy reads from a mount that does not exist,
// which is a low finding (MITCH-POL-007).
func inventoryWithMissingMountPolicy() string {
	return inventoryWithOnePolicy("old-kv/*", `"read"`)
}

// inventoryWithOnePolicy has one policy named "admin" with one path block
// granting the given capability list, written as HCL (for example
// `"read", "sudo"`). There are no mounts, so only built-in paths exist.
func inventoryWithOnePolicy(policyPath string, capabilities string) string {
	policyText := "path \"" + policyPath + "\" {\n  capabilities = [" + capabilities + "]\n}"
	encoded, err := json.Marshal(policyText)
	if err != nil {
		panic(err)
	}
	return `{"vault_address":"http://127.0.0.1:8200","health":{"version":"2.2.2"},` +
		`"namespaces":[{"path":"","secrets_engines":[],"auth_methods":[],` +
		`"acl_policies":[{"name":"admin","policy":` + string(encoded) + `}],"kv_counts":null}]}`
}

func TestReportShowsFindings(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), inventoryWithRootLikePolicy())

	exitCode, stdout, stderr := runForTest("report")
	if exitCode != exitcode.Success {
		t.Fatalf("without --fail-on, findings must not change the exit code: exit %d\nstderr: %s", exitCode, stderr)
	}
	// Without --repo there is also the one high "no git repository" finding.
	for _, expected := range []string{"## Findings", "| critical | MITCH-POL-001 | (root) | admin | * | - | 1 |", "| high | MITCH-GIT-001 | (all) |", "| 1 / 1 / 0 / 0 |"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("report is missing %q:\n%s", expected, stdout)
		}
	}
}

func TestReportFailOn(t *testing.T) {
	cases := []struct {
		name      string
		inventory string
		failOn    string
		exitCode  int
	}{
		// Without --repo, MITCH-GIT-001 is a high finding, so it counts too.
		{"no repo, fail on critical", inventoryWithMissingMountPolicy(), "critical", exitcode.Success},
		{"no repo, fail on high", inventoryWithMissingMountPolicy(), "high", exitcode.FindingsAboveThreshold},
		{"low finding, fail on low", inventoryWithMissingMountPolicy(), "low", exitcode.FindingsAboveThreshold},
		{"critical finding, fail on critical", inventoryWithRootLikePolicy(), "critical", exitcode.FindingsAboveThreshold},
		{"critical finding, fail on medium", inventoryWithRootLikePolicy(), "medium", exitcode.FindingsAboveThreshold},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := testDatabase(t)
			runForTest("init")
			saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), testCase.inventory)

			exitCode, stdout, stderr := runForTest("report", "--fail-on", testCase.failOn)
			if exitCode != testCase.exitCode {
				t.Fatalf("expected exit %d, got %d\nstderr: %s", testCase.exitCode, exitCode, stderr)
			}
			if !strings.HasPrefix(stdout, "# Mitch report") {
				t.Errorf("the report must print even when --fail-on fails:\n%s", stdout)
			}
			if testCase.exitCode == exitcode.FindingsAboveThreshold && !strings.Contains(stderr, "fail_on="+testCase.failOn) {
				t.Errorf("expected the --fail-on error in the log:\n%s", stderr)
			}
		})
	}
}

// repoManagingMissingMountPolicy writes a checkout whose Terraform manages
// exactly the policy in inventoryWithMissingMountPolicy, with the same text.
func repoManagingMissingMountPolicy(t *testing.T) string {
	t.Helper()
	folder := t.TempDir()
	terraform := `resource "vault_policy" "admin" {
  name   = "admin"
  policy = "path \"old-kv/*\" {\n  capabilities = [\"read\"]\n}"
}
`
	err := os.WriteFile(filepath.Join(folder, "main.tf"), []byte(terraform), 0o600)
	if err != nil {
		t.Fatalf("writing main.tf failed: %v", err)
	}
	return folder
}

func TestReportWithRepo(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), inventoryWithMissingMountPolicy())
	folder := repoManagingMissingMountPolicy(t)

	// Git matches Vault, so only the low policy finding is left, and
	// --fail-on high passes.
	exitCode, stdout, stderr := runForTest("report", "--repo", folder, "--fail-on", "high")
	if exitCode != exitcode.Success {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}
	for _, expected := range []string{"## Git comparison", "- Checkout: " + folder, "- Terraform files read: 1", "- Vault resources found: 1", "| 0 / 0 / 0 / 1 |"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("report is missing %q:\n%s", expected, stdout)
		}
	}
	if strings.Contains(stdout, "MITCH-GIT-") {
		t.Errorf("git matches Vault, so there must be no git findings:\n%s", stdout)
	}
	if !strings.Contains(stderr, "files_read=1") {
		t.Errorf("expected the files read in the log:\n%s", stderr)
	}
}

func TestReportWithRepoFindsDrift(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	// Vault has "admin" reading old-kv/*; git has nothing.
	saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), inventoryWithMissingMountPolicy())
	folder := t.TempDir()

	exitCode, stdout, stderr := runForTest("report", "--repo", folder, "--format", "json", "--fail-on", "medium")
	if exitCode != exitcode.FindingsAboveThreshold {
		t.Fatalf("expected exit %d, got %d\nstderr: %s", exitcode.FindingsAboveThreshold, exitCode, stderr)
	}
	var built report.Report
	err := json.Unmarshal([]byte(stdout), &built)
	if err != nil {
		t.Fatalf("the JSON report does not parse: %v\n%s", err, stdout)
	}
	if !built.Git.RepoGiven || built.Git.FilesRead != 0 || len(built.Findings) != 2 || built.Findings[0].Rule != "MITCH-GIT-004" {
		t.Errorf("expected MITCH-GIT-004 for the policy not in git, got git %+v findings %+v", built.Git, built.Findings)
	}
	if !strings.Contains(stderr, "holds no .tf or .tf.json files") {
		t.Errorf("an empty checkout must be warned about:\n%s", stderr)
	}
}

func TestReportRepoErrors(t *testing.T) {
	testDatabase(t)

	// A wrong path is a usage error, reported before the database is opened.
	missing := filepath.Join(t.TempDir(), "missing")
	exitCode, _, stderr := runForTest("report", "--repo", missing)
	if exitCode != exitcode.UsageError || !strings.Contains(stderr, "mitch report: --repo") {
		t.Errorf("missing --repo folder: exit %d, want %d\n%s", exitCode, exitcode.UsageError, stderr)
	}

	// A broken Terraform file fails loudly, naming the file and line.
	broken := t.TempDir()
	err := os.WriteFile(filepath.Join(broken, "main.tf"), []byte("resource \"vault_policy\" \"x\" {\n"), 0o600)
	if err != nil {
		t.Fatalf("writing main.tf failed: %v", err)
	}
	exitCode, _, stderr = runForTest("report", "--repo", broken)
	if exitCode != exitcode.GeneralError || !strings.Contains(stderr, "reading the Terraform in --repo failed") || !strings.Contains(stderr, "main.tf:") {
		t.Errorf("broken main.tf: exit %d, want %d\n%s", exitCode, exitcode.GeneralError, stderr)
	}
	if strings.Contains(stderr, "cannot open the database") {
		t.Errorf("--repo must be checked before the database is opened:\n%s", stderr)
	}
}

func TestReportWarnsOnUnparsablePolicy(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	broken := `{"namespaces":[{"path":"","secrets_engines":[],"auth_methods":[],"acl_policies":[{"name":"broken","policy":"path {"}]}]}`
	saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), broken)

	exitCode, stdout, stderr := runForTest("report")
	if exitCode != exitcode.Success {
		t.Fatalf("report failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, "could not be parsed") || !strings.Contains(stderr, "policies_not_analyzed=1") {
		t.Errorf("expected the unparsable policy in the report and the log\nstdout: %s\nstderr: %s", stdout, stderr)
	}
}

func TestReportErrors(t *testing.T) {
	cases := []struct {
		name      string
		setUp     func(t *testing.T, path string)
		arguments []string
		exitCode  int
		message   string
	}{
		{"no database", nil, []string{"report"}, exitcode.GeneralError, "mitch init"},
		{"no scans yet", func(t *testing.T, path string) { runForTest("init") }, []string{"report"}, exitcode.GeneralError, "this needs 1"},
		{"unknown scan", func(t *testing.T, path string) { runForTest("init") }, []string{"report", "--scan", "0000000000000000"}, exitcode.UsageError, "0000000000000000"},
		{"bad format", nil, []string{"report", "--format", "html"}, exitcode.UsageError, `--format must be "markdown" or "json"`},
		{"bad extension", nil, []string{"report", "--output", "report.csv"}, exitcode.UsageError, "must end in .md (Markdown) or .json (JSON)"},
		{"extra argument", nil, []string{"report", "extra"}, exitcode.UsageError, "unexpected argument"},
		{"bad fail-on", nil, []string{"report", "--fail-on", "severe"}, exitcode.UsageError, `--fail-on "severe" is not a severity; use one of: critical, high, medium, low`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := testDatabase(t)
			if testCase.setUp != nil {
				testCase.setUp(t, path)
			}
			exitCode, _, stderr := runForTest(testCase.arguments...)
			if exitCode != testCase.exitCode || !strings.Contains(stderr, testCase.message) {
				t.Errorf("expected exit %d with %q, got exit %d\nstderr: %s", testCase.exitCode, testCase.message, exitCode, stderr)
			}
		})
	}
}

func TestOutputFileUnwritableFailsLoudly(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), inventoryWithPolicy("only"))

	missingDirectory := filepath.Join(t.TempDir(), "does-not-exist", "report.md")
	exitCode, _, stderr := runForTest("report", "--output", missingDirectory)
	if exitCode != exitcode.GeneralError || !strings.Contains(stderr, "could not write the report") {
		t.Errorf("expected exit %d naming the write failure, got exit %d\nstderr: %s", exitcode.GeneralError, exitCode, stderr)
	}
}

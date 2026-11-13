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

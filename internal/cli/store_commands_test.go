package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jfrappier/mitch/internal/encryption"
	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/store"
)

const testPassphrase = "correct horse battery staple"

// useFastKDF swaps in cheap Argon2id settings for the length of one test.
func useFastKDF(t *testing.T) {
	t.Helper()
	original := newKDFParams
	newKDFParams = func() (encryption.KDFParams, error) {
		params, err := encryption.NewKDFParams()
		params.Time = 1
		params.MemoryKiB = 1024
		params.Threads = 1
		return params, err
	}
	t.Cleanup(func() { newKDFParams = original })
}

// testDatabase points MITCH_DB and MITCH_PASSPHRASE at a fresh path and
// returns that path. The database itself is not created.
func testDatabase(t *testing.T) string {
	t.Helper()
	useFastKDF(t)
	path := filepath.Join(t.TempDir(), "mitch.db")
	t.Setenv(databaseEnvVar, path)
	t.Setenv(passphraseEnvVar, testPassphrase)
	return path
}

func TestInitCreatesDatabase(t *testing.T) {
	path := testDatabase(t)

	exitCode, stdout, stderr := runForTest("init")
	if exitCode != exitcode.Success {
		t.Fatalf("expected exit code %d, got %d\nstderr: %s", exitcode.Success, exitCode, stderr)
	}
	if !strings.Contains(stdout, path) {
		t.Errorf("expected the path in the output, got %q", stdout)
	}
	if !strings.Contains(stderr, "cannot be recovered") {
		t.Errorf("expected the lost-passphrase warning, got:\n%s", stderr)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected the database file to exist: %v", err)
	}
}

func TestInitTwiceRefusesToOverwrite(t *testing.T) {
	testDatabase(t)
	runForTest("init")

	exitCode, _, stderr := runForTest("init")
	if exitCode != exitcode.GeneralError || !strings.Contains(stderr, "will not overwrite") {
		t.Errorf("expected a refusal to overwrite (exit %d), got exit %d\nstderr: %s", exitcode.GeneralError, exitCode, stderr)
	}
}

func TestInitNeedsAPassphrase(t *testing.T) {
	testDatabase(t)
	t.Setenv(passphraseEnvVar, "")

	exitCode, _, stderr := runForTest("init")
	if exitCode != exitcode.GeneralError || !strings.Contains(stderr, passphraseEnvVar) {
		t.Errorf("expected an error naming %s, got exit %d\nstderr: %s", passphraseEnvVar, exitCode, stderr)
	}
}

func TestInitRejectsShortPassphrase(t *testing.T) {
	path := testDatabase(t)
	t.Setenv(passphraseEnvVar, "short")

	exitCode, _, stderr := runForTest("init")
	if exitCode != exitcode.GeneralError || !strings.Contains(stderr, "at least 12") {
		t.Errorf("expected a length error, got exit %d\nstderr: %s", exitCode, stderr)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a rejected init must not leave a database behind")
	}
}

func TestPassphraseFileWinsAndTrimsOneLineBreak(t *testing.T) {
	path := testDatabase(t)
	t.Setenv(passphraseEnvVar, "a different passphrase entirely")

	passphraseFile := filepath.Join(t.TempDir(), "passphrase")
	err := os.WriteFile(passphraseFile, []byte(testPassphrase+"\n"), 0o600)
	if err != nil {
		t.Fatalf("writing the passphrase file failed: %v", err)
	}

	exitCode, _, stderr := runForTest("init", "--passphrase-file", passphraseFile)
	if exitCode != exitcode.Success {
		t.Fatalf("init failed: exit %d\nstderr: %s", exitCode, stderr)
	}

	// The file's passphrase, without its line break, must unlock the database.
	opened, err := store.Open(context.Background(), path, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("the passphrase from the file did not unlock the database: %v", err)
	}
	_ = opened.Close()
}

// writeOpenPassphraseFile writes the test passphrase to a file that other
// users can read (0644), and sets those permissions explicitly in case the
// umask removed them.
func writeOpenPassphraseFile(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not use Unix permission bits, so Mitch does not check them there")
	}
	passphraseFile := filepath.Join(t.TempDir(), "passphrase")
	err := os.WriteFile(passphraseFile, []byte(testPassphrase+"\n"), 0o600)
	if err != nil {
		t.Fatalf("writing the passphrase file failed: %v", err)
	}
	err = os.Chmod(passphraseFile, 0o644) //nolint:gosec // the test needs a file other users can read
	if err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	return passphraseFile
}

func TestPassphraseFileReadableByOthersIsRefused(t *testing.T) {
	path := testDatabase(t)
	passphraseFile := writeOpenPassphraseFile(t)

	exitCode, _, stderr := runForTest("init", "--passphrase-file", passphraseFile)
	if exitCode != exitcode.GeneralError {
		t.Errorf("exit %d, want %d", exitCode, exitcode.GeneralError)
	}
	for _, expected := range []string{"refusing to use the passphrase file", "chmod 600 " + passphraseFile, "--allow-insecure-passphrase-file"} {
		if !strings.Contains(stderr, expected) {
			t.Errorf("stderr is missing %q:\n%s", expected, stderr)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a refused init must not create the database")
	}
}

func TestAllowInsecurePassphraseFileWarnsAndContinues(t *testing.T) {
	path := testDatabase(t)
	passphraseFile := writeOpenPassphraseFile(t)

	exitCode, _, stderr := runForTest("init", "--passphrase-file", passphraseFile, "--allow-insecure-passphrase-file")
	if exitCode != exitcode.Success {
		t.Fatalf("init failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stderr, "using a passphrase file that other users can read") || !strings.Contains(stderr, "level=WARN") {
		t.Errorf("expected a warning about the open file:\n%s", stderr)
	}
	opened, err := store.Open(context.Background(), path, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("the database did not open with the file's passphrase: %v", err)
	}
	_ = opened.Close()
}

func TestHistoryEmptyAndWrongPassphrase(t *testing.T) {
	testDatabase(t)
	runForTest("init")

	exitCode, stdout, _ := runForTest("history")
	if exitCode != exitcode.Success || !strings.Contains(stdout, "No saved scans yet") {
		t.Errorf("expected an empty-history message, got exit %d: %q", exitCode, stdout)
	}

	t.Setenv(passphraseEnvVar, "not the right passphrase")
	exitCode, _, stderr := runForTest("history")
	if exitCode != exitcode.GeneralError || !strings.Contains(stderr, "passphrase is wrong") {
		t.Errorf("expected a wrong-passphrase error, got exit %d\nstderr: %s", exitCode, stderr)
	}
}

func TestHistoryAndExportShowSavedScan(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")

	opened, err := store.Open(context.Background(), path, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	started := time.Date(2026, 11, 13, 9, 30, 0, 0, time.UTC)
	scanID, err := opened.SaveScan(context.Background(), started, started.Add(2*time.Second), []byte(`{"mitch_version":"test"}`))
	if err != nil {
		t.Fatalf("SaveScan failed: %v", err)
	}
	_ = opened.Close()

	exitCode, stdout, stderr := runForTest("history")
	if exitCode != exitcode.Success {
		t.Fatalf("history failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	for _, expected := range []string{"ID", scanID, "2026-11-13 09:30:00", "2s"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("history output is missing %q:\n%s", expected, stdout)
		}
	}

	exitCode, stdout, stderr = runForTest("export", "--scan", scanID)
	if exitCode != exitcode.Success {
		t.Fatalf("export failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stdout, `"mitch_version": "test"`) {
		t.Errorf("expected the indented inventory, got:\n%s", stdout)
	}
}

func TestExportNeedsAKnownScan(t *testing.T) {
	testDatabase(t)
	runForTest("init")

	exitCode, _, stderr := runForTest("export")
	if exitCode != exitcode.UsageError || !strings.Contains(stderr, "--scan is required") {
		t.Errorf("expected a usage error for missing --scan, got exit %d\nstderr: %s", exitCode, stderr)
	}

	exitCode, _, stderr = runForTest("export", "--scan", "0000000000000000")
	if exitCode != exitcode.UsageError || !strings.Contains(stderr, "mitch history") {
		t.Errorf("expected a not-found usage error, got exit %d\nstderr: %s", exitCode, stderr)
	}
}

func TestScanWithoutDatabaseFailsBeforeContactingVault(t *testing.T) {
	testDatabase(t)
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:1")
	t.Setenv("VAULT_TOKEN", "test-token")

	exitCode, _, stderr := runForTest("scan")
	if exitCode != exitcode.GeneralError {
		t.Fatalf("expected exit code %d, got %d", exitcode.GeneralError, exitCode)
	}
	if !strings.Contains(stderr, "mitch init") || !strings.Contains(stderr, "--no-save") {
		t.Errorf("expected advice to run mitch init or pass --no-save, got:\n%s", stderr)
	}
	if strings.Contains(stderr, "VAULT_ADDR") {
		t.Errorf("the scan must stop before contacting Vault, got:\n%s", stderr)
	}
}

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfrappier/mitch/internal/encryption"
	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/store"
)

const testNewPassphrase = "a brand new passphrase"

// requireUnlocks fails the test unless passphrase opens the database.
func requireUnlocks(t *testing.T, path string, passphrase string) {
	t.Helper()
	opened, err := store.Open(context.Background(), path, []byte(passphrase))
	if err != nil {
		t.Fatalf("expected %q to unlock the database: %v", passphrase, err)
	}
	_ = opened.Close()
}

// requireRejected fails the test unless passphrase is rejected as wrong.
func requireRejected(t *testing.T, path string, passphrase string) {
	t.Helper()
	opened, err := store.Open(context.Background(), path, []byte(passphrase))
	if err == nil {
		_ = opened.Close()
		t.Fatalf("expected %q to be rejected", passphrase)
	}
	if !errors.Is(err, encryption.ErrWrongPassphrase) {
		t.Fatalf("expected a wrong-passphrase error for %q, got %v", passphrase, err)
	}
}

func TestPassphraseChangeFromEnvironmentKeepsScans(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	scanID := saveTestScan(t, path, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), inventoryWithPolicy("kept"))
	t.Setenv(newPassphraseEnvVar, testNewPassphrase)

	exitCode, _, stderr := runForTest("passphrase")
	if exitCode != exitcode.Success {
		t.Fatalf("passphrase failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	if !strings.Contains(stderr, "passphrase changed") || !strings.Contains(stderr, "no longer opens this database") {
		t.Errorf("expected the success and update-your-secrets messages, got:\n%s", stderr)
	}

	requireRejected(t, path, testPassphrase)
	requireUnlocks(t, path, testNewPassphrase)

	// The scans are still readable with the new passphrase.
	t.Setenv(passphraseEnvVar, testNewPassphrase)
	exitCode, stdout, stderr := runForTest("export", "--scan", scanID)
	if exitCode != exitcode.Success || !strings.Contains(stdout, `"name": "kept"`) {
		t.Errorf("the saved scan did not survive the change: exit %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}
}

func TestPassphraseChangeFromFiles(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	t.Setenv(passphraseEnvVar, "")

	directory := t.TempDir()
	currentFile := filepath.Join(directory, "current")
	newFile := filepath.Join(directory, "new")
	for file, content := range map[string]string{currentFile: testPassphrase + "\n", newFile: testNewPassphrase + "\n"} {
		err := os.WriteFile(file, []byte(content), 0o600)
		if err != nil {
			t.Fatalf("writing %s failed: %v", file, err)
		}
	}

	exitCode, _, stderr := runForTest("passphrase", "--passphrase-file", currentFile, "--new-passphrase-file", newFile)
	if exitCode != exitcode.Success {
		t.Fatalf("passphrase failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	requireUnlocks(t, path, testNewPassphrase)
}

func TestPassphraseChangeAtATerminal(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	t.Setenv(passphraseEnvVar, "")
	linesRead := fakeTerminal(t, testPassphrase, testNewPassphrase, testNewPassphrase)

	exitCode, _, stderr := runForTest("passphrase")
	if exitCode != exitcode.Success {
		t.Fatalf("passphrase failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	if *linesRead != 3 {
		t.Errorf("expected 3 prompts (current once, new twice), got %d", *linesRead)
	}
	for _, prompt := range []string{"Passphrase: ", "New passphrase: ", "Repeat new passphrase: "} {
		if !strings.Contains(stderr, prompt) {
			t.Errorf("expected the prompt %q, got:\n%s", prompt, stderr)
		}
	}
	requireUnlocks(t, path, testNewPassphrase)
}

func TestPassphraseChangeRefusals(t *testing.T) {
	cases := []struct {
		name          string
		newPassphrase string
		terminalLines []string
		exitCode      int
		message       string
	}{
		{"same as current", testPassphrase, nil, exitcode.UsageError, "same as the current one"},
		{"too short", "short", nil, exitcode.GeneralError, "use at least 12"},
		{"typed twice differently", "", []string{testNewPassphrase, "something else entirely"}, exitcode.GeneralError, "do not match; nothing was changed"},
		{"no source and no terminal", "", nil, exitcode.GeneralError, newPassphraseEnvVar},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := testDatabase(t)
			runForTest("init")
			t.Setenv(newPassphraseEnvVar, testCase.newPassphrase)
			if testCase.terminalLines != nil {
				fakeTerminal(t, testCase.terminalLines...)
			} else {
				original := stdinIsTerminal
				stdinIsTerminal = func() bool { return false }
				t.Cleanup(func() { stdinIsTerminal = original })
			}

			exitCode, _, stderr := runForTest("passphrase")
			if exitCode != testCase.exitCode || !strings.Contains(stderr, testCase.message) {
				t.Errorf("expected exit %d with %q, got exit %d\nstderr: %s", testCase.exitCode, testCase.message, exitCode, stderr)
			}
			// Nothing changed: the old passphrase still works.
			requireUnlocks(t, path, testPassphrase)
		})
	}
}

func TestPassphraseChangeWrongCurrentPassphrase(t *testing.T) {
	path := testDatabase(t)
	runForTest("init")
	t.Setenv(passphraseEnvVar, "not the right passphrase")
	t.Setenv(newPassphraseEnvVar, testNewPassphrase)

	exitCode, _, stderr := runForTest("passphrase")
	if exitCode != exitcode.GeneralError || !strings.Contains(stderr, "passphrase is wrong") {
		t.Errorf("expected a wrong-passphrase failure, got exit %d\nstderr: %s", exitCode, stderr)
	}
	requireUnlocks(t, path, testPassphrase)
}

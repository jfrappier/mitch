package cli

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/store"
)

// fakeTerminal makes Mitch think a person is at a terminal who will type
// the given lines, in order. It returns a counter of lines read.
func fakeTerminal(t *testing.T, lines ...string) *int {
	t.Helper()
	originalIsTerminal := stdinIsTerminal
	originalRead := readHiddenLine
	t.Cleanup(func() {
		stdinIsTerminal = originalIsTerminal
		readHiddenLine = originalRead
	})

	linesRead := 0
	stdinIsTerminal = func() bool { return true }
	readHiddenLine = func() ([]byte, error) {
		if linesRead >= len(lines) {
			t.Fatalf("Mitch asked for line %d, but the test only typed %d", linesRead+1, len(lines))
		}
		line := lines[linesRead]
		linesRead++
		return []byte(line), nil
	}
	return &linesRead
}

func TestInitPromptsTwiceAtATerminal(t *testing.T) {
	path := testDatabase(t)
	t.Setenv(passphraseEnvVar, "")
	linesRead := fakeTerminal(t, testPassphrase, testPassphrase)

	exitCode, stdout, stderr := runForTest("init")
	if exitCode != exitcode.Success {
		t.Fatalf("init failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	if *linesRead != 2 {
		t.Errorf("expected the passphrase to be asked twice, got %d", *linesRead)
	}
	if !strings.Contains(stderr, "Passphrase: ") || !strings.Contains(stderr, "Repeat passphrase: ") {
		t.Errorf("expected both prompts on standard error, got:\n%s", stderr)
	}
	if strings.Contains(stdout, "Passphrase") {
		t.Errorf("prompts must not go to standard output, got:\n%s", stdout)
	}

	opened, err := store.Open(context.Background(), path, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("the typed passphrase did not unlock the database: %v", err)
	}
	_ = opened.Close()
}

func TestInitStopsWhenPassphrasesDiffer(t *testing.T) {
	path := testDatabase(t)
	t.Setenv(passphraseEnvVar, "")
	fakeTerminal(t, testPassphrase, testPassphrase+"x")

	exitCode, _, stderr := runForTest("init")
	if exitCode != exitcode.GeneralError || !strings.Contains(stderr, "do not match") {
		t.Errorf("expected a mismatch error, got exit %d\nstderr: %s", exitCode, stderr)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a mismatched passphrase must not create a database")
	}
}

func TestEmptyTypedPassphraseIsRejected(t *testing.T) {
	testDatabase(t)
	t.Setenv(passphraseEnvVar, "")
	fakeTerminal(t, "")

	exitCode, _, stderr := runForTest("init")
	if exitCode != exitcode.GeneralError || !strings.Contains(stderr, "empty") {
		t.Errorf("expected an empty-passphrase error, got exit %d\nstderr: %s", exitCode, stderr)
	}
}

func TestUnlockPromptsOnce(t *testing.T) {
	testDatabase(t)
	runForTest("init")

	t.Setenv(passphraseEnvVar, "")
	linesRead := fakeTerminal(t, testPassphrase)

	exitCode, _, stderr := runForTest("history")
	if exitCode != exitcode.Success {
		t.Fatalf("history failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	if *linesRead != 1 || strings.Contains(stderr, "Repeat") {
		t.Errorf("unlocking must ask once, got %d prompts\nstderr: %s", *linesRead, stderr)
	}
}

func TestEnvironmentVariableSkipsThePrompt(t *testing.T) {
	testDatabase(t)
	linesRead := fakeTerminal(t)

	exitCode, _, stderr := runForTest("init")
	if exitCode != exitcode.Success {
		t.Fatalf("init failed: exit %d\nstderr: %s", exitCode, stderr)
	}
	if *linesRead != 0 {
		t.Errorf("MITCH_PASSPHRASE is set, so no prompt is expected; got %d", *linesRead)
	}
}

func TestNoTerminalAndNoPassphraseFailsWithoutWaiting(t *testing.T) {
	testDatabase(t)
	t.Setenv(passphraseEnvVar, "")

	originalIsTerminal := stdinIsTerminal
	t.Cleanup(func() { stdinIsTerminal = originalIsTerminal })
	stdinIsTerminal = func() bool { return false }

	exitCode, _, stderr := runForTest("init")
	if exitCode != exitcode.GeneralError || !strings.Contains(stderr, "no terminal") || !strings.Contains(stderr, passphraseEnvVar) {
		t.Errorf("expected a no-terminal error naming %s, got exit %d\nstderr: %s", passphraseEnvVar, exitCode, stderr)
	}
}

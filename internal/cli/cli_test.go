package cli

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/logging"
)

// runForTest calls Run and returns the exit code plus everything written to
// standard output and standard error.
func runForTest(arguments ...string) (int, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run(arguments, &stdout, &stderr)
	return exitCode, stdout.String(), stderr.String()
}

func TestVersionPrintsVersion(t *testing.T) {
	exitCode, stdout, _ := runForTest("version")

	if exitCode != exitcode.Success {
		t.Errorf("expected exit code %d, got %d", exitcode.Success, exitCode)
	}
	if !strings.HasPrefix(stdout, "mitch ") {
		t.Errorf("expected output to start with %q, got %q", "mitch ", stdout)
	}
}

func TestHelpListsEveryCommand(t *testing.T) {
	exitCode, stdout, _ := runForTest("help")

	if exitCode != exitcode.Success {
		t.Errorf("expected exit code %d, got %d", exitcode.Success, exitCode)
	}
	for _, listed := range commands() {
		if !strings.Contains(stdout, listed.name) {
			t.Errorf("help output is missing command %q", listed.name)
		}
	}
}

func TestNoCommandShowsHelpAndFails(t *testing.T) {
	exitCode, stdout, _ := runForTest()

	if exitCode != exitcode.UsageError {
		t.Errorf("expected exit code %d, got %d", exitcode.UsageError, exitCode)
	}
	if !strings.Contains(stdout, "Commands:") {
		t.Errorf("expected help text, got %q", stdout)
	}
}

func TestUnknownCommandFailsLoudly(t *testing.T) {
	exitCode, _, stderr := runForTest("explode")

	if exitCode != exitcode.UsageError {
		t.Errorf("expected exit code %d, got %d", exitcode.UsageError, exitCode)
	}
	expectedParts := []string{"level=ERROR", "unknown command", "command=explode", "mitch help"}
	for _, expected := range expectedParts {
		if !strings.Contains(stderr, expected) {
			t.Errorf("error output is missing %q\nfull output: %s", expected, stderr)
		}
	}
}

func TestStubCommandsReturnNotImplemented(t *testing.T) {
	stubs := []string{"terraform", "serve"}

	for _, name := range stubs {
		t.Run(name, func(t *testing.T) {
			exitCode, _, stderr := runForTest(name)

			if exitCode != exitcode.NotImplemented {
				t.Errorf("expected exit code %d, got %d", exitcode.NotImplemented, exitCode)
			}
			if !strings.Contains(stderr, "not implemented") {
				t.Errorf("expected a not-implemented error, got %q", stderr)
			}
		})
	}
}

func TestJSONLogFormatIsUsed(t *testing.T) {
	_, _, stderr := runForTest("--log-format", "json", "explode")

	if !strings.HasPrefix(strings.TrimSpace(stderr), "{") {
		t.Errorf("expected a JSON log line, got %q", stderr)
	}
}

func TestBadGlobalFlagValuesFail(t *testing.T) {
	testCases := [][]string{
		{"--log-format", "xml", "version"},
		{"--log-level", "loud", "version"},
		{"--no-such-flag", "version"},
	}

	for _, arguments := range testCases {
		exitCode, _, stderr := runForTest(arguments...)
		if exitCode != exitcode.UsageError {
			t.Errorf("arguments %v: expected exit code %d, got %d", arguments, exitcode.UsageError, exitCode)
		}
		if stderr == "" {
			t.Errorf("arguments %v: expected an error message, got nothing", arguments)
		}
	}
}

// testLogger returns a logger that discards its output.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()

	logger, err := logging.New(logging.Options{Output: io.Discard, Format: logging.FormatText, Level: logging.LevelInfo})
	if err != nil {
		t.Fatalf("creating the logger failed: %v", err)
	}
	return logger
}

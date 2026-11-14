package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/jfrappier/mitch/internal/encryption"
	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/store"
)

// Environment variables for the scan database.
const (
	// databaseEnvVar sets the database path when --db is not given.
	databaseEnvVar = "MITCH_DB"

	// passphraseEnvVar holds the passphrase, for CI and Docker.
	passphraseEnvVar = "MITCH_PASSPHRASE"

	// newPassphraseEnvVar holds the new passphrase for "mitch passphrase",
	// for scripted changes.
	newPassphraseEnvVar = "MITCH_NEW_PASSPHRASE" //nolint:gosec // G101: the name of an environment variable, not a credential

	// defaultDatabasePath is used when neither --db nor MITCH_DB is set.
	defaultDatabasePath = "mitch.db"
)

// stdinIsTerminal reports whether standard input is an interactive terminal,
// where a person can type a passphrase. Tests replace it.
var stdinIsTerminal = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) //nolint:gosec // a file descriptor always fits in int
}

// readHiddenLine reads one line from the terminal without showing what is
// typed, like ssh does for passwords. Tests replace it.
// Docs: https://pkg.go.dev/golang.org/x/term#ReadPassword
var readHiddenLine = func() ([]byte, error) {
	return term.ReadPassword(int(os.Stdin.Fd())) //nolint:gosec // a file descriptor always fits in int
}

// passphraseUse says what a passphrase is for. A passphrase that is being
// set (for a new database, or to replace the current one) is asked twice.
type passphraseUse int

const (
	unlockPassphrase passphraseUse = iota
	newPassphrase
	replacementPassphrase
)

// promptText is what the terminal shows when asking for a passphrase.
type promptText struct {
	first    string
	repeat   string
	mismatch string
}

// promptTexts holds the prompts for each use.
var promptTexts = map[passphraseUse]promptText{
	unlockPassphrase: {first: "Passphrase: "},
	newPassphrase: {
		first:    "Passphrase: ",
		repeat:   "Repeat passphrase: ",
		mismatch: "the two passphrases do not match; nothing was created",
	},
	replacementPassphrase: {
		first:    "New passphrase: ",
		repeat:   "Repeat new passphrase: ",
		mismatch: "the two new passphrases do not match; nothing was changed",
	},
}

// newKDFParams picks the Argon2id settings for "mitch init". Tests replace it
// with cheaper settings so they run quickly.
var newKDFParams = encryption.NewKDFParams

// storeFlags are the flags every command that uses the database accepts.
type storeFlags struct {
	databasePath   *string
	passphraseFile *string
}

// addStoreFlags registers --db and --passphrase-file on a command's flags.
func addStoreFlags(flags *flag.FlagSet) storeFlags {
	defaultPath := os.Getenv(databaseEnvVar)
	if defaultPath == "" {
		defaultPath = defaultDatabasePath
	}

	registered := storeFlags{
		databasePath: flags.String("db", defaultPath,
			"path to the Mitch database (default from "+databaseEnvVar+", else "+defaultDatabasePath+")"),
		passphraseFile: flags.String("passphrase-file", "",
			"read the passphrase from this file instead of "+passphraseEnvVar),
	}
	return registered
}

// readPassphrase gets the passphrase, trying in order:
//
//  1. --passphrase-file, so an explicit flag always does what it says
//  2. the MITCH_PASSPHRASE environment variable, for CI and Docker
//  3. a prompt, when a person is at a terminal
//
// With no terminal (a CI job or a pipe) and no file or variable, it fails
// instead of waiting for input that will never come.
func readPassphrase(runContext runContext, flags storeFlags, use passphraseUse) ([]byte, error) {
	if *flags.passphraseFile != "" {
		return readPassphraseFile(runContext, *flags.passphraseFile)
	}

	fromEnvironment := os.Getenv(passphraseEnvVar)
	if fromEnvironment != "" {
		return []byte(fromEnvironment), nil
	}

	if !stdinIsTerminal() {
		return nil, fmt.Errorf("no passphrase given and no terminal to ask on: set %s or pass --passphrase-file", passphraseEnvVar)
	}

	return promptForPassphrase(runContext, use)
}

// promptForPassphrase asks for the passphrase on the terminal without echoing
// it. A new passphrase is asked twice, so a typo can't lock the user out.
// Prompts go to standard error, so standard output stays clean for results.
func promptForPassphrase(runContext runContext, use passphraseUse) ([]byte, error) {
	prompts := promptTexts[use]

	fmt.Fprint(runContext.stderr, prompts.first)
	first, err := readHiddenLine()
	fmt.Fprintln(runContext.stderr)
	if err != nil {
		return nil, fmt.Errorf("reading the passphrase from the terminal failed: %w", err)
	}
	if len(first) == 0 {
		return nil, errors.New("the passphrase is empty")
	}

	if use == unlockPassphrase {
		return first, nil
	}

	fmt.Fprint(runContext.stderr, prompts.repeat)
	second, err := readHiddenLine()
	fmt.Fprintln(runContext.stderr)
	if err != nil {
		return nil, fmt.Errorf("reading the passphrase from the terminal failed: %w", err)
	}
	if !bytes.Equal(first, second) {
		return nil, errors.New(prompts.mismatch)
	}
	return first, nil
}

// readReplacementPassphrase gets the new passphrase for "mitch passphrase",
// trying in order:
//
//  1. --new-passphrase-file
//  2. the MITCH_NEW_PASSPHRASE environment variable
//  3. a prompt (asked twice), when a person is at a terminal
func readReplacementPassphrase(runContext runContext, newPassphraseFile string) ([]byte, error) {
	if newPassphraseFile != "" {
		return readPassphraseFile(runContext, newPassphraseFile)
	}

	fromEnvironment := os.Getenv(newPassphraseEnvVar)
	if fromEnvironment != "" {
		return []byte(fromEnvironment), nil
	}

	if !stdinIsTerminal() {
		return nil, fmt.Errorf("no new passphrase given and no terminal to ask on: set %s or pass --new-passphrase-file", newPassphraseEnvVar)
	}

	return promptForPassphrase(runContext, replacementPassphrase)
}

// readPassphraseFile reads a passphrase from a file. One trailing line break
// is removed, because most editors and "echo" add one.
func readPassphraseFile(runContext runContext, path string) ([]byte, error) {
	content, err := os.ReadFile(path) //nolint:gosec // path is the user's --passphrase-file flag
	if err != nil {
		return nil, fmt.Errorf("reading the passphrase file %s failed: %w", path, err)
	}

	text := string(content)
	text = strings.TrimSuffix(text, "\n")
	text = strings.TrimSuffix(text, "\r")
	if text == "" {
		return nil, fmt.Errorf("the passphrase file %s is empty", path)
	}

	problem, err := store.PermissionProblem(path)
	if err != nil {
		return nil, err
	}
	if problem != "" {
		logging.ForComponent(runContext.logger, "store").Warn("the passphrase file is readable by other users",
			logging.FieldOperation, "read_passphrase",
			"next_step", problem,
		)
	}

	return []byte(text), nil
}

// openStore opens and unlocks the database, and warns if its file permissions
// let other users read it.
func openStore(ctx context.Context, runContext runContext, flags storeFlags) (*store.Store, error) {
	passphrase, err := readPassphrase(runContext, flags, unlockPassphrase)
	if err != nil {
		return nil, err
	}
	return openStoreWithPassphrase(ctx, runContext, flags, passphrase)
}

// openStoreWithPassphrase is openStore for a passphrase the caller already read.
func openStoreWithPassphrase(ctx context.Context, runContext runContext, flags storeFlags, passphrase []byte) (*store.Store, error) {
	opened, err := store.Open(ctx, *flags.databasePath, passphrase)
	if err != nil {
		if errors.Is(err, encryption.ErrWrongPassphrase) {
			return nil, fmt.Errorf("%w. Next step: check %s or --passphrase-file; a lost passphrase cannot be recovered", err, passphraseEnvVar)
		}
		return nil, err
	}

	problem, err := store.PermissionProblem(*flags.databasePath)
	if err != nil {
		closeStoreQuietly(opened)
		return nil, err
	}
	if problem != "" {
		logging.ForComponent(runContext.logger, "store").Warn("the database file is readable by other users",
			logging.FieldOperation, "open_store",
			"next_step", problem,
		)
	}

	return opened, nil
}

// closeStore closes the database and logs a failure, which matters because
// SQLite may still be writing.
func closeStore(runContext runContext, opened *store.Store) {
	err := opened.Close()
	if err != nil {
		logging.ForComponent(runContext.logger, "store").Error("closing the database failed",
			logging.FieldOperation, "close_store",
			logging.FieldError, err.Error(),
		)
	}
}

// closeStoreQuietly closes the database while another error is already being
// reported, so that error is the one the user sees.
func closeStoreQuietly(opened *store.Store) {
	_ = opened.Close()
}

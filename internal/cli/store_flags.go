package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

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

	// defaultDatabasePath is used when neither --db nor MITCH_DB is set.
	defaultDatabasePath = "mitch.db"
)

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

// readPassphrase gets the passphrase from --passphrase-file or MITCH_PASSPHRASE.
//
// A file wins over the environment variable, so an explicit flag always does
// what it says.
func readPassphrase(runContext runContext, flags storeFlags) ([]byte, error) {
	if *flags.passphraseFile != "" {
		return readPassphraseFile(runContext, *flags.passphraseFile)
	}

	fromEnvironment := os.Getenv(passphraseEnvVar)
	if fromEnvironment != "" {
		return []byte(fromEnvironment), nil
	}

	return nil, fmt.Errorf("no passphrase given: set %s or pass --passphrase-file", passphraseEnvVar)
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
	passphrase, err := readPassphrase(runContext, flags)
	if err != nil {
		return nil, err
	}

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

package cli

import (
	"bytes"
	"context"
	"flag"

	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/logging"
)

// runPassphrase changes the passphrase that protects the database.
//
//	mitch passphrase [--new-passphrase-file FILE] [--db PATH] [--passphrase-file FILE]
//
// The current passphrase comes from the usual places (--passphrase-file,
// MITCH_PASSPHRASE, or a prompt). The new one comes from
// --new-passphrase-file, MITCH_NEW_PASSPHRASE, or a prompt asked twice.
func runPassphrase(runContext runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch passphrase", flag.ContinueOnError)
	flags.SetOutput(runContext.stderr)
	databaseFlags := addStoreFlags(flags)
	newPassphraseFile := flags.String("new-passphrase-file", "",
		"read the new passphrase from this file instead of "+newPassphraseEnvVar)

	exitCode, parsed := parseCommandFlags(runContext, flags, arguments)
	if !parsed {
		return exitCode
	}

	passphraseLogger := logging.ForComponent(runContext.logger, "store")
	ctx := context.Background()

	// Step 1: unlock with the current passphrase. A wrong one stops here,
	// before the new passphrase is asked for.
	current, err := readPassphrase(runContext, databaseFlags, unlockPassphrase)
	if err != nil {
		passphraseLogger.Error("cannot read the current passphrase", logging.FieldOperation, "change_passphrase", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	opened, err := openStoreWithPassphrase(ctx, runContext, databaseFlags, current)
	if err != nil {
		passphraseLogger.Error("cannot open the database", logging.FieldOperation, "change_passphrase", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	defer closeStore(runContext, opened)

	// Step 2: get the new passphrase.
	replacement, err := readReplacementPassphrase(runContext, *newPassphraseFile)
	if err != nil {
		passphraseLogger.Error("cannot read the new passphrase", logging.FieldOperation, "change_passphrase", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}

	// A "change" to the same passphrase is almost always a mistake, such as
	// MITCH_NEW_PASSPHRASE left set to the old value.
	if bytes.Equal(current, replacement) {
		passphraseLogger.Error("the new passphrase is the same as the current one; nothing was changed",
			logging.FieldOperation, "change_passphrase",
			"next_step", "choose a different passphrase",
		)
		return exitcode.UsageError
	}

	// Step 3: wrap the data key with the new passphrase.
	kdfParams, err := newKDFParams()
	if err != nil {
		passphraseLogger.Error("cannot change the passphrase", logging.FieldOperation, "change_passphrase", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	err = opened.ChangePassphrase(ctx, replacement, kdfParams)
	if err != nil {
		passphraseLogger.Error("cannot change the passphrase; the old passphrase still works",
			logging.FieldOperation, "change_passphrase",
			logging.FieldError, err.Error(),
		)
		return exitcode.GeneralError
	}

	passphraseLogger.Info("passphrase changed",
		logging.FieldOperation, "change_passphrase",
		"db", opened.Path(),
	)
	passphraseLogger.Warn("update MITCH_PASSPHRASE, passphrase files and your password manager now; the old passphrase no longer opens this database",
		logging.FieldOperation, "change_passphrase",
	)
	return exitcode.Success
}

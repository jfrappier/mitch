package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/scan"
	"github.com/jfrappier/mitch/internal/store"
	"github.com/jfrappier/mitch/internal/vaultclient"
	"github.com/jfrappier/mitch/internal/version"
)

// outputFileMode makes output files readable and writable by their owner only,
// because the inventory describes the Vault cluster.
const outputFileMode = 0o600

// runScan scans Vault and saves the inventory, encrypted, in the Mitch database.
//
//	mitch scan [--sudo] [--kv=false] [--no-save] [--output FILE] [--timeout DURATION]
//	           [--db PATH] [--passphrase-file FILE]
//
// Vault connection settings come from VAULT_ADDR, VAULT_TOKEN and the other
// standard Vault environment variables.
//
// By default the scan is saved and only its id is printed. --no-save prints
// the inventory as JSON instead, and needs no database. --output also writes
// the JSON to a file, in plain text.
//
// Exit codes: 0 when every check ran, 5 when some checks were skipped,
// 1 when the scan could not run at all.
func runScan(runContext runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch scan", flag.ContinueOnError)
	flags.SetOutput(runContext.stderr)

	sudo := flags.Bool("sudo", false, "also run checks that need the sudo capability (attach the mitch-scanner-sudo policy)")
	countKV := flags.Bool("kv", true, "count secrets in KV mounts by listing key names (never values); --kv=false turns it off")
	noSave := flags.Bool("no-save", false, "do not save the scan; print the inventory as JSON instead")
	outputPath := flags.String("output", "", "also write the JSON inventory to this file, in plain text")
	databaseFlags := addStoreFlags(flags)
	timeout := flags.Duration("timeout", 10*time.Minute, "stop the scan if it takes longer than this")

	err := flags.Parse(arguments)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitcode.Success
		}
		return exitcode.UsageError
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(runContext.stderr, "mitch scan: unexpected argument %q; settings come from flags and VAULT_* environment variables\n", flags.Arg(0))
		return exitcode.UsageError
	}

	scanLogger := logging.ForComponent(runContext.logger, "scan")
	saveScan := !*noSave

	// Step 1: unlock the database before scanning, so a missing database or
	// wrong passphrase fails in a second instead of after a long scan.
	var database *store.Store
	if saveScan {
		database, err = openStore(context.Background(), runContext, databaseFlags)
		if err != nil {
			scanLogger.Error("cannot open the database to save the scan",
				logging.FieldOperation, "open_store",
				logging.FieldError, err.Error(),
				"next_step", `run "mitch init" first, or pass --no-save to print the scan without saving it`,
			)
			return exitcode.GeneralError
		}
		defer closeStore(runContext, database)
	}

	// Step 2: connect to Vault using the standard environment variables.
	client, err := vaultclient.New(runContext.logger)
	if err != nil {
		scanLogger.Error("cannot connect to Vault",
			logging.FieldOperation, "connect",
			logging.FieldError, err.Error(),
		)
		return exitcode.GeneralError
	}

	// Step 3: run the scan.
	scanContext, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	scanner := scan.New(client, runContext.logger, scan.Options{Sudo: *sudo, CountKV: *countKV, MitchVersion: version.Version})
	inventory, err := scanner.Run(scanContext)
	if err != nil {
		scanLogger.Error("scan failed",
			logging.FieldOperation, "scan",
			logging.FieldError, err.Error(),
		)
		return exitcode.GeneralError
	}

	// Step 4: save and write the inventory.
	inventoryJSON, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		scanLogger.Error("could not encode the inventory as JSON",
			logging.FieldOperation, "write_output",
			logging.FieldError, err.Error(),
		)
		return exitcode.GeneralError
	}
	inventoryJSON = append(inventoryJSON, '\n')

	if saveScan {
		scanID, err := database.SaveScan(scanContext, inventory.StartedAt, inventory.FinishedAt, inventoryJSON)
		if err != nil {
			scanLogger.Error("could not save the scan",
				logging.FieldOperation, "save_scan",
				"db", database.Path(),
				logging.FieldError, err.Error(),
			)
			return exitcode.GeneralError
		}
		scanLogger.Info("scan saved", logging.FieldOperation, "save_scan", "scan_id", scanID, "db", database.Path())
		fmt.Fprintln(runContext.stdout, scanID)
	}

	// Without --output, the JSON goes to standard output only when the scan
	// is not saved; a saved scan prints just its id.
	writeJSON := *outputPath != "" || !saveScan
	if writeJSON {
		err = writeOutput(runContext, *outputPath, inventoryJSON)
	}
	if err != nil {
		scanLogger.Error("could not write the inventory",
			logging.FieldOperation, "write_output",
			"output", *outputPath,
			logging.FieldError, err.Error(),
		)
		return exitcode.GeneralError
	}

	// Step 5: report skipped checks loudly and pick the exit code.
	for _, skipped := range inventory.Skipped {
		scanLogger.Warn("check skipped",
			logging.FieldOperation, "summary",
			"check", skipped.Check,
			"namespace", skipped.Namespace,
			"path", skipped.Path,
			logging.FieldHTTPStatus, skipped.HTTPStatus,
			"reason", skipped.Reason,
			"next_step", skipped.NextStep,
		)
	}
	for _, notRequested := range inventory.NotRequested {
		scanLogger.Info("check not requested",
			logging.FieldOperation, "summary",
			"check", notRequested.Check,
			"reason", notRequested.Reason,
		)
	}

	if len(inventory.Skipped) > 0 {
		scanLogger.Warn("scan finished with skipped checks",
			logging.FieldOperation, "summary",
			"skipped_checks", len(inventory.Skipped),
			"exit_code", exitcode.PartialScan,
		)
		return exitcode.PartialScan
	}
	return exitcode.Success
}

// writeOutput writes the JSON to standard output, or to a file readable only
// by its owner.
func writeOutput(runContext runContext, outputPath string, content []byte) error {
	if outputPath == "" {
		_, err := runContext.stdout.Write(content)
		return err
	}

	// The user chooses the output path on purpose, so gosec's file-path
	// warning (G304) does not apply here.
	file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, outputFileMode) //nolint:gosec // path is the user's --output flag
	if err != nil {
		return err
	}

	// OpenFile only applies the mode to new files, so tighten an existing one too.
	err = file.Chmod(outputFileMode)
	if err != nil {
		closeErr := file.Close()
		return errors.Join(fmt.Errorf("setting permissions on %s failed: %w", outputPath, err), closeErr)
	}

	_, err = file.Write(content)
	if err != nil {
		closeErr := file.Close()
		return errors.Join(fmt.Errorf("writing %s failed: %w", outputPath, err), closeErr)
	}

	err = file.Close()
	if err != nil {
		return err
	}

	logging.ForComponent(runContext.logger, "scan").Warn(
		"inventory written as plain text; treat this file as sensitive",
		logging.FieldOperation, "write_output",
		"output", outputPath,
	)
	return nil
}

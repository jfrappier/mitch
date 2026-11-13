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
	"github.com/jfrappier/mitch/internal/vaultclient"
	"github.com/jfrappier/mitch/internal/version"
)

// outputFileMode makes output files readable and writable by their owner only,
// because the inventory describes the Vault cluster.
const outputFileMode = 0o600

// runScan scans Vault and prints the inventory as JSON.
//
//	mitch scan [--sudo] [--output FILE] [--timeout DURATION]
//
// Vault connection settings come from VAULT_ADDR, VAULT_TOKEN and the other
// standard Vault environment variables.
//
// Exit codes: 0 when every check ran, 5 when some checks were skipped,
// 1 when the scan could not run at all.
func runScan(runContext runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch scan", flag.ContinueOnError)
	flags.SetOutput(runContext.stderr)

	sudo := flags.Bool("sudo", false, "also run checks that need the sudo capability (attach the mitch-scanner-sudo policy)")
	outputPath := flags.String("output", "", "write the JSON inventory to this file instead of standard output")
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

	// Step 1: connect to Vault using the standard environment variables.
	client, err := vaultclient.New(runContext.logger)
	if err != nil {
		scanLogger.Error("cannot connect to Vault",
			logging.FieldOperation, "connect",
			logging.FieldError, err.Error(),
		)
		return exitcode.GeneralError
	}

	// Step 2: run the scan.
	scanContext, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	scanner := scan.New(client, runContext.logger, scan.Options{Sudo: *sudo, MitchVersion: version.Version})
	inventory, err := scanner.Run(scanContext)
	if err != nil {
		scanLogger.Error("scan failed",
			logging.FieldOperation, "scan",
			logging.FieldError, err.Error(),
		)
		return exitcode.GeneralError
	}

	// Step 3: write the inventory.
	inventoryJSON, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		scanLogger.Error("could not encode the inventory as JSON",
			logging.FieldOperation, "write_output",
			logging.FieldError, err.Error(),
		)
		return exitcode.GeneralError
	}
	inventoryJSON = append(inventoryJSON, '\n')

	err = writeOutput(runContext, *outputPath, inventoryJSON)
	if err != nil {
		scanLogger.Error("could not write the inventory",
			logging.FieldOperation, "write_output",
			"output", *outputPath,
			logging.FieldError, err.Error(),
		)
		return exitcode.GeneralError
	}

	// Step 4: report skipped checks loudly and pick the exit code.
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

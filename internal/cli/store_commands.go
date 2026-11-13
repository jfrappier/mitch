package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"text/tabwriter"

	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/store"
)

// runInit creates a new, empty Mitch database.
//
//	mitch init [--db PATH] [--passphrase-file FILE]
func runInit(runContext runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch init", flag.ContinueOnError)
	flags.SetOutput(runContext.stderr)
	databaseFlags := addStoreFlags(flags)

	exitCode, parsed := parseCommandFlags(runContext, flags, arguments)
	if !parsed {
		return exitCode
	}

	initLogger := logging.ForComponent(runContext.logger, "store")

	passphrase, err := readPassphrase(runContext, databaseFlags)
	if err != nil {
		initLogger.Error("cannot create the database", logging.FieldOperation, "init", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}

	kdfParams, err := newKDFParams()
	if err != nil {
		initLogger.Error("cannot create the database", logging.FieldOperation, "init", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}

	created, err := store.Create(context.Background(), *databaseFlags.databasePath, passphrase, kdfParams)
	if err != nil {
		initLogger.Error("cannot create the database", logging.FieldOperation, "init", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	closeStore(runContext, created)

	initLogger.Info("database created",
		logging.FieldOperation, "init",
		"db", *databaseFlags.databasePath,
	)
	initLogger.Warn("keep your passphrase safe: if it is lost, saved scans cannot be recovered by anyone",
		logging.FieldOperation, "init",
	)
	fmt.Fprintf(runContext.stdout, "Created %s\n", *databaseFlags.databasePath)
	return exitcode.Success
}

// runHistory lists saved scans, newest first. It decrypts nothing, but still
// needs the passphrase, so a wrong one is caught before anything is shown.
//
//	mitch history [--db PATH] [--passphrase-file FILE]
func runHistory(runContext runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch history", flag.ContinueOnError)
	flags.SetOutput(runContext.stderr)
	databaseFlags := addStoreFlags(flags)

	exitCode, parsed := parseCommandFlags(runContext, flags, arguments)
	if !parsed {
		return exitCode
	}

	historyLogger := logging.ForComponent(runContext.logger, "store")
	ctx := context.Background()

	opened, err := openStore(ctx, runContext, databaseFlags)
	if err != nil {
		historyLogger.Error("cannot open the database", logging.FieldOperation, "history", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	defer closeStore(runContext, opened)

	summaries, err := opened.ListScans(ctx)
	if err != nil {
		historyLogger.Error("cannot list saved scans", logging.FieldOperation, "history", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}

	if len(summaries) == 0 {
		fmt.Fprintln(runContext.stdout, `No saved scans yet. Run "mitch scan" to save one.`)
		return exitcode.Success
	}

	table := tabwriter.NewWriter(runContext.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "ID\tSTARTED (UTC)\tDURATION")
	for _, summary := range summaries {
		duration := summary.FinishedAt.Sub(summary.StartedAt).Round(1e6)
		fmt.Fprintf(table, "%s\t%s\t%s\n", summary.ID, summary.StartedAt.UTC().Format("2006-01-02 15:04:05"), duration)
	}
	err = table.Flush()
	if err != nil {
		historyLogger.Error("writing the scan list failed", logging.FieldOperation, "history", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	return exitcode.Success
}

// runExport prints one saved scan as JSON.
//
//	mitch export --scan ID [--output FILE] [--db PATH] [--passphrase-file FILE]
func runExport(runContext runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch export", flag.ContinueOnError)
	flags.SetOutput(runContext.stderr)
	databaseFlags := addStoreFlags(flags)
	scanID := flags.String("scan", "", `id of the saved scan to export (see "mitch history")`)
	outputPath := flags.String("output", "", "write the JSON to this file instead of standard output")

	exitCode, parsed := parseCommandFlags(runContext, flags, arguments)
	if !parsed {
		return exitCode
	}
	if *scanID == "" {
		fmt.Fprintln(runContext.stderr, `mitch export: --scan is required; run "mitch history" to see saved scan ids`)
		return exitcode.UsageError
	}

	exportLogger := logging.ForComponent(runContext.logger, "store")
	ctx := context.Background()

	opened, err := openStore(ctx, runContext, databaseFlags)
	if err != nil {
		exportLogger.Error("cannot open the database", logging.FieldOperation, "export", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	defer closeStore(runContext, opened)

	inventoryJSON, err := opened.LoadScan(ctx, *scanID)
	if err != nil {
		exportLogger.Error("cannot load the scan", logging.FieldOperation, "export", "scan_id", *scanID, logging.FieldError, err.Error())
		if errors.Is(err, store.ErrScanNotFound) {
			return exitcode.UsageError
		}
		return exitcode.GeneralError
	}

	// Re-indent so exports look the same as "mitch scan --no-save" output.
	var indented json.RawMessage
	err = json.Unmarshal(inventoryJSON, &indented)
	if err != nil {
		exportLogger.Error("the saved scan is not valid JSON", logging.FieldOperation, "export", "scan_id", *scanID, logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	pretty, err := json.MarshalIndent(indented, "", "  ")
	if err != nil {
		exportLogger.Error("encoding the scan failed", logging.FieldOperation, "export", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	pretty = append(pretty, '\n')

	// A file export logs its own plain-text warning in writeOutput.
	if *outputPath == "" {
		exportLogger.Warn("printing a decrypted scan as plain text; treat the output as sensitive",
			logging.FieldOperation, "export",
			"scan_id", *scanID,
		)
	}

	err = writeOutput(runContext, *outputPath, pretty)
	if err != nil {
		exportLogger.Error("could not write the export", logging.FieldOperation, "write_output", "output", *outputPath, logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	return exitcode.Success
}

// parseCommandFlags parses a command's flags and rejects extra arguments.
// It returns parsed=false with the exit code to use when the command should stop.
func parseCommandFlags(runContext runContext, flags *flag.FlagSet, arguments []string) (int, bool) {
	err := flags.Parse(arguments)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitcode.Success, false
		}
		return exitcode.UsageError, false
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(runContext.stderr, "%s: unexpected argument %q\n", flags.Name(), flags.Arg(0))
		return exitcode.UsageError, false
	}
	return exitcode.Success, true
}

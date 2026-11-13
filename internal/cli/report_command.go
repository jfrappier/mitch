package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"

	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/report"
)

// runReport summarizes one saved scan. With no --scan it uses the newest one.
//
//	mitch report [--scan ID] [--format markdown|json] [--output FILE.md|FILE.json] [--db PATH] [--passphrase-file FILE]
func runReport(runContext runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch report", flag.ContinueOnError)
	flags.SetOutput(runContext.stderr)
	databaseFlags := addStoreFlags(flags)
	scanID := flags.String("scan", "", `id of the saved scan (see "mitch history"); default: the newest scan`)
	format := flags.String("format", formatMarkdown, "what to print in the terminal: markdown or json")
	outputPath := flags.String("output", "", "also save the report to this file; .md saves Markdown, .json saves JSON")

	exitCode, parsed := parseCommandFlags(runContext, flags, arguments)
	if !parsed {
		return exitCode
	}

	// Check the flags before asking for a passphrase, so a typo fails fast.
	err := checkOutputFlags(*format, *outputPath)
	if err != nil {
		fmt.Fprintf(runContext.stderr, "mitch report: %v\n", err)
		return exitcode.UsageError
	}

	reportLogger := logging.ForComponent(runContext.logger, "report")
	ctx := context.Background()

	opened, err := openStore(ctx, runContext, databaseFlags)
	if err != nil {
		reportLogger.Error("cannot open the database", logging.FieldOperation, "report", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	defer closeStore(runContext, opened)

	// Step 1: pick the scan.
	if *scanID == "" {
		newest, err := newestScanIDs(ctx, opened, 1)
		if err != nil {
			reportLogger.Error("cannot pick a scan to report on",
				logging.FieldOperation, "report",
				logging.FieldError, err.Error(),
				"next_step", `run "mitch scan" to save a scan first`,
			)
			return exitcode.GeneralError
		}
		*scanID = newest[0]
	}

	// Step 2: decrypt it and build the report.
	inventory, exitCode, loaded := loadInventory(ctx, reportLogger, opened, *scanID)
	if !loaded {
		return exitCode
	}
	built := report.Build(*scanID, inventory)

	// Step 3: show it, and save it if --output was given.
	rendered, err := renderReport(built)
	if err != nil {
		reportLogger.Error("writing the report failed", logging.FieldOperation, "render_report", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	err = writeRendered(runContext, "report", *format, *outputPath, rendered)
	if err != nil {
		reportLogger.Error("could not write the report", logging.FieldOperation, "write_output", "output", *outputPath, logging.FieldError, err.Error())
		return exitcode.GeneralError
	}

	// A report on a partial scan is still useful, but say so loudly.
	if len(built.Skipped) > 0 {
		reportLogger.Warn("this scan skipped checks, so the report is incomplete; see \"Scan gaps\"",
			logging.FieldOperation, "report",
			"scan_id", *scanID,
			"skipped_checks", len(built.Skipped),
		)
	}
	return exitcode.Success
}

// renderReport writes a report as both Markdown and JSON.
func renderReport(built report.Report) (renderedOutput, error) {
	var markdown bytes.Buffer
	err := report.WriteMarkdown(&markdown, built)
	if err != nil {
		return renderedOutput{}, err
	}
	encoded, err := encodeJSON(built)
	if err != nil {
		return renderedOutput{}, err
	}
	return renderedOutput{markdown: markdown.Bytes(), json: encoded}, nil
}

package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/findings"
	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/report"
)

// runReport summarizes one saved scan. With no --scan it uses the newest one.
//
//	mitch report [--scan ID] [--repo PATH] [--format markdown|json] [--output FILE.md|FILE.json] [--fail-on SEVERITY] [--db PATH] [--passphrase-file FILE]
//
// With --repo, it compares the scan with the Terraform in that local git
// checkout. With --fail-on, it exits with code 4 when any finding, policy or
// git, is at or above that severity, so a CI job can fail on it.
func runReport(runContext runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch report", flag.ContinueOnError)
	flags.SetOutput(runContext.stderr)
	databaseFlags := addStoreFlags(flags)
	scanID := flags.String("scan", "", `id of the saved scan (see "mitch history"); default: the newest scan`)
	format := flags.String("format", formatMarkdown, "what to print in the terminal: markdown or json")
	outputPath := flags.String("output", "", "also save the report to this file; .md saves Markdown, .json saves JSON")
	repoPath := flags.String("repo", "", repoFlagUsage)
	failOn := flags.String("fail-on", "", "exit with code 4 when any finding is at or above this severity: "+strings.Join(findings.Severities(), ", ")+"; default: never")

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
	if *failOn != "" && !findings.IsSeverity(*failOn) {
		fmt.Fprintf(runContext.stderr, "mitch report: --fail-on %q is not a severity; use one of: %s\n", *failOn, strings.Join(findings.Severities(), ", "))
		return exitcode.UsageError
	}
	repo, exitCode, read := readRepoFlag(runContext, "mitch report", *repoPath)
	if !read {
		return exitCode
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
	built := report.Build(*scanID, inventory, repo)

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
	if len(built.PoliciesNotAnalyzed) > 0 {
		reportLogger.Warn("some policies could not be parsed, so they were not checked for findings; see \"Findings\"",
			logging.FieldOperation, "report",
			"scan_id", *scanID,
			"policies_not_analyzed", len(built.PoliciesNotAnalyzed),
		)
	}

	// Step 4: with --fail-on, fail when a finding is serious enough.
	if *failOn != "" {
		count := built.CountFindingsAtOrAbove(*failOn)
		if count > 0 {
			reportLogger.Error("findings at or above the --fail-on severity",
				logging.FieldOperation, "fail_on",
				"scan_id", *scanID,
				"fail_on", *failOn,
				"findings", count,
				"exit_code", exitcode.FindingsAboveThreshold,
			)
			return exitcode.FindingsAboveThreshold
		}
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

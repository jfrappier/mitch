package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"

	"github.com/jfrappier/mitch/internal/diff"
	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/logging"
)

// runDiff shows what changed between two saved scans. With no --from and
// --to it compares the two newest scans.
//
//	mitch diff [--from ID --to ID] [--format markdown|json] [--output FILE.md|FILE.json] [--db PATH] [--passphrase-file FILE]
func runDiff(runContext runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch diff", flag.ContinueOnError)
	flags.SetOutput(runContext.stderr)
	databaseFlags := addStoreFlags(flags)
	fromID := flags.String("from", "", `id of the older scan (see "mitch history"); default: the second newest scan`)
	toID := flags.String("to", "", `id of the newer scan (see "mitch history"); default: the newest scan`)
	format := flags.String("format", formatMarkdown, "what to print in the terminal: markdown or json")
	outputPath := flags.String("output", "", "also save the diff to this file; .md saves Markdown, .json saves JSON")

	exitCode, parsed := parseCommandFlags(runContext, flags, arguments)
	if !parsed {
		return exitCode
	}

	// Check the flags before asking for a passphrase, so a typo fails fast.
	err := checkOutputFlags(*format, *outputPath)
	if err != nil {
		fmt.Fprintf(runContext.stderr, "mitch diff: %v\n", err)
		return exitcode.UsageError
	}
	if (*fromID == "") != (*toID == "") {
		fmt.Fprintln(runContext.stderr, `mitch diff: give both --from and --to, or neither to compare the two newest scans; run "mitch history" to see scan ids`)
		return exitcode.UsageError
	}
	if *fromID != "" && *fromID == *toID {
		fmt.Fprintln(runContext.stderr, "mitch diff: --from and --to are the same scan; pick two different scans")
		return exitcode.UsageError
	}

	diffLogger := logging.ForComponent(runContext.logger, "diff")
	ctx := context.Background()

	opened, err := openStore(ctx, runContext, databaseFlags)
	if err != nil {
		diffLogger.Error("cannot open the database", logging.FieldOperation, "diff", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	defer closeStore(runContext, opened)

	// Step 1: pick the two scans.
	if *fromID == "" {
		newest, err := newestScanIDs(ctx, opened, 2)
		if err != nil {
			diffLogger.Error("cannot pick scans to compare",
				logging.FieldOperation, "diff",
				logging.FieldError, err.Error(),
				"next_step", `run "mitch scan" again so there are two scans to compare`,
			)
			return exitcode.GeneralError
		}
		*toID = newest[0]
		*fromID = newest[1]
	}

	// Step 2: decrypt both scans.
	fromInventory, exitCode, loaded := loadInventory(ctx, diffLogger, opened, *fromID)
	if !loaded {
		return exitCode
	}
	toInventory, exitCode, loaded := loadInventory(ctx, diffLogger, opened, *toID)
	if !loaded {
		return exitCode
	}

	// Step 3: compare them.
	result, err := diff.Compare(*fromID, fromInventory, *toID, toInventory)
	if err != nil {
		diffLogger.Error("comparing the scans failed",
			logging.FieldOperation, "diff",
			"from", *fromID,
			"to", *toID,
			logging.FieldError, err.Error(),
		)
		return exitcode.GeneralError
	}

	// Step 4: show it, and save it if --output was given.
	rendered, err := renderDiff(result)
	if err != nil {
		diffLogger.Error("writing the diff failed", logging.FieldOperation, "render_diff", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}
	err = writeRendered(runContext, "diff", *format, *outputPath, rendered)
	if err != nil {
		diffLogger.Error("could not write the diff", logging.FieldOperation, "write_output", "output", *outputPath, logging.FieldError, err.Error())
		return exitcode.GeneralError
	}

	diffLogger.Info("scans compared",
		logging.FieldOperation, "diff",
		"from", *fromID,
		"to", *toID,
		"changed_sections", len(result.Sections),
		"warnings", len(result.Warnings),
	)
	return exitcode.Success
}

// renderDiff writes a diff as both Markdown and JSON.
func renderDiff(result diff.Result) (renderedOutput, error) {
	var markdown bytes.Buffer
	err := diff.WriteMarkdown(&markdown, result)
	if err != nil {
		return renderedOutput{}, err
	}
	encoded, err := encodeJSON(result)
	if err != nil {
		return renderedOutput{}, err
	}
	return renderedOutput{markdown: markdown.Bytes(), json: encoded}, nil
}

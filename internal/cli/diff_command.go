package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"

	"github.com/jfrappier/mitch/internal/diff"
	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/scan"
	"github.com/jfrappier/mitch/internal/store"
)

// Output formats for "mitch diff".
const (
	diffFormatText = "text"
	diffFormatJSON = "json"
)

// errNotEnoughScans means the database has fewer than two saved scans.
var errNotEnoughScans = errors.New("diff needs at least two saved scans")

// runDiff shows what changed between two saved scans. With no --from and
// --to it compares the two newest scans.
//
//	mitch diff [--from ID --to ID] [--format text|json] [--output FILE] [--db PATH] [--passphrase-file FILE]
func runDiff(runContext runContext, arguments []string) int {
	flags := flag.NewFlagSet("mitch diff", flag.ContinueOnError)
	flags.SetOutput(runContext.stderr)
	databaseFlags := addStoreFlags(flags)
	fromID := flags.String("from", "", `id of the older scan (see "mitch history"); default: the second newest scan`)
	toID := flags.String("to", "", `id of the newer scan (see "mitch history"); default: the newest scan`)
	format := flags.String("format", diffFormatText, "output format: text or json")
	outputPath := flags.String("output", "", "write the diff to this file instead of standard output")

	exitCode, parsed := parseCommandFlags(runContext, flags, arguments)
	if !parsed {
		return exitCode
	}

	// Check the flags before asking for a passphrase, so a typo fails fast.
	if *format != diffFormatText && *format != diffFormatJSON {
		fmt.Fprintf(runContext.stderr, "mitch diff: --format must be %q or %q, not %q\n", diffFormatText, diffFormatJSON, *format)
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
		newest, secondNewest, err := twoNewestScans(ctx, opened)
		if err != nil {
			diffLogger.Error("cannot pick scans to compare",
				logging.FieldOperation, "diff",
				logging.FieldError, err.Error(),
				"next_step", `run "mitch scan" again so there are two scans to compare`,
			)
			return exitcode.GeneralError
		}
		*fromID = secondNewest
		*toID = newest
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

	// Step 4: write the result in the chosen format.
	content, err := renderDiff(result, *format)
	if err != nil {
		diffLogger.Error("writing the diff failed", logging.FieldOperation, "render_diff", logging.FieldError, err.Error())
		return exitcode.GeneralError
	}

	// A file output logs its own plain-text warning in writeOutput.
	if *outputPath == "" {
		diffLogger.Warn("printing decrypted scan details as plain text; treat the output as sensitive",
			logging.FieldOperation, "diff",
			"from", *fromID,
			"to", *toID,
		)
	}
	err = writeOutput(runContext, *outputPath, content)
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

// twoNewestScans returns the ids of the newest and second newest scans.
func twoNewestScans(ctx context.Context, opened *store.Store) (string, string, error) {
	summaries, err := opened.ListScans(ctx)
	if err != nil {
		return "", "", err
	}
	if len(summaries) < 2 {
		return "", "", fmt.Errorf("%w, and %s has %d", errNotEnoughScans, opened.Path(), len(summaries))
	}
	// ListScans returns the newest scan first.
	return summaries[0].ID, summaries[1].ID, nil
}

// loadInventory decrypts one saved scan and reads it as an Inventory.
// It returns loaded=false with the exit code to use when it fails.
func loadInventory(ctx context.Context, diffLogger *slog.Logger, opened *store.Store, scanID string) (scan.Inventory, int, bool) {
	inventoryJSON, err := opened.LoadScan(ctx, scanID)
	if err != nil {
		diffLogger.Error("cannot load the scan", logging.FieldOperation, "load_scan", "scan_id", scanID, logging.FieldError, err.Error())
		if errors.Is(err, store.ErrScanNotFound) {
			return scan.Inventory{}, exitcode.UsageError, false
		}
		return scan.Inventory{}, exitcode.GeneralError, false
	}

	var inventory scan.Inventory
	err = json.Unmarshal(inventoryJSON, &inventory)
	if err != nil {
		diffLogger.Error("the saved scan is not a valid inventory", logging.FieldOperation, "load_scan", "scan_id", scanID, logging.FieldError, err.Error())
		return scan.Inventory{}, exitcode.GeneralError, false
	}
	return inventory, exitcode.Success, true
}

// renderDiff turns a Result into text or indented JSON.
func renderDiff(result diff.Result, format string) ([]byte, error) {
	if format == diffFormatJSON {
		encoded, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(encoded, '\n'), nil
	}

	var text bytes.Buffer
	err := diff.WriteText(&text, result)
	if err != nil {
		return nil, err
	}
	return text.Bytes(), nil
}

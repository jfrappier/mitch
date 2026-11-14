package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jfrappier/mitch/internal/exitcode"
	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/scan"
	"github.com/jfrappier/mitch/internal/store"
)

// errNotEnoughScans means the database has fewer saved scans than a command needs.
var errNotEnoughScans = errors.New("not enough saved scans")

// newestScanIDs returns the ids of the newest saved scans, newest first.
// It fails if the database holds fewer than count scans.
func newestScanIDs(ctx context.Context, opened *store.Store, count int) ([]string, error) {
	summaries, err := opened.ListScans(ctx)
	if err != nil {
		return nil, err
	}
	if len(summaries) < count {
		return nil, fmt.Errorf("%w: this needs %d, and %s has %d", errNotEnoughScans, count, opened.Path(), len(summaries))
	}

	// ListScans returns the newest scan first.
	ids := []string{}
	for _, summary := range summaries[:count] {
		ids = append(ids, summary.ID)
	}
	return ids, nil
}

// loadInventory decrypts one saved scan and reads it as an Inventory.
// It returns loaded=false with the exit code to use when it fails.
func loadInventory(ctx context.Context, commandLogger *slog.Logger, opened *store.Store, scanID string) (scan.Inventory, int, bool) {
	inventoryJSON, err := opened.LoadScan(ctx, scanID)
	if err != nil {
		commandLogger.Error("cannot load the scan", logging.FieldOperation, "load_scan", "scan_id", scanID, logging.FieldError, err.Error())
		if errors.Is(err, store.ErrScanNotFound) {
			return scan.Inventory{}, exitcode.UsageError, false
		}
		return scan.Inventory{}, exitcode.GeneralError, false
	}

	var inventory scan.Inventory
	err = json.Unmarshal(inventoryJSON, &inventory)
	if err != nil {
		commandLogger.Error("the saved scan is not a valid inventory", logging.FieldOperation, "load_scan", "scan_id", scanID, logging.FieldError, err.Error())
		return scan.Inventory{}, exitcode.GeneralError, false
	}
	return inventory, exitcode.Success, true
}

// encodeJSON indents a value as JSON with a trailing line break, the same
// way every Mitch command prints JSON.
func encodeJSON(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding JSON failed: %w", err)
	}
	return append(encoded, '\n'), nil
}

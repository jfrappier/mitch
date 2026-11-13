// Package exitcode defines every exit code Mitch can return.
//
// Each code means one thing, so scripts and CI pipelines can react to a
// specific failure instead of parsing log text. The full table is also in
// docs/exit-codes.md. If you add a code here, add it there too.
package exitcode

const (
	// Success means the command finished and found nothing that needs attention.
	Success = 0

	// GeneralError means the command failed for a reason not covered below.
	// The log output always says what failed and why.
	GeneralError = 1

	// UsageError means the command line was wrong: an unknown command,
	// an unknown flag, or a missing required value.
	UsageError = 2

	// NotImplemented means the command exists but has not been built yet.
	NotImplemented = 3

	// FindingsAboveThreshold means the scan worked, but it found at least one
	// issue at or above the severity the user asked to fail on.
	FindingsAboveThreshold = 4

	// PartialScan means the scan finished, but some checks were skipped,
	// for example because Vault returned HTTP 403 for a path.
	PartialScan = 5
)

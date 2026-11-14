# Exit codes

Every Mitch command exits with one of these codes, so scripts and CI jobs can react to a specific outcome. The source of truth is [`internal/exitcode/exitcode.go`](../internal/exitcode/exitcode.go).

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | Success | The command finished and found nothing that needs attention. |
| 1 | GeneralError | The command failed. The log says what failed and why. |
| 2 | UsageError | The command line was wrong: unknown command, unknown flag, or a bad flag value. |
| 3 | NotImplemented | The command exists but is not built yet. No command returns it today; the number stays reserved. |
| 4 | FindingsAboveThreshold | The scan worked and found at least one issue at or above the severity you chose to fail on. |
| 5 | PartialScan | The scan finished but skipped some checks, for example after an HTTP 403 from Vault. The log lists each skipped check. |

# Developing Mitch

## Requirements

- Go, at the version in [`go.mod`](../go.mod). With Go 1.21 or later installed, `go` downloads the right version automatically ([Go toolchains](https://go.dev/doc/toolchain)).
- [golangci-lint](https://golangci-lint.run) v2.15.0 for linting.

## Common tasks

| Task | Command |
| --- | --- |
| Run all tests | `go test -race -count=1 ./...` |
| Lint | `golangci-lint run ./...` |
| Check formatting | `gofmt -l .` (prints nothing when everything is formatted) |
| Build for your machine | `go build -o mitch ./cmd/mitch` |
| Build a static binary for another platform | `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o mitch ./cmd/mitch` |

CI runs all of these on every pull request. See [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

## Coding standards

- **Readable over clever.** Write for someone who doesn't know Go: descriptive names, one step per line, no chained one-liners.
- **Comment the why.** Every function says what it does. Every call to Vault names the endpoint.
- **Fail loud and specific.** Errors say what failed, where (Vault path or file), the HTTP status, and what to do next. Never swallow an error.
- **One log format.** Use the logger from `internal/logging` and its field constants. See [logging.md](logging.md).
- **No new dependencies without approval.** Each one must be pure Go, open source, maintained, and have a named fallback.
- **Test everything.** New code comes with tests.

## Approved dependencies

| Package | Purpose | Fallback |
| --- | --- | --- |
| `github.com/hashicorp/vault/api` | Vault HTTP client | Standard library `net/http` |
| `github.com/hashicorp/hcl/v2` | Parse policies and Terraform | None equivalent |
| `modernc.org/sqlite` | SQLite driver, no cgo | `github.com/ncruces/go-sqlite3` |
| `golang.org/x/crypto/argon2` | Passphrase key derivation | Standard library `crypto/pbkdf2` |

None are used yet. Each is added in the pull request that first needs it.

# Developing Mitch

## Requirements

- Go, at the version in [`go.mod`](../go.mod). With Go 1.21 or later installed, `go` downloads the right version automatically ([Go toolchains](https://go.dev/doc/toolchain)).
- [golangci-lint](https://golangci-lint.run) v2.15.0 for linting.

## Common tasks

| Task | Command |
| --- | --- |
| Run all unit tests | `go test -race -count=1 ./...` |
| Run integration tests | See [Integration tests](#integration-tests) |
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

Each is added in the pull request that first needs it. In use today: `github.com/hashicorp/vault/api`, `modernc.org/sqlite` and `golang.org/x/crypto/argon2`.

`vault/api` brings in these indirect dependencies, all pure Go: `cenkalti/backoff`, `go-jose/go-jose`, HashiCorp's `errwrap`, `go-cleanhttp`, `go-multierror`, `go-retryablehttp`, `go-rootcerts`, `go-secure-stdlib`, `go-sockaddr` and `hcl` v1, `mitchellh/go-homedir`, `mitchellh/mapstructure`, `ryanuber/go-glob`, and `golang.org/x/{net,text,time}`. `modernc.org/sqlite` brings in `modernc.org/{libc,mathutil,memory}`, `dustin/go-humanize`, `google/uuid`, `mattn/go-isatty`, `ncruces/go-strftime`, `remyoudompheng/bigfft` and `golang.org/x/sys`, all pure Go. The exact versions are in [`go.mod`](../go.mod).

`modernc.org/sqlite` must stay on the `modernc.org/libc` version its own `go.mod` names ([driver docs](https://pkg.go.dev/modernc.org/sqlite)). This is enforced, so nobody has to remember it:

- [`.github/dependabot.yml`](../.github/dependabot.yml) tells Dependabot never to propose a `libc`-only update.
- The CI job `dependency-pins` fails if the two versions disagree, and prints the command to fix it.

To upgrade, run `go get modernc.org/sqlite@<version> && go mod tidy`. That moves `libc` along with it.

## Integration tests

Integration tests run Mitch against a real Vault dev server. They only build with the `integration` tag, and they fail (not skip) when the two variables below are missing, so a misconfigured run can't pass by accident.

Start a Vault dev server in Docker. The official image runs a dev server by default and takes its root token from `VAULT_DEV_ROOT_TOKEN_ID` ([hashicorp/vault on Docker Hub](https://hub.docker.com/r/hashicorp/vault)). The image is multi-arch, so this works on Apple Silicon:

```shell
docker run -d --name vault-dev -p 8200:8200 --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault:2.2.2
```

Run the tests:

```shell
MITCH_TEST_VAULT_ADDR=http://127.0.0.1:8200 MITCH_TEST_VAULT_ROOT_TOKEN=root go test -tags integration -count=1 -v ./...
```

Remove the server when you are done:

```shell
docker rm -f vault-dev
```

CI runs the same tests against Vault 1.19.5 and 2.2.2. Never point these variables at a real cluster: the tests create policies and tokens.

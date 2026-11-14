[Mitch docs](README.md) › Running Mitch in Docker

# Running Mitch in Docker

The Mitch image is small and locked down. It is built on [distroless static (Debian 13)](https://github.com/GoogleContainerTools/distroless): it has no shell and no package manager, it has the CA certificates needed for TLS to Vault, and it runs as the `nonroot` user. The image works on Apple Silicon (arm64) and Intel (amd64).

> **Not built yet:** a published image. For now, build it from this repository.

## 1. Build the image

```shell
docker build -t mitch .
```

This builds for your machine's architecture. The Dockerfile cross-compiles Go, so a [multi-platform build](https://docs.docker.com/build/building/multi-platform/) for both architectures needs no emulation.

## 2. Create a volume for the database

The database lives in `/data` inside the container (`MITCH_DB=/data/mitch.db`). Put it on a named volume so scans outlive the container:

```shell
docker volume create mitch-data
```

## 3. Create the database

```shell
docker run --rm -e MITCH_PASSPHRASE -v mitch-data:/data mitch init
```

`-e MITCH_PASSPHRASE` with no value passes the variable from your shell, so the passphrase is not typed on the command line or saved in your shell history. Set it from a password manager or secret store. While the container runs, `docker inspect` can still show it to anyone who can run Docker commands on the machine; use a passphrase file if that matters. See [saving-scans.md](saving-scans.md) for passphrase rules.

To use a file instead, mount it read-only and pass `--passphrase-file`:

```shell
docker run --rm -v mitch-data:/data -v "$PWD/passphrase:/run/secrets/mitch_passphrase:ro" \
  mitch init --passphrase-file /run/secrets/mitch_passphrase
```

On Linux, the container reads the file as uid 65532, so that user must be able to read it. Docker Desktop on macOS handles this for you.

Or add `-it` (`docker run --rm -it ...`) and Mitch asks for the passphrase without showing what you type.

## 4. Scan

```shell
docker run --rm -e MITCH_PASSPHRASE -e VAULT_ADDR -e VAULT_TOKEN -v mitch-data:/data mitch scan
```

If Vault runs on your Mac (for example a dev server on port 8200), use `VAULT_ADDR=http://host.docker.internal:8200`. On Docker Desktop, [`host.docker.internal`](https://docs.docker.com/desktop/features/networking/networking-how-tos/) reaches your host.

See [scanning.md](scanning.md) for the policy the token needs.

## 5. Use the results

Every other command works the same way:

```shell
docker run --rm -e MITCH_PASSPHRASE -v mitch-data:/data mitch history
docker run --rm -e MITCH_PASSPHRASE -v mitch-data:/data mitch report
```

To get files out, such as `--output` or `mitch terraform`, mount a folder from your machine and write into it:

```shell
mkdir -p out
docker run --rm -e MITCH_PASSPHRASE -v mitch-data:/data -v "$PWD/out:/out" mitch report --output /out/report.json
```

On Linux, the container writes as uid 65532, so that folder must be writable by that user. Docker Desktop on macOS handles this for you.

## Browse in the web UI

See [web-ui.md](web-ui.md#running-in-docker) for `mitch serve` in a container.

## Build arguments

| Argument | Default | Meaning |
| --- | --- | --- |
| `VERSION` | `dev` | Shown by `mitch version`. |
| `COMMIT` | `unknown` | Shown by `mitch version`. |
| `BUILD_DATE` | `unknown` | Shown by `mitch version`. |
| `GO_VERSION` | the `go` line in `go.mod` | The Go toolchain image used to build. |

For example: `docker build --build-arg VERSION=v0.1.0 --build-arg COMMIT="$(git rev-parse HEAD)" -t mitch .`

Only `go.mod`, `go.sum`, `cmd/` and `internal/` are sent to Docker (see `.dockerignore`), so a local `mitch.db` or generated files never end up in an image.

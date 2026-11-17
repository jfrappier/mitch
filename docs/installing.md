---
title: Installing Mitch
weight: 1
---

Mitch is one file with nothing else to install. Download the binary for your machine from the [latest release](https://github.com/jfrappier/mitch/releases/latest), or pull the Docker image from GitHub Container Registry.

Every release is built by the [release workflow](https://github.com/jfrappier/mitch/blob/main/.github/workflows/release.yml) in this repository, never on someone's laptop.

## Download a binary

| Your machine | File |
| --- | --- |
| Mac with Apple Silicon (M1 and later) | `mitch-darwin-arm64` |
| Mac with Intel | `mitch-darwin-amd64` |
| Linux, arm64 | `mitch-linux-arm64` |
| Linux, x86-64 | `mitch-linux-amd64` |
| Windows, x86-64 | `mitch-windows-amd64.exe` |

### 1. Download the binary and the checksum file

This example is for a Mac with Apple Silicon. Change `FILE` for another machine.

```shell
FILE=mitch-darwin-arm64
BASE=https://github.com/jfrappier/mitch/releases/latest/download
curl --fail --show-error --location --output "$FILE" --write-out "$FILE: HTTP %{http_code}\n" "$BASE/$FILE"
curl --fail --show-error --location --output SHA256SUMS --write-out "SHA256SUMS: HTTP %{http_code}\n" "$BASE/SHA256SUMS"
```

Both lines should end with `HTTP 200`. `--fail` makes curl stop with an error on any other status, instead of saving an error page as the binary.

### 2. Check the checksum

On macOS:

```shell
grep " $FILE\$" SHA256SUMS | shasum -a 256 --check
```

On Linux:

```shell
grep " $FILE\$" SHA256SUMS | sha256sum --check --strict
```

You should see `mitch-darwin-arm64: OK`. Anything else means the download is damaged or is not the released file. Do not run it.

### 3. Install it

```shell
chmod +x "$FILE"
sudo mv "$FILE" /usr/local/bin/mitch
mitch version
```

`mitch version` prints the release version and the commit it was built from.

### Optional: check where the binary came from

Each release binary has a signed [build provenance attestation](https://docs.github.com/en/actions/concepts/security/artifact-attestations). It proves the file was built by Mitch's release workflow, from this repository. With the [GitHub CLI](https://cli.github.com/):

```shell
gh attestation verify mitch-darwin-arm64 --repo jfrappier/mitch
```

Run it on the downloaded file, before step 3 renames it. Docs: [`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify).

## Pull the Docker image

The image works on Apple Silicon and Intel; Docker picks the right one.

```shell
docker pull ghcr.io/jfrappier/mitch:latest
```

| Tag | Meaning |
| --- | --- |
| `latest` | The newest release. |
| `0.1.0` | Exactly that release. |
| `0.1` | The newest `0.1.x` release. |

Pin an exact version, such as `ghcr.io/jfrappier/mitch:0.1.0`, anywhere you need the same Mitch every time, such as CI.

The image has a signed build provenance attestation too. `gh attestation verify` needs you to be logged in to the registry for this ([docs](https://cli.github.com/manual/gh_attestation_verify)):

```shell
gh attestation verify oci://ghcr.io/jfrappier/mitch:latest --repo jfrappier/mitch
```

See [Running Mitch in Docker](docker.md) for how to run it.

## Build it yourself

You need Go (the version in `go.mod`):

```shell
go build -o mitch ./cmd/mitch
```

See [Developing Mitch](development.md) for tests and the rest.

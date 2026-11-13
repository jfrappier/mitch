<p align="center">
  <img src="docs/assets/logo.png" alt="Mitch the bulldog" width="200">
</p>

# Mitch

Mitch is a read-only inventory and audit tool for HashiCorp Vault.

People often ask how to run reports in Vault, but Vault is not a CMDB or an inventory tool. Mitch scans a Vault cluster and stores what it finds, so you can answer questions like "how many secrets do we have?", "which plugins were installed by hand?", and "which policies are too broad?"

> **Status:** early development. `mitch scan` works today: it inventories Vault, including secret counts for KV mounts, and saves each scan encrypted (`mitch init`, `mitch history`, `mitch export`), and shows what changed between two scans (`mitch diff`). Reports, Terraform and policy findings are not built yet. See [Scanning Vault](docs/scanning.md), [Saving scans](docs/saving-scans.md) and [Comparing scans](docs/comparing-scans.md).

## What Mitch will do

- **Scan** secrets engine and auth method mounts, the paths under them, plugins (built-in vs manually registered), server configuration, namespaces (Enterprise), and ACL policies.
- **Report** on counts, changes since the last scan, and drift between Vault and your git repository.
- **Generate Terraform** so Vault configuration can be managed as code.
- **Flag overly permissive policies** and suggest tighter ones.

## Design principles

- **Read-only.** Mitch never writes to Vault and never reads secret values. It lists paths and reads metadata only.
- **One binary, nothing to install.** Mitch is a single Go binary for macOS, Linux and Windows, plus a small Docker image. No runtime or package manager required.
- **Encrypted at rest.** Scan results are stored in a local SQLite database, with sensitive fields encrypted using a key derived from your passphrase.
- **Least privilege.** Mitch publishes the exact Vault policies it needs. Endpoints that require `sudo` are skipped unless you opt in with `--sudo`.

## Documentation

- [Scanning Vault](docs/scanning.md): policy setup, flags, and output
- [Saving scans](docs/saving-scans.md): the encrypted database and passphrase
- [Comparing scans](docs/comparing-scans.md): what changed between two scans
- [Design decisions](docs/design-decisions.md) and what each means for you
- [How Mitch protects your data](docs/data-security.md)
- [Logging](docs/logging.md)
- [Exit codes](docs/exit-codes.md)
- [Developing Mitch](docs/development.md)

## Supported Vault versions

Vault 1.19 and later, including 2.x.

## License

Apache License 2.0. See [LICENSE](LICENSE).

<p align="center">
  <img src="docs/assets/logo.png" alt="Mitch the bulldog" width="200">
</p>

# Mitch

Mitch is a read-only inventory and audit tool for HashiCorp Vault.

People often ask how to run reports in Vault, but Vault is not a CMDB or an inventory tool. Mitch scans a Vault cluster and stores what it finds, so you can answer questions like "how many secrets do we have?", "which plugins were installed by hand?", and "which policies are too broad?"

> **Status:** early development. Nothing here is usable yet.

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

## Supported Vault versions

Vault 1.19 and later, including 2.x.

## License

Apache License 2.0. See [LICENSE](LICENSE).

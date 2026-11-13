# Design decisions

Each decision below says what was chosen, why, and what it means for you as a user.

## Read-only, never secret values

**Decision:** Mitch never writes to Vault and never reads secret data. It lists paths and reads metadata only.
**Impact:** You can give Mitch a narrowly scoped token. Secret counts come from listing paths, which takes one request per folder, so large Vaults take longer to scan.

## KV secrets are counted, not named

**Decision:** Mitch counts secrets and folders in every KV v1 and v2 mount by listing key names, one request at a time. It records only the counts per mount, never key or folder names. The policy that allows this, `mitch-scanner-kv`, names each mount exactly instead of using a wildcard. Counting is on by default; `--kv=false` turns it off.
**Impact:** Folder names, which can reveal what a Vault holds, stay out of the inventory and logs. You run `mitch policy --kv2-mount <mount>` for your KV mounts and update the policy when you add one. Until you do, the scan exits with code 5 and names the command to run.

## One Go binary, no runtime

**Decision:** Mitch is written in Go and ships as one static binary per platform (macOS arm64/amd64, Linux arm64/amd64, Windows amd64), plus a small Docker image.
**Impact:** Nothing else to install or maintain: no Node, Python or package manager. All dependencies are pure Go and compiled in.

## SQLite storage, encrypted by Mitch

**Decision:** Scan results are stored in a local SQLite file. Each scan is encrypted as a whole by Mitch, with a key derived from your passphrase; only ids and timestamps stay in the clear. `mitch scan` saves by default and unlocks the database before contacting Vault. See [data-security.md](data-security.md).
**Impact:** A stolen database file or backup is unreadable without the passphrase. If you lose the passphrase, your scan history cannot be recovered. Run `mitch init` once before your first scan, or use `--no-save` for a one-off JSON inventory.

## Git as the source of truth

**Decision:** Mitch recommends that all Vault policies live in git as HCL files used by Terraform, and that all Vault configuration is Terraform. You point Mitch at a local checkout; Mitch never clones or holds git credentials.
**Impact:** Without a repository, every report contains one high-severity finding saying Vault config can't be confirmed as managed as code. With a repository, Mitch reports drift between git and the live Vault.

## Sudo is opt-in

**Decision:** Some Vault endpoints require the `sudo` capability. Mitch skips them unless you pass `--sudo` and attach the published sudo add-on policy.
**Impact:** The default scan needs no `sudo`. Audit devices and plugin checksums are only checked with `--sudo`, and the report lists what was skipped.

## CLI and local UI, no scheduler

**Decision:** One binary provides the CLI and a local read-only web UI (`mitch serve`). Mitch has no built-in scheduler.
**Impact:** Run it once, in CI, or on a schedule with cron or the tool you already use.

## No AI in v1

**Decision:** Every count, finding and Terraform file comes from deterministic code. A later version may let you connect your own AI provider for explanations, off by default.
**Impact:** Results are repeatable and nothing about your Vault is sent to a third party.

## Supported Vault versions

**Decision:** Vault 1.19 and later, tested against 2.x.
**Impact:** Older versions may work but are not tested.

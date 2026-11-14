<p align="center">
  <img src="assets/logo.png" alt="Mitch the bulldog" width="120">
</p>

<h1 align="center">Mitch documentation</h1>

Mitch scans a HashiCorp Vault cluster, read-only, and saves an encrypted inventory you can report on, compare and turn into Terraform. Start with **Get started** in order; the rest you can read when you need it.

## Get started

| Step | Page | What you do there |
| --- | --- | --- |
| 1 | [Saving scans](saving-scans.md) | Choose a passphrase and create the encrypted database with `mitch init`. |
| 2 | [Scanning Vault](scanning.md) | Load Mitch's Vault policy, create a token, and run `mitch scan`. |
| 3 | [Reports](reports.md) | Summarize a scan with `mitch report`. |

## Use your scans

| Page | Command | What it covers |
| --- | --- | --- |
| [Comparing scans](comparing-scans.md) | `mitch diff` | What changed in Vault between two scans. |
| [Generating Terraform](terraform.md) | `mitch terraform` | Write Terraform with import blocks, then let Terraform manage Vault. |
| [The web UI](web-ui.md) | `mitch serve` | Browse scans, reports and changes in your browser. |
| [Running in Docker](docker.md) | `docker run ... mitch` | Build the image and keep the database on a volume. |

## Understand Mitch

| Page | What it covers |
| --- | --- |
| [How Mitch protects your data](data-security.md) | What is stored, how it is encrypted, and what to treat as sensitive. |
| [Design decisions](design-decisions.md) | Each decision and what it means for you. |

## Reference

| Page | What it covers |
| --- | --- |
| [Logging](logging.md) | Log format, fields, and what is redacted. |
| [Exit codes](exit-codes.md) | What each exit code means, for scripts and CI. |
| [Developing Mitch](development.md) | Build, test, and run the integration tests. |

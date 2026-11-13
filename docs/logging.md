# Logging

Mitch writes every log line in the same format, so people can read it and log tools can parse it without custom rules.

- Log lines go to **standard error**. Command results go to **standard output**, so you can redirect results to a file without log lines mixed in.
- Mitch uses Go's standard [`log/slog`](https://pkg.go.dev/log/slog) package. No third-party logging library.

## Formats

Choose the format with the global `--log-format` flag, before the command name.

**text** (default): `key=value` pairs, one line per entry.

```text
time=2026-11-13T00:22:05.663Z level=ERROR msg="command is not implemented yet" component=scan operation=run_command command=scan next_step="watch the project README for release notes"
```

**json**: one JSON object per line.

```json
{"time":"2026-11-13T00:22:05.665Z","level":"ERROR","msg":"unknown command","component":"cli","operation":"parse_command","command":"bogus","next_step":"run \"mitch help\" to see available commands"}
```

## Fields

| Field | Always present | Meaning |
| --- | --- | --- |
| `time` | Yes | When the line was written, RFC 3339. |
| `level` | Yes | `DEBUG`, `INFO`, `WARN` or `ERROR`. |
| `msg` | Yes | What happened, in plain words. |
| `component` | Yes | Which part of Mitch wrote the line, such as `cli` or `scan`. |
| `operation` | Yes | What that part was doing, such as `list_mounts`. |
| `http_status` | On Vault calls | The HTTP status Vault returned. |
| `duration_ms` | On Vault calls | How long the call took, in milliseconds. |
| `error` | On failures | The underlying error. |
| `next_step` | On failures | What to do about it. |

## Levels

Set the lowest level written with `--log-level debug|info|warn|error`. The default is `info`.

## What is never logged

Mitch never logs secret values or Vault tokens. Folder and key names inside KV mounts are always redacted, because they can reveal what a Vault holds. A failed list inside a mount is logged as, for example, `path=secret/metadata/<redacted>`. Mount paths are not redacted, because they are already in the inventory.

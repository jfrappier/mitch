# The web UI

`mitch serve` runs a small web page for browsing saved scans: the list of scans, the report for each one (the same as `mitch report`), and the changes between two scans (the same as `mitch diff`). It reads only the saved, encrypted scans. It never contacts Vault, never starts a scan, and never changes the database.

## 1. Start it

```shell
mitch serve
```

Mitch asks for the database passphrase (or reads `MITCH_PASSPHRASE` or `--passphrase-file`, see [saving-scans.md](saving-scans.md)), then prints a link:

```text
Mitch web UI is running. Open this link (it holds this run's access token):

  http://127.0.0.1:8484/login?token=3f9c...

Press Ctrl+C to stop.
```

## 2. Open the link

Open the link in your browser. The token in it is new every time `mitch serve` starts. The browser keeps it in a cookie until you close the browser, and the address bar no longer shows it. Without the token, every page answers `401 Unauthorized`.

The page has no scripts and loads nothing from other sites. Pages are not cached by the browser.

## 3. Stop it

Press Ctrl+C. The database is closed and the token stops working.

## Why there is a token

The UI listens on `127.0.0.1`, so other machines cannot reach it. Other users and other programs on the same machine can, and so can a web page in your own browser that sends requests to `127.0.0.1`. The token keeps all of them out: only someone who saw the link in your terminal can open the pages.

Treat the link like the passphrase while `mitch serve` runs. It is printed to the terminal only and never written to the log.

## Running in Docker

Inside a container, `127.0.0.1` is the container itself, so listen on every address and publish the port to `127.0.0.1` on your machine only:

```shell
docker run --rm -it -e MITCH_PASSPHRASE -v mitch-data:/data -p 127.0.0.1:8484:8484 mitch serve --listen 0.0.0.0:8484
```

The printed link uses `127.0.0.1:8484`, which reaches the container through the published port. `-p 127.0.0.1:8484:8484` keeps the port off your network ([Docker port publishing](https://docs.docker.com/engine/network/port-publishing/)). Mitch logs a warning whenever it listens on anything other than `127.0.0.1` or `::1`, because the UI uses plain HTTP.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen ADDRESS:PORT` | `127.0.0.1:8484` | Where to listen. Port `0` picks a free port, shown in the link. |
| `--db PATH`, `--passphrase-file FILE` | | See [saving-scans.md](saving-scans.md). |

If the port is in use, Mitch exits with an error; pick another with `--listen 127.0.0.1:8485`.

> **Not built yet:** policy findings. The UI will show them once `mitch` produces them.

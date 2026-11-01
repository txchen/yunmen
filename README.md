# Yunmen

Yunmen (云门, "cloud gate") is a small self-hosted SSH gateway for one person's servers. You reach it from a browser or from the `yunmen` CLI. Target SSH keys and passwords stay on the gateway. Your laptop, a work machine, or a borrowed browser only ever hold revocable Yunmen credentials.

- **Web**: hosts, multiple terminal tabs (xterm.js), a minimal file browser with upload and download, and device management.
- **CLI**: `yunmen login | hosts | connect [alias] | logout`. A full interactive PTY for vim and tmux, with no cloudflared on the client.
- **Security**: Cloudflare Access in front, plus Yunmen's own password and TOTP. CLI devices are approved in the browser and revoked one at a time, and revocation closes their terminals. Credentials are encrypted at rest.

The gateway terminates SSH, so it and Cloudflare can see terminal traffic. This is not end-to-end encryption between your device and the target.

## Install the CLI

Linux and macOS (amd64, arm64):

```sh
curl -fsSL https://raw.githubusercontent.com/txchen/yunmen/master/scripts/install.sh | sh
```

The script downloads the latest release from GitHub, verifies its SHA-256 checksum, and installs `yunmen` to `/usr/local/bin` if that directory is writable, otherwise to `~/.local/bin`. Set `YUNMEN_VERSION=v0.0.1` to pin a version or `YUNMEN_INSTALL_DIR` to choose the directory. Archives and `checksums.txt` are also on the [releases page](https://github.com/txchen/yunmen/releases).

## Documentation

- [Deployment](docs/deployment.md): Cloudflare Tunnel + Access, Compose, first-time setup.
- [Operations](docs/operations.md): configuration, admin commands, backup and restore.
- [API and terminal protocol](docs/api.md).
- [Requirements](docs/requirements.md), [decisions](docs/decisions.md), [open questions](docs/open-questions.md).

## Development

Requires Go 1.27+ and Node 24+. The integration tests also use OpenSSH `sshd`, `sftp-server`, `tmux`, and `vim`, and skip tests that need them when they are missing.

```sh
make web            # build web/dist (embedded into the server)
make test           # go vet, go test, web unit tests
make e2e            # real binaries in a real PTY + headless Firefox against a local sshd
make build          # dist/yunmen-server, dist/yunmen
make image          # Docker image
```

To run locally against a loopback origin:

```sh
export YUNMEN_MASTER_KEY_FILE=./data/master.key YUNMEN_DATA_DIR=./data
mkdir -p data && go run ./cmd/yunmen-server genkey > data/master.key && chmod 600 data/master.key
go run ./cmd/yunmen-server init
YUNMEN_MODE=standalone YUNMEN_PUBLIC_ORIGIN=http://127.0.0.1:8080 go run ./cmd/yunmen-server
```

For Web development with hot reload, run `cd web && npm run dev`. Then start the server with `YUNMEN_PUBLIC_ORIGIN=http://localhost:5173` so that the proxied `Origin` matches.

# Operations

## Configuration

| Variable | Required | Meaning |
| --- | --- | --- |
| `YUNMEN_MODE` | yes | `access` or `standalone`. No default and no fallback. |
| `YUNMEN_PUBLIC_ORIGIN` | yes | Exact browser origin, e.g. `https://yunmen.example.com`. `http` is accepted only for loopback development. |
| `YUNMEN_MASTER_KEY` / `YUNMEN_MASTER_KEY_FILE` | exactly one | Base64 of 32 random bytes (`yunmen-server genkey`). |
| `YUNMEN_DATA_DIR` | no | Database directory (default `./data`, `/data` in the image). |
| `YUNMEN_LISTEN` | no | Listen address (default `127.0.0.1:8080`, `0.0.0.0:8080` in the image). |
| `YUNMEN_CLIENT_IP_HEADER` | no | Header carrying the visitor's address, set by the tunnel or proxy in front, e.g. `Cf-Connecting-IP` or `X-Real-IP`. Used to rate limit sign-in per visitor. For `X-Forwarded-For` the last address is used. Set it only when nothing but that proxy can reach Yunmen, because anyone else could send the header. Unset, the TCP peer address is used. |
| `YUNMEN_ACCESS_TEAM_DOMAIN` | access mode only | `https://<team>.cloudflareaccess.com` |
| `YUNMEN_ACCESS_AUD` | access mode only | Access application audience tag |
| `YUNMEN_ACCESS_OWNER_EMAILS` | access mode only | Comma-separated browser identities treated as the owner |
| `YUNMEN_ACCESS_SERVICE_CLIENT_IDS` | access mode only | Comma-separated service-token Client IDs allowed to pair CLI devices |

CLI: `YUNMEN_CONFIG_DIR` overrides the config directory. `YUNMEN_NO_KEYRING=1` forces the file fallback.

## Administration commands

Run them where the database and key are available, for example `docker compose run --rm -it yunmen <command>`.

- `init` creates the owner and enrolls TOTP. It runs once.
- `reset-password` and `reset-totp` are local recovery. They revoke all sessions and devices.
- `revoke-all` revokes every session and device without changing secrets.
- `recovery-codes` replaces the owner's 10 recovery codes and prints them. `init` also prints the first set.
- `genkey` prints a new master key. Never use it to replace the key of an existing database.

After `reset-*` or `revoke-all`, a running server closes the affected terminals within about 15 seconds.

## Backup and restore

A backup is two things, kept apart:

1. **The database.** With the Compose setup it is `deploy/data/yunmen.db`. Stop the server (`docker compose stop`) and copy it. Alternatively, while it runs, use `sqlite3 deploy/data/yunmen.db ".backup /backup/yunmen.db"`. Do not copy the live file with plain `cp`, because the WAL may hold recent writes.
2. **The master key**, stored separately, in a password manager or offline. The database without the key cannot decrypt target credentials or the TOTP seed. The key without the database is useless.

To restore, keep the server stopped, put the database back in place, and configure the same master key. Run `docker compose run --rm yunmen revoke-all` before starting the service, so sessions and devices revoked after the backup was taken never become usable again. Then run `docker compose up -d` and re-pair your CLI devices. Yunmen verifies the master key when opening the database.

If the key is lost, the encrypted data cannot be recovered. Start a new database, run `init` again, and re-enter the hosts.

## Logs

The server writes JSON lines to stderr: sign-ins, host and device changes, terminal open and close with their reasons, and upload results. Logs never contain secrets or terminal content.

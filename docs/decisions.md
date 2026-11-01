# Implementation decisions

Choices made while building v1. Each one is reversible unless it says otherwise. Product requirements are in [requirements.md](requirements.md).

## Stack

| Area | Decision | Why |
| --- | --- | --- |
| Server and CLI | Go, one module (`cmd/yunmen-server`, `cmd/yunmen`) | Long-lived byte streams and cancellation; static binaries. Recommended in the design, adopted. |
| Web | Vue 3 + TypeScript + Vite + xterm.js | Vue is required; TypeScript keeps the protocol client typed. |
| Storage | SQLite (`modernc.org/sqlite`, pure Go, no cgo), WAL, append-only numbered migrations in `internal/store/store.go` | One file, static builds, cross-compiles. |
| SSH | `golang.org/x/crypto/ssh` in-process client; `github.com/pkg/sftp` | Server terminates SSH; no system `ssh` or ambient config. |
| WebSocket | `github.com/coder/websocket` | Context-based API that fits the cancellation model. |
| Access JWT | `github.com/golang-jwt/jwt/v5`, RS256 only | Cloudflare signs with RS256. |
| Keyring | `github.com/zalando/go-keyring` (macOS Keychain, Secret Service on Linux) | Falls back to `secrets.json` (0600) when unavailable. |
| Versioning | One version string (`internal/version`) for server, CLI and image | Matching versions are the supported combination. |
| Release | GitHub Releases for CLI archives and checksums; GHCR multi-arch image (`.github/workflows/release.yml`) | Not run yet. |

## Initial support matrix

| Item | Supported in v1 | Not supported |
| --- | --- | --- |
| Server | Linux amd64/arm64 container; any Linux host for the binary | |
| CLI | Linux, macOS and Windows, amd64 and arm64 (release builds). Linux amd64 is tested; macOS, Windows and arm64 are built but untested | |
| Browsers | Current Firefox and Chromium-based browsers (Firefox tested headless) | Safari untested |
| Target key formats | OpenSSH, PKCS#1, SEC1, PKCS#8 PEM; Ed25519, ECDSA (P-256/384/521), RSA ≥ 2048; passphrase-protected keys (the passphrase is used once at import and discarded) | DSA, RSA < 2048, FIDO/`sk-` keys, PuTTY `.ppk`, OpenSSH certificates |
| Target auth | `publickey` and standard `password` | `keyboard-interactive`, target-side MFA, agent forwarding |
| SFTP upload | Servers that support `hardlink@openssh.com` (OpenSSH sftp-server, pkg/sftp) | Servers without it: upload is refused with a clear error; listing and download still work |

## Security model

- **Two layers, never one.** `YUNMEN_MODE` must be set explicitly to `access` or `standalone`. In access mode every request, static assets and WebSocket upgrades included, needs a valid `Cf-Access-Jwt-Assertion`, checked for RS256, issuer, audience, expiry (required), and a signing key from `<team>/cdn-cgi/access/certs`. The server never falls back from access mode. Standalone mode skips only the Cloudflare layer.
- **Principals.** A user assertion (`sub` and `email` present) maps to the owner only if the email is in `YUNMEN_ACCESS_OWNER_EMAILS`. A service-token assertion (`common_name` present, empty `sub`) maps to a service principal only if the Client ID is in `YUNMEN_ACCESS_SERVICE_CLIENT_IDS`. Owner APIs reject service principals, and CLI APIs reject owner assertions.
- **Device binding.** Pairing start, poll, and every later CLI request must come from the same service principal. The device token is stored as a SHA-256 hash (tokens are 256-bit random) and is bound to that principal.
- **Owner login** takes password and TOTP in one request. There is no partial "password OK" state, and the error does not say which factor failed. Passwords use Argon2id (64 MiB, t=3). TOTP is RFC 6238 SHA-1, 6 digits, 30 s, ±1 step. The last accepted step is advanced atomically, so a code works once. Failures are rate limited at 5 per 5 minutes per client address and 20 per 5 minutes overall. Attempts are reserved before the password hash runs, so parallel guesses cannot exceed the budget. The client address comes from the header named by `YUNMEN_CLIENT_IP_HEADER` when set (the owner's deployment uses `Cf-Connecting-IP` from the host tunnel), from `Cf-Connecting-IP` in access mode, and otherwise from the TCP peer. An unset header is never trusted, so clients cannot invent a fresh address per guess.
- **CLI approval** always asks for the owner password and a fresh TOTP code. The approval page needs the user code typed in and never lists pending requests. Pairing requests expire after 5 minutes, at most 10 can be pending, and the poll interval is 2 seconds.
- **Browser session**: opaque random token in a `__Host-` cookie (HttpOnly, Secure, SameSite=Strict), stored hashed, 12-hour fixed expiry. Every non-GET request and every browser WebSocket upgrade must carry `Origin` equal to `YUNMEN_PUBLIC_ORIGIN`. A CLI upgrade uses a bearer token and must not carry an `Origin`.
- **Encryption at rest**: AES-256-GCM with a random nonce and a version byte. Associated data binds each ciphertext to its purpose and record ID (`host/credential-id`), so a blob cannot be moved to another record. On a new database a key-check record is written. Every later start verifies it before any migration or write. A database that already holds encrypted rows but no key check is refused.
- **Logs** carry IDs, aliases and reasons. They never contain passwords, keys, tokens, TOTP data or terminal content.

## Host trust

- Probe fetches the host key without offering any user credential and returns a 10-minute observation ID tied to the exact `address:port`.
- Create and update test SSH authentication with the observed key pinned before anything is saved, and report whether SFTP is available.
- Connections restrict `HostKeyAlgorithms` to the pinned key type and compare the full key bytes. RSA host keys must sign with SHA-2, so OpenSSH older than 7.2 cannot be used with an RSA host key. A mismatch is reported as `host_key_changed` before any credential is sent.
- Changing address or port requires a new observation. Username or credential changes keep the pin.
- **Key library.** Private keys live in a library (`ssh_keys`) and hosts reference one key, so one key serves many hosts. A key can be generated on the gateway (Ed25519), in which case only its public line is ever shown, or imported. Importing a key that is already in the library reuses the existing entry. Deleting a key is refused while hosts use it. Deleting it also ends terminals and transfers that are still running with it. Each session records the key it authenticated with in the live registry for that purpose. Passwords stay owned by their host.
- Schema 2 moves every host-owned key from schema 1 into the library, deduplicated by fingerprint. The move runs inside the migration transaction.

## Terminal

- One WebSocket is one new shell on one host, chosen by host ID. The endpoint accepts no addresses or credentials.
- Binary frames carry raw bytes, at most 16 KiB. Text frames carry JSON controls. The gateway never decodes, splits lines, or converts newlines.
- Output window is 256 KiB of unacknowledged output. If acks make no progress for 60 s while output is pending, the terminal ends with `slow_consumer`. Input is acknowledged after the SSH channel write, and clients keep at most 64 KiB in flight. The server pings every 25 s, and the CLI pings independently.
- The live registry (`internal/live`) serializes registration against revocation and keeps tombstones. Every terminal and transfer registers before SSH resources are allocated, and ends at the earliest of the Yunmen credential expiry and the Access assertion expiry. Each credential can hold at most 32 live operations at once.
- Every 15 seconds the server re-checks every live credential against the database. This ends sessions revoked by the local recovery commands, which run in a separate process.
- Client input is written to SSH by its own goroutine, through a queue bounded at 80 KiB. When the remote stops reading, acks, pings, resize and close still get through. A client that goes past the input window is ended with `protocol_error`.
- Ending a terminal releases its registry entry and SSH session before the WebSocket close handshake, so a peer that never answers the close frame cannot keep resources alive.
- The CLI uses raw mode and restores it on every exit path, including signals and panics. Ctrl-C is sent as byte `0x03`. `Enter ~ .` disconnects locally, and `~~` sends a literal `~`. After an abnormal end the CLI turns off mouse and bracketed-paste modes and shows the cursor. It deliberately does not leave the alternate screen, so the last screen stays visible. It sends the local `$TERM` and falls back to `xterm-256color`. The browser sends `xterm-256color`.
- **Web input encoding.** Firefox delivers non-BMP characters such as emoji as two keypress events, one per UTF-16 surrogate half, and xterm forwards each half separately. The web client holds a trailing high surrogate until its partner arrives (`web/src/terminal/encode.ts`). Before this fix, each half was encoded alone and became U+FFFD. The real-browser e2e run reproduced this. It is one concrete instance of the terminal-character class of bug.
- Reconnecting starts a new shell and nothing is replayed. Persistence comes from remote tmux.

## Files

- Each listing, download, or upload owns its own SSH and SFTP connection. It never shares a terminal's connection.
- Listing is capped at 5000 entries (`truncated`). Symlink target types are resolved, and names that are not UTF-8 are shown but disabled.
- Downloads stream with `Content-Length`. A failure mid-stream truncates the response, so the browser reports it as failed.
- **Uploads never overwrite.**
  1. The destination is checked with `Lstat`, so a symlink counts as existing and is never followed.
  2. The data goes to an exclusively created temporary file, `.<name>.yunmen-<id>.part`, in the same directory, in sequential chunks of at most 8 MiB with a SHA-256 per chunk.
  3. After every byte is written and the file has closed, commit is `hardlink(temp, final)`, which fails if `final` exists. The temporary link is then removed.
  - Servers without the hardlink extension get an explicit refusal.
  - Cancel, a 2-minute idle timeout, revocation, logout, host removal, or shutdown removes exactly that temporary file.
  - A SQLite ledger lists pending temporary files, and the server removes them at startup.
- **Simplification versus the design.** `begin` has no idempotency key. A lost `begin` response leaves an upload that is cleaned up after 2 minutes idle. Retrying the last chunk or a commit is safe. A chunk whose body is cut off, or whose digest does not match, is rolled back on the server, and the Web client resends it up to 3 times. The 2-minute idle timer counts only the time between chunks, so a slow chunk is never cut off partway.

## Recovery

- **Recovery codes.** `init` prints 10 one-time codes (`XXXXX-XXXXX`, 50 bits each, stored as SHA-256 hashes). On the Web, password plus a recovery code starts the replacement of the authenticator. The code is used up only once the new authenticator confirms a code, in the same transaction that replaces the TOTP secret and revokes every session and device. A recovery code never signs in by itself. Codes can be regenerated in Settings (password and TOTP) or with `yunmen-server recovery-codes`.
- Local recovery also remains: `yunmen-server reset-password`, `reset-totp`, and `revoke-all` run on the server and revoke every session and device. A running server closes the affected terminals within about 15 seconds.
- **Windows CLI.** Prompts use `CONIN$`/`CONOUT$` in place of `/dev/tty`. The console gets VT input (from `x/term` raw mode) and VT output processing with `DISABLE_NEWLINE_AUTO_RETURN`, so bytes are interpreted as sent, and the mode is restored on exit. Resize is detected by polling every 250 ms. Secrets use the Windows Credential Manager. `scripts/install.ps1` installs to `%LOCALAPPDATA%\Programs\yunmen` and adds it to the user PATH. The PowerShell script was tested with PowerShell 7 in a Linux container; the Windows binaries have never run.
- **No upload size limit**, by owner decision. Transfers are limited only by the target and by Cloudflare.
- **Session persistence is the remote multiplexer's job**, by owner decision: tmux or a similar tool on the target. The gateway never keeps or resumes a shell.

## Reconciliation with the original design

| Design proposal | v1 | Reason |
| --- | --- | --- |
| Password, then a separate MFA challenge | One request with both factors | Removes a partially authenticated state. Same security. |
| Recovery codes | Recovery codes plus local admin reset | Adopted in v0.0.2 at the owner's request. |
| Five-minute reauthentication for sensitive actions | Fresh password and TOTP on every device approval; host edits use the session | Device approval is the step that grants new access. |
| Reusable key records and key import | Key library with generate and import | Adopted in v0.0.2 at the owner's request. |
| OpenAPI-generated clients | Hand-written `docs/api.md`, Go and TS mirrors | Small API. Generation was not worth the toolchain yet. |
| Persisted upload idempotency and commit records | In-memory results for 10 minutes plus a cleanup ledger | Restart does not resume uploads in v1, as the design allows. |

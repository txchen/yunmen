# Yunmen HTTP and terminal API (v1)

The server serves the Web UI and this API from one origin. Every response under `/api/` has `Cache-Control: no-store`. Errors are JSON: `{"error": "human readable message"}`, sometimes with extra fields noted below.

## Authentication layers

| Caller | Outer layer (access mode) | Yunmen layer |
| --- | --- | --- |
| Browser | `Cf-Access-Jwt-Assertion` for an owner email | `__Host-yunmen_session` cookie (`yunmen_session` on an http localhost dev origin), HttpOnly, SameSite=Strict, 12 h fixed |
| CLI | Same header, minted by Cloudflare from `CF-Access-Client-Id` / `CF-Access-Client-Secret`, for an allowed service token | `Authorization: Bearer ymd_...` device token, 30 d fixed, bound to that service token |

In standalone mode the outer layer is skipped. Yunmen credentials are always required.

Browser state-changing requests (any method other than GET) must send `Origin` equal to the configured public origin; the browser does this automatically for `fetch`. A request without a valid session gets `401`; a missing or invalid Access assertion gets `403`.

## Browser endpoints

### Session

- `POST /api/v1/auth/login` `{password, code}` → `200 {expiresAt}` and sets the cookie. `401` wrong password or code (deliberately not distinguished), `429` too many failures (5 per 5 minutes), `503` owner not initialized.
- `POST /api/v1/auth/logout` → `204`. Ends this session's terminals and transfers.
- `GET /api/v1/auth/session` → `200 {expiresAt, mode}` or `401`. Use it at app start to decide between the login view and the app.

### Hosts

Host object:

```json
{
  "id": "…", "alias": "home", "name": "Home server",
  "address": "10.0.0.2", "port": 22, "username": "me",
  "authKind": "key" | "password",
  "keyFingerprint": "SHA256:…",          // only for key auth: the client key
  "hostKeyType": "ssh-ed25519",
  "hostKeyFingerprint": "SHA256:…",      // the pinned target host key
  "revision": 3, "createdAt": "…", "updatedAt": "…"
}
```

Saved passwords and private keys are never returned.

- `GET /api/v1/hosts` → `200 [Host]`.
- `POST /api/v1/hosts/probe` `{address, port}` → `200 {observationId, endpoint, keyType, fingerprint, expiresAt}`. Fetches the target host key without sending any credential. `502 {error}` when unreachable. The UI must show `keyType` and `fingerprint` and require the owner to confirm them against an independent source (for example `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the target) before saving.
- `POST /api/v1/hosts` `{alias, name, address, port, username, auth, observationId}` → `201 {host, sftpAvailable}`.
  - `auth` is `{kind: "key", privateKey: "<PEM text>", passphrase?: "…"}` or `{kind: "password", password: "…"}`.
  - The server tests SSH authentication with the observed key pinned before saving. Nothing is saved on failure.
  - `400` validation error or missing/expired observation, `409` alias taken, `422 {error, reason: "target_auth_failed"}` credential rejected, `502 {error, reason}` network or host key problem.
- `PUT /api/v1/hosts/{id}` same body plus `revision`. `auth` omitted keeps the saved credential. `observationId` is required when address or port changes, and optional otherwise (re-pin after an intentional host key change). `409` when `revision` is stale. Same test-before-save behavior.
- `DELETE /api/v1/hosts/{id}` → `204`. Closes that host's terminals and transfers.

Alias rule: `^[a-z0-9][a-z0-9._-]{0,62}$`. Name is optional (defaults to alias).

### Devices and CLI approval

- `GET /api/v1/devices` → `200 [{id, label, servicePrincipal, authorizedAt, expiresAt, lastUsedAt|null, revokedAt|null, status: "active"|"expired"|"revoked", activeTerminals}]`.
- `POST /api/v1/devices/{id}/revoke` → `200 {closedTerminals}`. Idempotent.
- `POST /api/v1/pairings/lookup` `{userCode}` → `200 {userCode, label, requestedAt, expiresAt, servicePrincipal}` or `404`.
- `POST /api/v1/pairings/approve` `{userCode, password, code}` → `204`. Requires the owner password and a fresh TOTP code every time. `401`, `404`, `429` as above.
- `POST /api/v1/pairings/deny` `{userCode}` → `204`.

The approval page lives at `/approve`. The CLI prints that URL and an 8-character code like `K7QM-2XPA`. The owner types the code; the page never lists pending requests.

### Files (SFTP)

- `GET /api/v1/hosts/{id}/files?path=<abs path or empty for home>` → `200 {path, entries: [{name, type: "file"|"dir"|"symlink"|"other", size, mode, modTime, target?, validName}], truncated}`. `path` is the server-resolved absolute path; build breadcrumbs from it. `target` is the resolved type of a symlink. `validName: false` entries cannot be opened or downloaded. At most 5000 entries (`truncated: true` beyond).
- `GET /api/v1/hosts/{id}/download?path=<abs path>` → file bytes as an attachment. Use a plain link or `window.location` so the browser's download manager streams it; do not buffer into a Blob.
- Upload (no overwrite, ever):
  1. `POST /api/v1/hosts/{id}/uploads` `{directory, name, size}` → `201 {uploadId, chunkSize, path}`. `409` if the name exists.
  2. For each chunk in order: `PUT /api/v1/uploads/{uploadId}?offset=<n>` with the raw bytes as body (`Content-Type: application/octet-stream`) and header `X-Content-SHA256: <hex sha256 of this chunk>` → `200 {confirmed}`. `confirmed` is the server-confirmed byte count; show it as progress. A retry of the same chunk is safe. `409 {error, confirmed}` on an unexpected offset.
  3. `POST /api/v1/uploads/{uploadId}/commit` → `200 {path}`. `409` if the name appeared meanwhile; nothing is overwritten.
  - `DELETE /api/v1/uploads/{uploadId}` cancels and removes the temporary file.
  - `410` means the upload ended (cancelled, idle 2 min, revoked, expired).
- Error statuses: `400` invalid, `403` permission denied on the target, `404` missing, `409` conflict, `410` gone, `501 {error}` SFTP unavailable on the host (show "Files unavailable; terminals still work"), `502` target failure.

## CLI endpoints

All carry the Access service token headers. Except pairing, all carry the bearer device token.

- `POST /api/v1/cli/pair/start` `{label}` → `200 {pollToken, userCode, expiresAt, interval, approveUrl}`.
- `POST /api/v1/cli/pair/poll` `{pollToken}` → `200 {status: "pending"|"slow_down"|"denied"|"expired"}` or `200 {status: "approved", deviceId, deviceToken, expiresAt, label}`. The token is returned once.
- `GET /api/v1/cli/hosts` → `200 [{id, alias, name, endpoint, username}]`.
- `GET /api/v1/cli/device` → `200 {id, label, …}`.
- `POST /api/v1/cli/logout` → `204`. Revokes this device and ends its terminals.

## Terminal WebSocket

`GET /api/v1/terminal`, WebSocket subprotocol `yunmen.term.v1` (required). Browser: same-origin with the session cookie. CLI: `Authorization: Bearer`, Access headers, no `Origin`.

Frames:

- **Binary** frames are raw terminal bytes, both directions, at most 16 KiB each. Never decode them as lines; never convert newlines.
- **Text** frames are one JSON control object.

| Direction | Control | Meaning |
| --- | --- | --- |
| C→S | `{"type":"open","hostId","cols","rows","term"}` | Must be the first message, within 10 s. `cols`/`rows` 1..1000. |
| S→C | `{"type":"ready","sessionId","expiresAt"}` | Shell started. The server closes the terminal at `expiresAt`. |
| C→S | `{"type":"resize","cols","rows"}` | Any time after open. |
| C→S | `{"type":"ack","bytes"}` | Cumulative output bytes the client has rendered. Send after the bytes are consumed (xterm write callback, completed stdout write). |
| S→C | `{"type":"ack","bytes"}` | Cumulative input bytes written to the SSH channel. |
| C→S | `{"type":"close"}` | User disconnect. |
| S→C | `{"type":"end","reason","message","exitStatus"?,"signal"?}` | Final message; the socket closes after it. |

Flow control: the server keeps at most 256 KiB of unacknowledged output in flight and ends the terminal with `slow_consumer` after 60 s without ack progress while blocked. Clients should keep at most 64 KiB of unacknowledged input in flight. Do not send binary frames before `ready`.

End reasons: `remote_exit`, `client_close`, `target_auth_failed`, `host_key_unknown`, `host_key_changed`, `target_unreachable`, `network_lost`, `revoked`, `expired`, `slow_consumer`, `server_shutdown`, `host_removed`, `protocol_error`, `open_failed`.

A socket can also drop without `end`; treat that as `network_lost`. Reconnecting starts a new shell. Nothing is replayed. Use remote tmux (`tmux new -A -s main`) to keep work across disconnects.

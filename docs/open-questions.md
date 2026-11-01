# Open questions and unverified assumptions

## Needs a real Cloudflare deployment

The personal deployment uses a Cloudflare Tunnel without Access (owner decision, 2026-11-01). Items 1 and 2 below matter only for the optional Access mode. None of these ran against Cloudflare. Tests use a local fake issuer with the claim shapes below.

1. **Service-token claim shape.** Yunmen treats an assertion with a non-empty `common_name` and an empty `sub` as a service token whose Client ID is `common_name`. Confirm it against a real assertion: decode `Cf-Access-Jwt-Assertion` on a CLI request (`yunmen-server` logs nothing secret, so use a test origin).
2. **Assertion expiry versus terminal lifetime.** Terminals end at the assertion's `exp`. If Cloudflare issues short-lived assertions for service tokens or browser sessions, long sessions will drop at that time. Measure the real `exp` for both, then decide whether to keep this rule or to cap only by Yunmen expiry and re-check the assertion on reconnect.
3. **WebSocket through the Tunnel** without client-side cloudflared: verify that browser and CLI terminals connect through the tunnel hostname and that idle sessions survive with 25-second pings. Also test tunnel restart and client sleep/wake. In Access mode, also check that the CLI's `CF-Access-Client-Id`/`Secret` headers pass on the upgrade request.
4. **Upload sizes through Tunnel.** Chunks are 8 MiB, under the documented 100 MB request limit. Check the plan's file-traffic restrictions before relying on large transfers.

## Owner decisions (resolved)

- Windows CLI: released, but untested; the owner has no Windows machine.
- Key library: adopted.
- Recovery codes: adopted.
- Upload size: no limit.
- Session persistence: reconnect plus tmux (or a similar tool) on the target.

## Known limitations

- No device-to-target end-to-end encryption. The gateway and Cloudflare can see terminal traffic.
- Closing SSH does not guarantee that every remote descendant process ends.
- A local admin reset reaches open terminals through the 15-second sweep, so they can run for up to 15 seconds after the command.
- Host-key observations are tied to `address:port` and a 10-minute TTL, not to the host's revision. Saving still checks the revision.
- A directory listing reads the whole directory before applying the 5000-entry cap, because pkg/sftp has no streaming iterator.
- Deleting a host drops its pending-upload ledger. Any partial temporary file stays on the target.
- In standalone mode anyone who can reach the server can fill the 10 pending pairing slots for 5 minutes.
- The HTTP server has no overall read timeout, since long downloads and uploads need one. A stalled chunk body holds only its own upload.
- Downloads are not snapshots. A file that changes on the target while it is being read is streamed as it changes.
- Rate limiting is kept in memory, so a restart resets it.
- Windows, macOS and arm64 CLI builds have never been run.
- `go test -race` needs cgo. It was run in a Debian Go container, not on the development host.

# Accepted product requirements

These are owner-confirmed product decisions. They come from the implementation brief and the confirmed section of the original design (`ai_lab/projects/yunmen/specs/initial-design.md`). Implementation choices are in [decisions.md](decisions.md). Open questions are in [open-questions.md](open-questions.md).

## Product

- Yunmen ("cloud gate") is a lightweight, self-hosted SSH gateway for one owner across their own devices. It is a new product, not a Termix fork or an extension of another SSH tool.
- Server, Web, and CLI live in one repository. Web uses Vue. Go is preferred for the CLI.
- Distribution is CLI binaries plus a Server Docker image that contains the Web assets.
- Target-server credentials stay at the gateway. SSH private keys and standard SSH password authentication are supported.
- Interactive shells, tmux, and vim come first. Terminal compatibility is a core acceptance requirement. An earlier terminal-character problem was never diagnosed.
- Web provides host management, terminal tabs, minimal remote directory browsing, file upload, and file download.
- Web lists CLI devices (name, authorization time, expiry, last use) and revokes them one at a time. Revoking a device closes that device's active terminals and leaves other devices alone.

## Access and authentication

- Yunmen always requires its own owner password and TOTP.
- The personal deployment publishes Yunmen through a Cloudflare Tunnel that already runs on the host, outside Yunmen's Compose file. It does not use Cloudflare Access: password plus TOTP is the gate. (Owner decision, 2026-11-01. This replaces the earlier requirement of Cloudflare Access as an outer layer, which stays available as an optional mode.)
- CLI clients must not require cloudflared. A CLI device needs a Yunmen device token, issued after browser approval with owner login and TOTP; approval may happen on another device. When the optional Access mode is used, the device also needs an Access service token, and a service token alone never authorizes SSH access or owner settings.
- Lifetimes: CLI device token fixed at 30 days, Web session 12 hours.
- The master key comes from `YUNMEN_MASTER_KEY` or `YUNMEN_MASTER_KEY_FILE`, exactly one of them.
- The CLI stores its secrets in the OS credential store when available, with a disclosed owner-only file as the fallback. It never stores the owner password, TOTP material, or target credentials. The server stores only a hash of the device token.
- Logout revokes the device token online and removes local credentials. If the server is unreachable, the CLI says remote revocation has not completed and points to Web. Removing the local Cloudflare secret does not revoke it in Cloudflare.

## CLI shape

```
yunmen login <gateway-url>
yunmen hosts
yunmen connect <alias>
yunmen connect          # searchable host selector
yunmen logout
```

## First-release exclusions

Teams and roles, native SSH ingress, external SFTP/scp, port forwarding, batch commands, automation, recordings, shared terminals, plugins, dashboards, HA, remote editing, delete/rename/move, permission editing, folder uploads, archives, sync, cross-host copy.

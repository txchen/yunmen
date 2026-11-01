# Deployment

This sets up Yunmen on one machine that can reach your servers, published through a Cloudflare Tunnel that already runs on that host. Sign-in uses Yunmen's own password and TOTP. Nothing in this repository deploys anything for you.

Yunmen serves plain HTTP on `127.0.0.1:8080`; the tunnel provides HTTPS. Browsers need HTTPS for the secure session cookie and for upload checksums, so `YUNMEN_PUBLIC_ORIGIN` must be the `https://` address of your tunnel hostname. Plain `http` is accepted only for `localhost`.

## 1. Server

```sh
cd deploy
mkdir -p data secrets && chmod 700 data secrets
printf 'YUNMEN_UID=%s\nYUNMEN_GID=%s\n' "$(id -u)" "$(id -g)" > .env   # the container runs as you
docker run --rm ghcr.io/txchen/yunmen:latest genkey > secrets/master.key
chmod 600 secrets/master.key
cp yunmen.env.example yunmen.env            # set YUNMEN_PUBLIC_ORIGIN to your https:// address
docker compose up -d
docker compose run --rm -it yunmen init     # owner password + TOTP enrollment, local only
```

The container runs as your own user (from `.env`), so it can read the owner-only key file. The database lives in `deploy/data`.

`init` refuses to run twice. There is no web registration and no bootstrap route. Write down the 10 recovery codes it prints. With your password, any one of them lets you replace a lost authenticator from the sign-in page.

Instead of the key file you may set `YUNMEN_MASTER_KEY` in the environment. Configure exactly one of the two. The server refuses to start when the key is missing, malformed, set twice, or different from the key the database was created with.

The container has to reach your target hosts. If they are only on the host's LAN, check that the default Docker network routes there, or set `network_mode: host` and `YUNMEN_LISTEN=127.0.0.1:8080` instead of the port mapping.

## 2. Cloudflare Tunnel

In the Cloudflare dashboard, open your existing tunnel and add a public hostname, for example `yunmen.example.com`, with service `http://localhost:8080`. Tunnels pass WebSockets through by default, so terminals need no extra setting. If your cloudflared uses a local config file instead, add an ingress rule:

```yaml
ingress:
  - hostname: yunmen.example.com
    service: http://localhost:8080
  # ...your other rules, ending with the catch-all
  - service: http_status:404
```

Then restart cloudflared. Set `YUNMEN_PUBLIC_ORIGIN=https://yunmen.example.com` in `yunmen.env` to match.

The Compose file publishes Yunmen on `127.0.0.1:8080` only, so the tunnel is the only way in from outside. Uploads go in 8 MiB chunks, well under Cloudflare's per-request limit.

Without a tunnel, any HTTPS reverse proxy on the host works as well, as long as it passes WebSocket upgrades through and leaves the `Origin` header alone. With Caddy:

```caddy
yunmen.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

## 3. Use it

- Browser: open `https://yunmen.example.com` and sign in with your password and TOTP. Under Keys, generate a key on the gateway and add its public line to `~/.ssh/authorized_keys` on your servers, or import an existing key. To add a host, check its host key and compare the fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` run on the target. Then pick the key and save.
- CLI on each device:
  ```sh
  yunmen login https://yunmen.example.com   # press Enter at "Access Client ID"; it shows a code
  # approve in any signed-in browser at /approve (password + TOTP again)
  yunmen hosts
  yunmen connect home
  ```
  On the remote host, run `tmux new -A -s main` (or Kiwa, or a similar tool) so a dropped connection never loses work. Yunmen does not keep shells alive itself.

## Exposure without Cloudflare Access

Without Cloudflare Access in front, anyone who can reach the hostname can reach the sign-in page. Yunmen still requires the password and a TOTP code for everything, and it limits failed attempts. Known consequences:

- The failed-attempt limit is kept per client address. Through the tunnel every request comes from cloudflared's address, so the limit acts as one shared budget. Someone guessing passwords can keep you locked out of sign-in for minutes at a time, though not break in.
- Anyone can start CLI pairing requests, which expire after 5 minutes unapproved. At most 10 can be pending at once.

## Optional: Cloudflare Access in front

Yunmen can also require a Cloudflare Access assertion on every request, with CLI devices using an Access service token. Set `YUNMEN_MODE=access` and these variables (see [operations.md](operations.md)): `YUNMEN_ACCESS_TEAM_DOMAIN`, `YUNMEN_ACCESS_AUD`, `YUNMEN_ACCESS_OWNER_EMAILS`, `YUNMEN_ACCESS_SERVICE_CLIENT_IDS`. Add an Access application covering the whole tunnel hostname, with an Allow policy for you and a Service Auth policy for CLI service tokens. Publish Yunmen only through the tunnel, so that no route bypasses Access. Each CLI device then enters its service token's Client ID and Secret at `yunmen login`. This mode has not been tested against a real Cloudflare account.

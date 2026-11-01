# Personal deployment: Cloudflare Tunnel + Access

This sets up Yunmen on one machine that can reach your servers. No port is published. Browsers and the CLI reach it only through Cloudflare. Nothing in this repository deploys anything for you.

## 1. Cloudflare side

1. **Tunnel.** In Zero Trust, go to Networks, then Tunnels, and create a tunnel. Add a public hostname such as `yunmen.example.com` with service `http://yunmen:8080`, which is the Compose service name. Save the tunnel token.
2. **Access application.** Create a self-hosted application for `yunmen.example.com` that covers the whole hostname, with no path exceptions. Add two policies.
   - **Allow** your identity, for example an email include rule, so the browser can log in.
   - **Service Auth** with an include rule for the service token(s) you create below.
   Copy the application's audience (AUD) tag and note your team domain (`https://<team>.cloudflareaccess.com`).
3. **Service token per CLI device.** Go to Access, then Service credentials, and create a token. Keep the Client ID and Client Secret for `yunmen login`. Set its duration to whatever you want. Yunmen's device token expires separately, after 30 days.
4. Optionally add a Cache Rule that bypasses cache for `/api/*`.

There is no alternative route. Do not publish the container port or add other hostnames pointing at it.

## 2. Server

```sh
cd deploy
mkdir -p secrets && chmod 700 secrets
docker run --rm ghcr.io/txchen/yunmen:latest genkey > secrets/master.key
printf '%s' '<tunnel token>' > secrets/tunnel.token
chmod 600 secrets/*
cp yunmen.env.example yunmen.env   # fill in origin, team domain, AUD, owner email, service Client IDs
docker compose up -d
docker compose run --rm -it yunmen init     # owner password + TOTP enrollment, local only
```

`init` refuses to run twice. There is no web registration and no bootstrap route. Write down the 10 recovery codes it prints. With your password, any one of them lets you replace a lost authenticator from the sign-in page.

Instead of the key file you may set `YUNMEN_MASTER_KEY` in the environment. Configure exactly one of the two. The server refuses to start when the key is missing, malformed, set twice, or different from the key the database was created with.

The container has to reach your target hosts. If they are only on the host's LAN, give the `yunmen` service a network that routes there.

## 3. Use it

- Browser: open `https://yunmen.example.com`, pass Access, then sign in with your password and TOTP. Under Keys, generate a key on the gateway and add its public line to `~/.ssh/authorized_keys` on your servers, or import an existing key. To add a host, check its host key and compare the fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` run on the target. Then pick the key and save.
- CLI on each device:
  ```sh
  yunmen login https://yunmen.example.com   # prompts for the service token, shows a code
  # approve in any signed-in browser at /approve (password + TOTP again)
  yunmen hosts
  yunmen connect home
  ```
  On the remote host, run `tmux new -A -s main` (or a similar tool) so a dropped connection never loses work. Yunmen does not keep shells alive itself.

## Standalone mode (no Cloudflare)

Set `YUNMEN_MODE=standalone` and put Yunmen behind your own HTTPS reverse proxy with `YUNMEN_PUBLIC_ORIGIN` set to its URL. Password and TOTP still apply, and the CLI leaves the Access Client ID empty. Only use this when you have your own outer protection.

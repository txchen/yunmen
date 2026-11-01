#!/usr/bin/env bash
# End-to-end check of the real binaries in a real PTY (tmux), against a local
# OpenSSH sshd. Standalone mode on loopback only; never a production setup.
#
#   scripts/e2e-pty.sh            run and print PASS/FAIL per check
#
# Requires: go, tmux, sshd, sftp-server, vim, python3, curl.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d /tmp/yunmen-e2e.XXXXXX)
PORT_HTTP=$((20000 + RANDOM % 10000))
PORT_SSH=$((PORT_HTTP + 1))
ORIGIN="http://127.0.0.1:$PORT_HTTP"
SOCK="$WORK/tmux.sock"
T="tmux -S $SOCK"
PASSWORD="e2e owner password 123"
FAILED=0
PIDS=()

cleanup() {
  $T kill-server 2>/dev/null || true
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  [ "${KEEP:-}" = 1 ] || rm -rf "$WORK"
}
trap cleanup EXIT

check() { # name, condition-command...
  local name=$1; shift
  if "$@"; then echo "PASS  $name"; else echo "FAIL  $name"; FAILED=1; fi
}
screen() { $T capture-pane -p -t "$1" -S -200; }
wait_screen() { # pane, regex, [timeout]
  local deadline=$(( $(date +%s) + ${3:-15} ))
  while ! screen "$1" | grep -qE -- "$2"; do
    [ "$(date +%s)" -lt "$deadline" ] || { echo "--- timeout waiting for /$2/ in $1:"; screen "$1" | grep -v "^ *$" | tail -12; return 1; }
    sleep 0.2
  done
}
totp() { python3 - "$1" "$2" <<'EOF'
import base64, hmac, hashlib, struct, sys
secret = base64.b32decode(sys.argv[1] + "=" * (-len(sys.argv[1]) % 8))
h = hmac.new(secret, struct.pack(">Q", int(sys.argv[2])), hashlib.sha1).digest()
o = h[-1] & 15
print("%06d" % ((struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000))
EOF
}
# fresh_code sets CODE to a never-used TOTP code inside the server's +/-1
# step window, waiting for the next 30 s step when needed.
LAST_STEP=0
fresh_code() {
  local now=$(( $(date +%s) / 30 ))
  local step=$(( LAST_STEP + 1 > now ? LAST_STEP + 1 : now ))
  while [ "$step" -gt $(( $(date +%s) / 30 + 1 )) ]; do sleep 1; done
  LAST_STEP=$step
  CODE=$(totp "$SECRET" "$step")
}

echo "work dir: $WORK"
cd "$ROOT"
[ "${WEB:-}" = 1 ] && (cd web && npm run build >/dev/null)
go build -o "$WORK/yunmen-server" ./cmd/yunmen-server
go build -o "$WORK/yunmen" ./cmd/yunmen

# Target: OpenSSH with a predictable bash session.
mkdir -p "$WORK/ssh" "$WORK/home"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/ssh/hostkey"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/ssh/userkey"
cp "$WORK/ssh/userkey.pub" "$WORK/ssh/authorized_keys"
SFTP=/usr/libexec/openssh/sftp-server; [ -x "$SFTP" ] || SFTP=/usr/lib/openssh/sftp-server
cat > "$WORK/ssh/session.sh" <<EOF
#!/bin/sh
case "\$SSH_ORIGINAL_COMMAND" in
  "") cd $WORK/home; export INPUTRC=/dev/null LANG=C.UTF-8; exec bash --norc --noprofile -i ;;
  sftp|internal-sftp) exec $SFTP ;;
  *) exec /bin/sh -c "\$SSH_ORIGINAL_COMMAND" ;;
esac
EOF
chmod 700 "$WORK/ssh/session.sh"
cat > "$WORK/ssh/sshd_config" <<EOF
Port $PORT_SSH
ListenAddress 127.0.0.1
HostKey $WORK/ssh/hostkey
AuthorizedKeysFile $WORK/ssh/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
StrictModes no
PidFile $WORK/ssh/pid
LogLevel ERROR
Subsystem sftp $SFTP
ForceCommand $WORK/ssh/session.sh
EOF
$(command -v sshd || echo /usr/sbin/sshd) -f "$WORK/ssh/sshd_config" -D -e 2>"$WORK/sshd.log" & PIDS+=($!)

export YUNMEN_MASTER_KEY_FILE="$WORK/master.key" YUNMEN_DATA_DIR="$WORK/data"
"$WORK/yunmen-server" genkey > "$WORK/master.key"; chmod 600 "$WORK/master.key"

$T -f /dev/null new-session -d -s main -x 100 -y 30
$T set-option -g remain-on-exit on
$T set-option -g default-shell /bin/bash

# Owner init through the interactive prompts, reading the TOTP secret off the screen.
$T new-window -t main -n init "env YUNMEN_MASTER_KEY_FILE=$YUNMEN_MASTER_KEY_FILE YUNMEN_DATA_DIR=$YUNMEN_DATA_DIR $WORK/yunmen-server init"
wait_screen main:init "New owner password"
$T send-keys -t main:init "$PASSWORD" Enter; wait_screen main:init "Repeat"
$T send-keys -t main:init "$PASSWORD" Enter; wait_screen main:init "Enter the current 6-digit code"
SECRET=$(screen main:init | sed -n 's/.*enter this secret manually: \([A-Z2-7]*\).*/\1/p' | head -1)
$T send-keys -t main:init "$(totp "$SECRET" $(( $(date +%s) / 30 )))" Enter
check "owner init with TOTP enrollment" wait_screen main:init "Owner initialized"

start_server() {
  YUNMEN_MODE=standalone YUNMEN_LISTEN="127.0.0.1:$PORT_HTTP" YUNMEN_PUBLIC_ORIGIN="$ORIGIN" "$WORK/yunmen-server" serve 2>>"$WORK/server.log" & SERVER_PID=$!; PIDS+=($SERVER_PID)
  for _ in $(seq 50); do curl -sf "$ORIGIN/healthz" >/dev/null && break; sleep 0.1; done
}
start_server

api() { curl -s -b "$WORK/jar" -c "$WORK/jar" -H "Origin: $ORIGIN" -H 'Content-Type: application/json' "$@"; }
fresh_code
check "web login with password and TOTP" test "$(api -o /dev/null -w '%{http_code}' -X POST "$ORIGIN/api/v1/auth/login" -d "{\"password\":\"$PASSWORD\",\"code\":\"$CODE\"}")" = 200

PROBE=$(api -X POST "$ORIGIN/api/v1/hosts/probe" -d "{\"address\":\"127.0.0.1\",\"port\":$PORT_SSH}")
OBS=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["observationId"])' <<<"$PROBE")
FP=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["fingerprint"])' <<<"$PROBE")
check "probe fingerprint matches the target host key" test "$FP" = "$(ssh-keygen -lf "$WORK/ssh/hostkey.pub" | awk '{print $2}')"
KEY=$(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read()))' "$WORK/ssh/userkey")
CREATE=$(api -X POST "$ORIGIN/api/v1/hosts" -d "{\"alias\":\"box\",\"name\":\"E2E box\",\"address\":\"127.0.0.1\",\"port\":$PORT_SSH,\"username\":\"$(id -un)\",\"auth\":{\"kind\":\"key\",\"privateKey\":$KEY},\"observationId\":\"$OBS\"}")
grep -q "sftpAvailable.:true" <<<"$CREATE" || echo "create response: $CREATE"
check "host saved after authenticated test" grep -q "sftpAvailable.:true" <<<"$CREATE"

if [ "${WEB:-}" = 1 ]; then
  head -c 20000000 /dev/urandom > "$WORK/upload-big.bin"
  firefox --headless --no-remote --profile "$(mktemp -d "$WORK/ff.XXXX")" --remote-debugging-port 19333 >/dev/null 2>&1 & PIDS+=($!)
  for _ in $(seq 100); do curl -s -o /dev/null http://127.0.0.1:19333/ && break; sleep 0.2; done
  fresh_code
  mkdir -p "$WORK/shots"
  ORIGIN=$ORIGIN PASSWORD=$PASSWORD CODE=$CODE BIDI=ws://127.0.0.1:19333/session WORKHOME=$WORK/home UPLOAD=$WORK/upload-big.bin SHOTS=$WORK/shots \
    node "$ROOT/scripts/e2e-web.mjs" || FAILED=1
fi

# CLI login on a standalone gateway: no service token prompt; approve via the web API.
export YUNMEN_CONFIG_DIR="$WORK/cli" YUNMEN_NO_KEYRING=1
CLIENV="env YUNMEN_CONFIG_DIR=$YUNMEN_CONFIG_DIR YUNMEN_NO_KEYRING=1 TERM=xterm-256color"
$T new-window -t main -n login "$CLIENV $WORK/yunmen login $ORIGIN --label e2e-laptop"
wait_screen main:login "Code: "
check "login asks for no Access service token on a standalone gateway" bash -c "! $T capture-pane -p -t main:login | grep -q 'Access'"
CODE=$(screen main:login | sed -n 's/.*Code: *\([A-Z0-9-]*\).*/\1/p' | head -1)
USERCODE=$CODE; fresh_code
check "approval with password and TOTP" test "$(api -o /dev/null -w '%{http_code}' -X POST "$ORIGIN/api/v1/pairings/approve" -d "{\"userCode\":\"$USERCODE\",\"password\":\"$PASSWORD\",\"code\":\"$CODE\"}")" = 204
check "CLI receives device token" wait_screen main:login "Approved. Device token valid until"
check "CLI secrets file is owner-only" test "$(stat -c %a "$WORK/cli/secrets.json")" = 600

check "yunmen hosts lists the host" bash -c "$CLIENV $WORK/yunmen hosts | grep -q 'box.*E2E box'"

# Interactive session in a real PTY.
$T new-window -t main -n conn "$CLIENV $WORK/yunmen connect box; echo EXIT=\$?; stty -a | grep -o -- '-\?icanon' ; sleep 600"
P=main:conn
wait_screen $P 'bash-[0-9.]+\$'
$T send-keys -t $P "printf 'u:%s:\\n' '中文 😀 é ┌─┐'" Enter
check "unicode round trip" wait_screen $P "u:中文 😀 é ┌─┐:"
$T send-keys -t $P "stty size" Enter
check "initial size forwarded" wait_screen $P "^$($T display -p -t $P "#{pane_height} #{pane_width}")$"
$T resize-window -t $P -x 120 -y 40; sleep 0.5
$T send-keys -t $P "stty size" Enter
check "resize forwarded" wait_screen $P "^$($T display -p -t $P "#{pane_height} #{pane_width}")$"
$T send-keys -t $P "sleep 30; echo SLEPT" Enter; sleep 0.5
$T send-keys -t $P C-c; sleep 0.5
$T send-keys -t $P 'echo after-$((40+2))' Enter
check "Ctrl-C reaches the remote program" wait_screen $P "^after-42"

$T send-keys -t $P "vim -u NONE -N vim.txt" Enter; sleep 1
$T send-keys -t $P "i" "hello 中文 vim" Escape; sleep 0.3
$T send-keys -t $P ":wq" Enter; sleep 0.5
$T send-keys -t $P "cat vim.txt" Enter
check "vim edits and writes a file" wait_screen $P "^hello 中文 vim"

$T send-keys -t $P "tmux -S $WORK/inner.sock -f /dev/null new -s work bash --norc --noprofile" Enter; sleep 1
$T send-keys -t $P 'echo tmux-$((6*7))-${TMUX:+inside}' Enter
check "tmux runs inside the session" wait_screen $P "^tmux-42-inside"
$T send-keys -t $P C-b d
check "tmux detach" wait_screen $P "detached"
$T send-keys -t $P "exit 5" Enter
check "remote exit status propagated" wait_screen $P "^EXIT=5"
check "terminal restored after exit" wait_screen $P "^icanon"

# Reconnect and reattach tmux; local escape ~. disconnects.
$T respawn-window -k -t $P "$CLIENV $WORK/yunmen connect box; echo EXIT=\$?; stty -a | grep -o -- '-\?icanon'; sleep 600"
wait_screen $P 'bash-[0-9.]+\$'
$T send-keys -t $P "tmux -S $WORK/inner.sock attach -t work" Enter
check "tmux reattach after reconnect shows earlier output" wait_screen $P "^tmux-42"
$T send-keys -t $P C-b d; sleep 0.5
$T send-keys -t $P Enter "~."
check "~. disconnects locally" wait_screen $P "Disconnected from box"
check "terminal restored after ~." wait_screen $P "^icanon"

# Gateway loss mid-session: explicit reason, terminal restored, then a restart
# from the same database keeps the device and host.
$T respawn-window -k -t $P "$CLIENV $WORK/yunmen connect box; echo EXIT=\$?; stty -a | grep -o -- '-\?icanon'; sleep 600"
wait_screen $P 'bash-[0-9.]+\$'
kill "$SERVER_PID"
check "gateway loss reported" wait_screen $P "connection to the gateway lost|gateway shutting down"
check "terminal restored after gateway loss" wait_screen $P "^icanon"
check "reconnect guidance printed" wait_screen $P "Nothing was replayed"
start_server

# Device revocation from the web closes the live terminal.
$T respawn-window -k -t $P "$CLIENV $WORK/yunmen connect box; echo EXIT=\$?; stty -a | grep -o -- '-\?icanon'; sleep 600"
wait_screen $P 'bash-[0-9.]+\$'
DEV=$(api "$ORIGIN/api/v1/devices" | python3 -c 'import json,sys; print([d["id"] for d in json.load(sys.stdin) if d["status"]=="active"][0])')
api -X POST "$ORIGIN/api/v1/devices/$DEV/revoke" -d '{}' >/dev/null
check "revocation ends the CLI terminal with a reason" wait_screen $P "access revoked"
check "terminal restored after revocation" wait_screen $P "^icanon"
check "revoked device cannot list hosts" bash -c "! $CLIENV $WORK/yunmen hosts 2>/dev/null"

# Logout with the server unreachable reports pending revocation.
kill "$SERVER_PID"; sleep 0.3
OUT=$($CLIENV "$WORK/yunmen" logout 2>&1 || true)
check "offline logout reports remote revocation not completed" grep -q "NOT completed" <<<"$OUT"
check "offline logout removed local credentials" test ! -e "$WORK/cli/secrets.json"

check "no secrets in server log" bash -c "! grep -qE '$PASSWORD|ymd_|yms_|PRIVATE KEY' '$WORK/server.log'"

[ "$FAILED" = 0 ] && echo "ALL CHECKS PASSED" || { echo "SOME CHECKS FAILED (KEEP=1 keeps $WORK)"; exit 1; }

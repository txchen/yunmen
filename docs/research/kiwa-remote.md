# Kiwa remote transport findings

## Sources

Inspected upstream Kiwa commit `8e04bf0931a1d84de6b8ed8b1fae3cf45b84ad3f`, rather than relying on the older local checkout.

- [Remote launcher](https://github.com/txchen/kiwa/blob/8e04bf0931a1d84de6b8ed8b1fae3cf45b84ad3f/src/client.zig#L318-L355): invokes system OpenSSH with `-t -C`. Probes support for `ObscureKeystrokeTiming=no` using `ssh -G`, then uses that option when supported. This avoids OpenSSH's keystroke timing interval at the cost of timing privacy; it is not a custom compression protocol.
- [Rendering and scheduling](https://github.com/txchen/kiwa/blob/8e04bf0931a1d84de6b8ed8b1fae3cf45b84ad3f/src/server.zig#L32-L65): batches pane output with a 16 ms render interval. Its comment reports that an 8 ms interval doubled bytes and queued output on slow SSH links. This is a Kiwa observation, not a Yunmen benchmark.
- [Go SSH compression algorithms](https://github.com/golang/crypto/blob/v0.58.0/ssh/common.go): `supportedCompressions` contains only `none` in Yunmen's current dependency.
- [Yunmen SSH connector](../../internal/sshconn/sshconn.go): uses in-process Go SSH, pinned host keys, explicit stored credentials, and TCP keepalive at 30 seconds. It does not invoke OpenSSH or consult ambient SSH configuration.
- [Yunmen architecture](../decisions.md): terminal data is an opaque byte stream; the gateway does not interpret the terminal screen. Files use separate SSH/SFTP connections.

## Applicability

1. Kiwa's `-C` is relevant to the gateway-to-target bottleneck, but cannot be copied into the current Go SSH configuration. Supporting SSH compression requires a different backend or a maintained implementation of SSH compression.
2. `ObscureKeystrokeTiming=no` is an OpenSSH client option, not an SSH server setting. It is not a missing toggle in Yunmen's Go client.
3. Kiwa's rendering interval controls reconstructed terminal frames. Yunmen must preserve every byte; it cannot discard output or adopt screen-diff behavior without changing its architecture. Bounded byte coalescing is a separate optimization and needs latency measurements.
4. An OpenSSH backend could provide standard compression without a target agent, but would reopen the explicit in-process SSH/no-system-SSH decision. It must preserve pinned-key verification, explicit credential selection, password authentication, resize and exit status, cancellation, and revocation. Ambient SSH configuration and agents must not silently change authentication or trust policy.
5. A Go SSH fork could retain the existing API but introduces security-sensitive maintenance: delayed compression activation, streaming state, packet limits after decompression, and rekey behavior all need review and interoperability tests. Merely adding an algorithm name is insufficient.

## Recommendation

Do not add a nonfunctional compression toggle or replace the SSH backend as a small transport tweak. Decide explicitly between a controlled OpenSSH backend and a maintained compression-capable Go implementation. Keep the current backend until that choice is made. No throughput or latency benchmark was performed in this investigation.

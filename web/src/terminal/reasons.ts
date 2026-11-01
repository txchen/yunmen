import type { EndReason } from './session'

export type Severity = 'info' | 'warn' | 'danger'

export const END_REASONS: Record<EndReason, { text: string; severity: Severity }> = {
  remote_exit: { text: 'The remote shell exited.', severity: 'info' },
  client_close: { text: 'Disconnected.', severity: 'info' },
  target_auth_failed: { text: 'The host rejected the saved credentials.', severity: 'warn' },
  host_key_unknown: { text: 'No host key is pinned for this host. Edit the host and verify its key.', severity: 'warn' },
  host_key_changed: {
    text:
      'HOST KEY CHANGED. The host presented a different key than the pinned one. This can mean a man-in-the-middle ' +
      'attack. Do not reconnect until you have checked the new fingerprint on the host itself, then re-verify it in the host editor.',
    severity: 'danger',
  },
  target_unreachable: { text: 'The host could not be reached.', severity: 'warn' },
  network_lost: { text: 'The connection was lost.', severity: 'warn' },
  revoked: { text: 'Access was revoked.', severity: 'warn' },
  expired: { text: 'The terminal reached its time limit.', severity: 'info' },
  slow_consumer: { text: 'Closed because this browser stopped consuming output.', severity: 'warn' },
  server_shutdown: { text: 'The Yunmen server is shutting down.', severity: 'warn' },
  host_removed: { text: 'The host was deleted.', severity: 'info' },
  protocol_error: { text: 'Protocol error between the browser and the server.', severity: 'warn' },
  open_failed: { text: 'The shell could not be started.', severity: 'warn' },
}

export function describeEnd(reason: string): { text: string; severity: Severity } {
  return END_REASONS[reason as EndReason] ?? { text: `Session ended (${reason}).`, severity: 'warn' }
}

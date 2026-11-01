export const PROTOCOL = 'yunmen.term.v1'
export const MAX_FRAME = 16 * 1024
export const INPUT_WINDOW = 64 * 1024
export const INPUT_QUEUE_LIMIT = 4 * 1024 * 1024
export const ACK_THRESHOLD = 32 * 1024
export const ACK_DELAY_MS = 20

export type EndReason =
  | 'remote_exit'
  | 'client_close'
  | 'target_auth_failed'
  | 'host_key_unknown'
  | 'host_key_changed'
  | 'target_unreachable'
  | 'network_lost'
  | 'revoked'
  | 'expired'
  | 'slow_consumer'
  | 'server_shutdown'
  | 'host_removed'
  | 'protocol_error'
  | 'open_failed'

export interface EndInfo {
  reason: EndReason | string
  message: string
  exitStatus?: number
  signal?: string
}

export type SessionState =
  | { kind: 'connecting' }
  | { kind: 'ready'; sessionId: string; expiresAt: string }
  | ({ kind: 'ended' } & EndInfo)

export interface SocketLike {
  binaryType: string
  readyState: number
  onopen: ((ev: unknown) => void) | null
  onmessage: ((ev: { data: unknown }) => void) | null
  onclose: ((ev: unknown) => void) | null
  onerror: ((ev: unknown) => void) | null
  send(data: string | ArrayBufferLike | ArrayBufferView): void
  close(): void
}

export interface SessionOptions {
  url: string
  hostId: string
  cols: number
  rows: number
  // Must call `done` once the bytes are rendered; acks are counted from it.
  write: (data: Uint8Array, done: () => void) => void
  onState: (state: SessionState) => void
  createSocket?: (url: string, protocol: string) => SocketLike
}

const OPEN = 1

export function terminalUrl(loc: { protocol: string; host: string }): string {
  return `${loc.protocol === 'https:' ? 'wss' : 'ws'}://${loc.host}/api/v1/terminal`
}

type Control =
  | { type: 'ready'; sessionId: string; expiresAt: string }
  | { type: 'ack'; bytes: number }
  | ({ type: 'end' } & EndInfo)

function parseControl(text: string): Control | null {
  let v: unknown
  try {
    v = JSON.parse(text)
  } catch {
    return null
  }
  if (!v || typeof v !== 'object') return null
  const o = v as Record<string, unknown>
  switch (o.type) {
    case 'ready':
      return { type: 'ready', sessionId: String(o.sessionId ?? ''), expiresAt: String(o.expiresAt ?? '') }
    case 'ack':
      return typeof o.bytes === 'number' ? { type: 'ack', bytes: o.bytes } : null
    case 'end':
      return {
        type: 'end',
        reason: String(o.reason ?? 'protocol_error'),
        message: typeof o.message === 'string' ? o.message : '',
        exitStatus: typeof o.exitStatus === 'number' ? o.exitStatus : undefined,
        signal: typeof o.signal === 'string' && o.signal ? o.signal : undefined,
      }
    default:
      return null
  }
}

export class TerminalSession {
  state: SessionState = { kind: 'connecting' }

  private readonly opts: SessionOptions
  private socket: SocketLike | null = null
  private cols: number
  private rows: number
  private opened = false

  private rendered = 0
  private ackedOutput = 0
  private ackTimer: ReturnType<typeof setTimeout> | null = null

  private inputSent = 0
  private inputAcked = 0
  private queue: Uint8Array[] = []
  private queuedBytes = 0

  constructor(opts: SessionOptions) {
    this.opts = opts
    this.cols = opts.cols
    this.rows = opts.rows
  }

  start() {
    const create = this.opts.createSocket ?? ((url, protocol) => new WebSocket(url, protocol) as unknown as SocketLike)
    const ws = create(this.opts.url, PROTOCOL)
    ws.binaryType = 'arraybuffer'
    this.socket = ws
    ws.onopen = () => {
      this.opened = true
      this.sendControl({ type: 'open', hostId: this.opts.hostId, cols: this.cols, rows: this.rows, term: 'xterm-256color' })
    }
    ws.onmessage = (ev) => this.handleMessage(ev.data)
    ws.onclose = () => this.finish({ reason: 'network_lost', message: '' })
    ws.onerror = () => {}
  }

  // Returns false when the bounded queue cannot take the whole input; nothing is queued then.
  sendInput(data: Uint8Array): boolean {
    if (this.state.kind === 'ended' || data.length === 0) return this.state.kind !== 'ended'
    if (this.queuedBytes + data.length > INPUT_QUEUE_LIMIT) return false
    for (let i = 0; i < data.length; i += MAX_FRAME) {
      this.queue.push(data.subarray(i, i + MAX_FRAME))
    }
    this.queuedBytes += data.length
    this.pump()
    return true
  }

  resize(cols: number, rows: number) {
    if (cols === this.cols && rows === this.rows) return
    this.cols = cols
    this.rows = rows
    if (this.opened && this.state.kind !== 'ended') this.sendControl({ type: 'resize', cols, rows })
  }

  close() {
    if (this.state.kind === 'ended') return
    if (this.opened) this.sendControl({ type: 'close' })
    this.finish({ reason: 'client_close', message: '' })
  }

  private handleMessage(data: unknown) {
    if (this.state.kind === 'ended') return
    if (data instanceof ArrayBuffer) {
      const bytes = new Uint8Array(data)
      this.opts.write(bytes, () => this.onRendered(bytes.length))
      return
    }
    if (typeof data !== 'string') return
    const msg = parseControl(data)
    if (!msg) return
    if (msg.type === 'ready') {
      this.setState({ kind: 'ready', sessionId: msg.sessionId, expiresAt: msg.expiresAt })
      this.pump()
    } else if (msg.type === 'ack') {
      this.inputAcked = Math.max(this.inputAcked, msg.bytes)
      this.pump()
    } else {
      this.finish({ reason: msg.reason, message: msg.message, exitStatus: msg.exitStatus, signal: msg.signal })
    }
  }

  private onRendered(n: number) {
    if (this.state.kind === 'ended') return
    this.rendered += n
    if (this.rendered - this.ackedOutput >= ACK_THRESHOLD) {
      this.flushAck()
    } else if (!this.ackTimer) {
      this.ackTimer = setTimeout(() => this.flushAck(), ACK_DELAY_MS)
    }
  }

  private flushAck() {
    if (this.ackTimer) clearTimeout(this.ackTimer)
    this.ackTimer = null
    if (this.state.kind === 'ended' || this.rendered === this.ackedOutput) return
    this.ackedOutput = this.rendered
    this.sendControl({ type: 'ack', bytes: this.rendered })
  }

  private pump() {
    if (this.state.kind !== 'ready' || !this.socket) return
    while (this.queue.length > 0) {
      const chunk = this.queue[0]
      if (this.inputSent - this.inputAcked + chunk.length > INPUT_WINDOW) break
      this.queue.shift()
      this.queuedBytes -= chunk.length
      this.inputSent += chunk.length
      this.socket.send(chunk)
    }
  }

  private sendControl(msg: Record<string, unknown>) {
    if (this.socket && this.socket.readyState === OPEN) this.socket.send(JSON.stringify(msg))
  }

  private finish(info: EndInfo) {
    if (this.state.kind === 'ended') return
    if (this.ackTimer) clearTimeout(this.ackTimer)
    this.ackTimer = null
    this.queue = []
    this.queuedBytes = 0
    const ws = this.socket
    if (ws) {
      ws.onopen = ws.onmessage = ws.onclose = ws.onerror = null
      ws.close()
    }
    this.setState({ kind: 'ended', ...info })
  }

  private setState(s: SessionState) {
    this.state = s
    this.opts.onState(s)
  }
}

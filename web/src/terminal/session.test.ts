import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { TerminalSession, type SessionState, type SocketLike } from './session'

class FakeSocket implements SocketLike {
  binaryType = 'blob'
  readyState = 0
  onopen: ((ev: unknown) => void) | null = null
  onmessage: ((ev: { data: unknown }) => void) | null = null
  onclose: ((ev: unknown) => void) | null = null
  onerror: ((ev: unknown) => void) | null = null
  sent: (string | Uint8Array)[] = []
  closed = false

  constructor(
    readonly url: string,
    readonly protocol: string,
  ) {}

  send(data: string | ArrayBufferLike | ArrayBufferView) {
    this.sent.push(typeof data === 'string' ? data : new Uint8Array(data as ArrayBuffer))
  }
  close() {
    this.closed = true
    this.readyState = 3
  }

  serverOpen() {
    this.readyState = 1
    this.onopen?.({})
  }
  serverText(obj: unknown) {
    this.onmessage?.({ data: JSON.stringify(obj) })
  }
  serverBinary(n: number) {
    this.onmessage?.({ data: new ArrayBuffer(n) })
  }
  serverDrop() {
    this.readyState = 3
    this.onclose?.({})
  }
  controls() {
    return this.sent.filter((m): m is string => typeof m === 'string').map((m) => JSON.parse(m))
  }
  binaries() {
    return this.sent.filter((m): m is Uint8Array => typeof m !== 'string')
  }
}

function setup(opts: { manualRender?: boolean } = {}) {
  let socket!: FakeSocket
  const states: SessionState[] = []
  const pendingRenders: (() => void)[] = []
  const session = new TerminalSession({
    url: 'ws://example.test/api/v1/terminal',
    hostId: 'h1',
    cols: 80,
    rows: 24,
    write: (_data, done) => (opts.manualRender ? pendingRenders.push(done) : done()),
    onState: (s) => states.push(s),
    createSocket: (url, protocol) => (socket = new FakeSocket(url, protocol)),
  })
  session.start()
  return { session, socket, states, pendingRenders }
}

function ready(socket: FakeSocket) {
  socket.serverOpen()
  socket.serverText({ type: 'ready', sessionId: 's1', expiresAt: '2030-01-01T00:00:00Z' })
}

beforeEach(() => vi.useFakeTimers())
afterEach(() => vi.useRealTimers())

describe('TerminalSession', () => {
  it('opens with the subprotocol and sends open as the first message', () => {
    const { socket } = setup()
    expect(socket.protocol).toBe('yunmen.term.v1')
    expect(socket.binaryType).toBe('arraybuffer')
    socket.serverOpen()
    expect(socket.controls()).toEqual([{ type: 'open', hostId: 'h1', cols: 80, rows: 24, term: 'xterm-256color' }])
  })

  it('holds input until ready, then flushes it', () => {
    const { session, socket, states } = setup()
    socket.serverOpen()
    session.sendInput(new Uint8Array([104, 105]))
    expect(socket.binaries()).toHaveLength(0)
    socket.serverText({ type: 'ready', sessionId: 's1', expiresAt: 'x' })
    expect(states.at(-1)).toEqual({ kind: 'ready', sessionId: 's1', expiresAt: 'x' })
    expect(socket.binaries().map((b) => Array.from(b))).toEqual([[104, 105]])
  })

  it('splits input into frames of at most 16 KiB', () => {
    const { session, socket } = setup()
    ready(socket)
    session.sendInput(new Uint8Array(40 * 1024))
    expect(socket.binaries().map((b) => b.length)).toEqual([16384, 16384, 8192])
  })

  it('pauses input beyond 64 KiB in flight and resumes on server ack', () => {
    const { session, socket } = setup()
    ready(socket)
    expect(session.sendInput(new Uint8Array(100 * 1024))).toBe(true)
    const sentBytes = () => socket.binaries().reduce((n, b) => n + b.length, 0)
    expect(sentBytes()).toBe(64 * 1024)
    socket.serverText({ type: 'ack', bytes: 32 * 1024 })
    expect(sentBytes()).toBe(96 * 1024)
    socket.serverText({ type: 'ack', bytes: 96 * 1024 })
    expect(sentBytes()).toBe(100 * 1024)
  })

  it('refuses input that would overflow the 4 MiB queue without dropping earlier input', () => {
    const { session, socket } = setup()
    ready(socket)
    expect(session.sendInput(new Uint8Array(3 * 1024 * 1024))).toBe(true)
    expect(session.sendInput(new Uint8Array(2 * 1024 * 1024))).toBe(false)
    const sentBytes = () => socket.binaries().reduce((n, b) => n + b.length, 0)
    for (let i = 0; i < 100 && sentBytes() < 3 * 1024 * 1024; i++) {
      socket.serverText({ type: 'ack', bytes: sentBytes() })
    }
    expect(sentBytes()).toBe(3 * 1024 * 1024)
  })

  it('acks cumulative rendered output: immediately at 32 KiB, otherwise after a short delay', () => {
    const { socket, pendingRenders } = setup({ manualRender: true })
    ready(socket)
    socket.serverBinary(20 * 1024)
    socket.serverBinary(20 * 1024)
    expect(socket.controls().filter((c) => c.type === 'ack')).toEqual([])
    pendingRenders.shift()!()
    pendingRenders.shift()!()
    expect(socket.controls().filter((c) => c.type === 'ack')).toEqual([{ type: 'ack', bytes: 40 * 1024 }])
    socket.serverBinary(100)
    pendingRenders.shift()!()
    expect(socket.controls().filter((c) => c.type === 'ack')).toHaveLength(1)
    vi.advanceTimersByTime(50)
    expect(socket.controls().filter((c) => c.type === 'ack').at(-1)).toEqual({ type: 'ack', bytes: 40 * 1024 + 100 })
  })

  it('sends resize only after open and only when the size changes', () => {
    const { session, socket } = setup()
    session.resize(100, 30)
    socket.serverOpen()
    expect(socket.controls()[0]).toMatchObject({ type: 'open', cols: 100, rows: 30 })
    session.resize(100, 30)
    session.resize(120, 40)
    expect(socket.controls().slice(1)).toEqual([{ type: 'resize', cols: 120, rows: 40 }])
  })

  it('reports the end control with its reason and exit status', () => {
    const { socket, states } = setup()
    ready(socket)
    socket.serverText({ type: 'end', reason: 'remote_exit', message: 'bye', exitStatus: 3 })
    socket.serverDrop()
    expect(states.at(-1)).toEqual({ kind: 'ended', reason: 'remote_exit', message: 'bye', exitStatus: 3, signal: undefined })
    expect(states.filter((s) => s.kind === 'ended')).toHaveLength(1)
  })

  it('treats a socket drop without end as network_lost', () => {
    const { socket, states } = setup()
    ready(socket)
    socket.serverDrop()
    expect(states.at(-1)).toMatchObject({ kind: 'ended', reason: 'network_lost' })
  })

  it('close sends the close control and closes the socket', () => {
    const { session, socket } = setup()
    ready(socket)
    session.close()
    expect(socket.controls().at(-1)).toEqual({ type: 'close' })
    expect(socket.closed).toBe(true)
  })
})

export type AuthKind = 'key' | 'password'

export interface Session {
  expiresAt: string
  mode: string
}

export interface Host {
  id: string
  alias: string
  name: string
  address: string
  port: number
  username: string
  authKind: AuthKind
  keyFingerprint?: string
  hostKeyType: string
  hostKeyFingerprint: string
  revision: number
  createdAt: string
  updatedAt: string
}

export interface ProbeResult {
  observationId: string
  endpoint: string
  keyType: string
  fingerprint: string
  expiresAt: string
}

export type HostAuth =
  | { kind: 'key'; privateKey: string; passphrase?: string }
  | { kind: 'password'; password: string }

export interface HostInput {
  alias: string
  name: string
  address: string
  port: number
  username: string
  auth?: HostAuth
  observationId?: string
  revision?: number
}

export interface SaveHostResult {
  host: Host
  sftpAvailable: boolean
}

export interface Device {
  id: string
  label: string
  servicePrincipal: string
  authorizedAt: string
  expiresAt: string
  lastUsedAt: string | null
  revokedAt: string | null
  status: 'active' | 'expired' | 'revoked'
  activeTerminals: number
}

export interface Pairing {
  userCode: string
  label: string
  requestedAt: string
  expiresAt: string
  servicePrincipal: string
}

export type EntryType = 'file' | 'dir' | 'symlink' | 'other'

export interface FileEntry {
  name: string
  type: EntryType
  size: number
  mode: string
  modTime: string
  target?: EntryType
  validName: boolean
}

export interface Listing {
  path: string
  entries: FileEntry[]
  truncated: boolean
}

export interface UploadBegin {
  uploadId: string
  chunkSize: number
  path: string
}

export class ApiError extends Error {
  readonly status: number
  readonly body: Record<string, unknown>

  constructor(status: number, body: Record<string, unknown>) {
    const message = typeof body.error === 'string' && body.error ? body.error : `Request failed (HTTP ${status})`
    super(message)
    this.status = status
    this.body = body
  }

  get reason(): string | undefined {
    return typeof this.body.reason === 'string' ? this.body.reason : undefined
  }
}

let unauthorizedHandler: () => void = () => {}

export function onUnauthorized(handler: () => void) {
  unauthorizedHandler = handler
}

interface RequestOptions {
  json?: unknown
  body?: BodyInit
  headers?: Record<string, string>
  signal?: AbortSignal
  // 401 on login and approval means a wrong password or code, not a lost session.
  redirectOn401?: boolean
}

export async function request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json', ...opts.headers }
  let body = opts.body
  if (opts.json !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.json)
  }
  const res = await fetch(path, { method, headers, body, signal: opts.signal, credentials: 'same-origin' })
  if (!res.ok) {
    let parsed: Record<string, unknown> = {}
    try {
      const value: unknown = await res.json()
      if (value && typeof value === 'object') parsed = value as Record<string, unknown>
    } catch {
      // Non-JSON error bodies fall back to a generic message.
    }
    if (res.status === 401 && opts.redirectOn401 !== false) unauthorizedHandler()
    throw new ApiError(res.status, parsed)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

const enc = encodeURIComponent

export const api = {
  session: () => request<Session>('GET', '/api/v1/auth/session', { redirectOn401: false }),
  login: (password: string, code: string) =>
    request<{ expiresAt: string }>('POST', '/api/v1/auth/login', { json: { password, code }, redirectOn401: false }),
  logout: () => request<void>('POST', '/api/v1/auth/logout', { redirectOn401: false }),

  hosts: () => request<Host[]>('GET', '/api/v1/hosts'),
  probe: (address: string, port: number) => request<ProbeResult>('POST', '/api/v1/hosts/probe', { json: { address, port } }),
  createHost: (input: HostInput) => request<SaveHostResult>('POST', '/api/v1/hosts', { json: input }),
  updateHost: (id: string, input: HostInput) => request<SaveHostResult>('PUT', `/api/v1/hosts/${enc(id)}`, { json: input }),
  deleteHost: (id: string) => request<void>('DELETE', `/api/v1/hosts/${enc(id)}`),

  devices: () => request<Device[]>('GET', '/api/v1/devices'),
  revokeDevice: (id: string) => request<{ closedTerminals: number }>('POST', `/api/v1/devices/${enc(id)}/revoke`),
  lookupPairing: (userCode: string) => request<Pairing>('POST', '/api/v1/pairings/lookup', { json: { userCode } }),
  approvePairing: (userCode: string, password: string, code: string) =>
    request<void>('POST', '/api/v1/pairings/approve', { json: { userCode, password, code }, redirectOn401: false }),
  denyPairing: (userCode: string) => request<void>('POST', '/api/v1/pairings/deny', { json: { userCode } }),

  listFiles: (hostId: string, path: string) => request<Listing>('GET', `/api/v1/hosts/${enc(hostId)}/files?path=${enc(path)}`),
  downloadUrl: (hostId: string, path: string) => `/api/v1/hosts/${enc(hostId)}/download?path=${enc(path)}`,
  beginUpload: (hostId: string, directory: string, name: string, size: number, signal?: AbortSignal) =>
    request<UploadBegin>('POST', `/api/v1/hosts/${enc(hostId)}/uploads`, { json: { directory, name, size }, signal }),
  putChunk: (uploadId: string, offset: number, chunk: ArrayBuffer, sha256: string, signal?: AbortSignal) =>
    request<{ confirmed: number }>('PUT', `/api/v1/uploads/${enc(uploadId)}?offset=${offset}`, {
      body: chunk,
      headers: { 'Content-Type': 'application/octet-stream', 'X-Content-SHA256': sha256 },
      signal,
    }),
  commitUpload: (uploadId: string, signal?: AbortSignal) =>
    request<{ path: string }>('POST', `/api/v1/uploads/${enc(uploadId)}/commit`, { signal }),
  cancelUpload: (uploadId: string) => request<void>('DELETE', `/api/v1/uploads/${enc(uploadId)}`),
}

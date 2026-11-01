import { api, ApiError } from '../api'

export const NAME_EXISTS = 'A file with that name already exists; nothing was overwritten'

export interface UploadCallbacks {
  onProgress: (confirmed: number) => void
  signal: AbortSignal
}

function hex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('')
}

function conflictAsExists(err: unknown): never {
  if (err instanceof ApiError && err.status === 409) throw new Error(NAME_EXISTS)
  throw err
}

// Reads one chunk at a time so large files never sit in memory. Any failure
// after begin, including an abort, deletes the server-side temporary file.
export async function uploadFile(hostId: string, directory: string, file: File, cb: UploadCallbacks): Promise<string> {
  const begin = await api.beginUpload(hostId, directory, file.name, file.size, cb.signal).catch(conflictAsExists)
  try {
    let offset = 0
    let stalls = 0
    while (offset < file.size) {
      const chunk = await file.slice(offset, offset + begin.chunkSize).arrayBuffer()
      const digest = hex(await crypto.subtle.digest('SHA-256', chunk))
      cb.signal.throwIfAborted()
      try {
        const { confirmed } = await api.putChunk(begin.uploadId, offset, chunk, digest, cb.signal)
        offset = confirmed
        stalls = 0
      } catch (err) {
        if (cb.signal.aborted || ++stalls > 3) throw err
        if (err instanceof ApiError && err.status === 409 && typeof err.body.confirmed === 'number') {
          offset = err.body.confirmed
        } else if (!(err instanceof ApiError) || err.status === 400 || err.status >= 500) {
          // Network drop, interrupted body or digest mismatch: the server rolled
          // the chunk back, so resend the same offset after a short pause.
          await new Promise((r) => setTimeout(r, 500 * stalls))
        } else {
          throw err
        }
      }
      cb.onProgress(offset)
    }
    const { path } = await api.commitUpload(begin.uploadId, cb.signal).catch(conflictAsExists)
    return path
  } catch (err) {
    await api.cancelUpload(begin.uploadId).catch(() => {})
    throw err
  }
}

import { afterEach, describe, expect, it, vi } from 'vitest'
import { NAME_EXISTS, uploadFile } from './upload'

const SHA_ABCD = '88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589'
const SHA_AB = 'fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603'

interface Call {
  method: string
  url: string
  sha?: string
  body?: string
}

type Responder = (call: Call, init: RequestInit) => Response | Promise<Response>

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function fakeFetch(respond: Responder) {
  const calls: Call[] = []
  vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
    const headers = (init.headers ?? {}) as Record<string, string>
    const call: Call = { method: init.method ?? 'GET', url, sha: headers['X-Content-SHA256'] }
    if (init.body instanceof ArrayBuffer) call.body = new TextDecoder().decode(init.body)
    calls.push(call)
    return respond(call, init)
  })
  return calls
}

const file = () => new File(['abcdabcdab'], 'notes.txt')

afterEach(() => vi.unstubAllGlobals())

describe('uploadFile', () => {
  it('sends each chunk in order with its SHA-256 and commits', async () => {
    const calls = fakeFetch((call) => {
      if (call.method === 'POST' && call.url.endsWith('/uploads')) return json(201, { uploadId: 'u1', chunkSize: 4, path: '/tmp/notes.txt' })
      if (call.method === 'PUT') {
        const offset = Number(new URL(call.url, 'http://x').searchParams.get('offset'))
        return json(200, { confirmed: offset + call.body!.length })
      }
      return json(200, { path: '/tmp/notes.txt' })
    })
    const progress: number[] = []
    const path = await uploadFile('h1', '/tmp', file(), { onProgress: (n) => progress.push(n), signal: new AbortController().signal })

    expect(path).toBe('/tmp/notes.txt')
    expect(progress).toEqual([4, 8, 10])
    expect(calls.map((c) => [c.method, c.url, c.sha, c.body])).toEqual([
      ['POST', '/api/v1/hosts/h1/uploads', undefined, undefined],
      ['PUT', '/api/v1/uploads/u1?offset=0', SHA_ABCD, 'abcd'],
      ['PUT', '/api/v1/uploads/u1?offset=4', SHA_ABCD, 'abcd'],
      ['PUT', '/api/v1/uploads/u1?offset=8', SHA_AB, 'ab'],
      ['POST', '/api/v1/uploads/u1/commit', undefined, undefined],
    ])
  })

  it('reports an existing name at begin without uploading anything', async () => {
    const calls = fakeFetch(() => json(409, { error: 'exists' }))
    await expect(uploadFile('h1', '/tmp', file(), { onProgress: () => {}, signal: new AbortController().signal })).rejects.toThrow(NAME_EXISTS)
    expect(calls).toHaveLength(1)
  })

  it('aborts the in-flight chunk and deletes the upload on cancel', async () => {
    const ctrl = new AbortController()
    const calls = fakeFetch((call, init) => {
      if (call.method === 'POST') return json(201, { uploadId: 'u1', chunkSize: 4, path: '/tmp/notes.txt' })
      if (call.method === 'DELETE') return new Response(null, { status: 204 })
      return new Promise((_resolve, reject) => {
        init.signal!.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
        ctrl.abort()
      })
    })
    await expect(uploadFile('h1', '/tmp', file(), { onProgress: () => {}, signal: ctrl.signal })).rejects.toThrow('aborted')
    expect(calls.at(-1)).toMatchObject({ method: 'DELETE', url: '/api/v1/uploads/u1' })
  })
})

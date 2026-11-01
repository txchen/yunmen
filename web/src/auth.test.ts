import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { api, ApiError } from './api'
import { auth, refreshSession, signOut } from './auth'

const session = { expiresAt: '2099-01-01T00:00:00Z', mode: 'standalone', recoveryCodesRemaining: 10 }

beforeEach(() => {
  Object.assign(auth, { session: null, checked: false, problem: null })
})
afterEach(() => {
  vi.restoreAllMocks()
})

it('recovers from a failed session check to the signed-out state', async () => {
  vi.spyOn(api, 'session').mockRejectedValueOnce(new TypeError('offline')).mockRejectedValueOnce(new ApiError(401, {}))
  await refreshSession()
  expect(auth.problem).toBe('unreachable')
  await refreshSession()
  expect(auth.problem).toBeNull()
  expect(auth.session).toBeNull()
  expect(auth.checked).toBe(true)
})

it('preserves the session when logout fails and allows a successful retry', async () => {
  auth.session = session
  vi.spyOn(api, 'logout').mockRejectedValueOnce(new TypeError('offline')).mockResolvedValueOnce(undefined)
  await expect(signOut()).rejects.toThrow('offline')
  expect(auth.session).toEqual(session)
  await signOut()
  expect(auth.session).toBeNull()
})

it('allows signing out when the server session has already expired', async () => {
  auth.session = session
  vi.spyOn(api, 'logout').mockRejectedValue(new ApiError(401, {}))
  await signOut()
  expect(auth.session).toBeNull()
})

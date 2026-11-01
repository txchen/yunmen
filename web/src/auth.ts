import { reactive } from 'vue'
import { api, ApiError, type Session } from './api'

export type AuthProblem = 'access' | 'unreachable' | null

export const auth = reactive({
  session: null as Session | null,
  checked: false,
  problem: null as AuthProblem,
})

export async function refreshSession(): Promise<void> {
  try {
    auth.session = await api.session()
    auth.problem = null
  } catch (err) {
    auth.session = null
    if (err instanceof ApiError && err.status === 403) auth.problem = 'access'
    else auth.problem = err instanceof ApiError && err.status === 401 ? null : 'unreachable'
  }
  auth.checked = true
}

// Only same-app absolute paths are accepted, so a crafted link cannot redirect off-site.
export function safeRedirect(value: unknown): string {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') ? value : '/hosts'
}

// A failed request must not pretend that the HttpOnly session cookie was revoked.
export async function signOut(): Promise<void> {
  try {
    await api.logout()
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 401)) throw err
  }
  auth.session = null
  auth.problem = null
}

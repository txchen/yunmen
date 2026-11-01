import type { AuthKind, HostAuth } from './api'

export const IMPORT_KEY = '__import__'

export interface AuthChoice {
  authKind: AuthKind
  // A library key id, IMPORT_KEY, or '' when nothing is selected.
  keyChoice: string
  privateKey: string
  passphrase: string
  keyLabel: string
  password: string
}

export interface SavedAuth {
  authKind: AuthKind
  keyId?: string
}

// `auth` undefined with no blocker means the saved credential is kept, so the request omits `auth`.
export interface ResolvedAuth {
  auth?: HostAuth
  blocker?: string
}

export function resolveHostAuth(choice: AuthChoice, saved: SavedAuth | null): ResolvedAuth {
  if (choice.authKind === 'password') {
    if (choice.password !== '') return { auth: { kind: 'password', password: choice.password } }
    return saved?.authKind === 'password' ? {} : { blocker: 'Enter the password.' }
  }
  if (choice.keyChoice === IMPORT_KEY) {
    if (choice.privateKey.trim() === '') return { blocker: 'Paste a private key.' }
    const auth: Extract<HostAuth, { privateKey: string }> = { kind: 'key', privateKey: choice.privateKey }
    if (choice.passphrase) auth.passphrase = choice.passphrase
    if (choice.keyLabel.trim()) auth.keyLabel = choice.keyLabel.trim()
    return { auth }
  }
  const keepsKey = saved?.authKind === 'key'
  if (choice.keyChoice === '') return keepsKey ? {} : { blocker: 'Choose a key.' }
  if (keepsKey && choice.keyChoice === saved.keyId) return {}
  return { auth: { kind: 'key', keyId: choice.keyChoice } }
}

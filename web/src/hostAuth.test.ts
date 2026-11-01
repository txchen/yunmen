import { describe, expect, it } from 'vitest'
import { IMPORT_KEY, resolveHostAuth, type AuthChoice } from './hostAuth'

const blank: AuthChoice = { authKind: 'key', keyChoice: '', privateKey: '', passphrase: '', keyLabel: '', password: '' }

describe('resolveHostAuth', () => {
  it('omits auth when an edited key host keeps its key, and sends keyId when it changes', () => {
    const saved = { authKind: 'key' as const, keyId: 'k1' }
    expect(resolveHostAuth({ ...blank, keyChoice: 'k1' }, saved)).toEqual({})
    expect(resolveHostAuth({ ...blank, keyChoice: 'k2' }, saved)).toEqual({ auth: { kind: 'key', keyId: 'k2' } })
    expect(resolveHostAuth({ ...blank, keyChoice: 'k1' }, { authKind: 'password' })).toEqual({
      auth: { kind: 'key', keyId: 'k1' },
    })
    expect(resolveHostAuth(blank, null).blocker).toBe('Choose a key.')
  })

  it('sends an inline import with only the optional fields that are filled in', () => {
    const choice = { ...blank, keyChoice: IMPORT_KEY, privateKey: 'PEM' }
    expect(resolveHostAuth(choice, null)).toEqual({ auth: { kind: 'key', privateKey: 'PEM' } })
    expect(resolveHostAuth({ ...choice, passphrase: 'pw', keyLabel: ' laptop ' }, null)).toEqual({
      auth: { kind: 'key', privateKey: 'PEM', passphrase: 'pw', keyLabel: 'laptop' },
    })
    expect(resolveHostAuth({ ...choice, privateKey: '  ' }, null).blocker).toBe('Paste a private key.')
  })

  it('keeps a saved password when the field is empty', () => {
    const choice = { ...blank, authKind: 'password' as const }
    expect(resolveHostAuth(choice, { authKind: 'password' })).toEqual({})
    expect(resolveHostAuth(choice, { authKind: 'key', keyId: 'k1' }).blocker).toBe('Enter the password.')
  })
})

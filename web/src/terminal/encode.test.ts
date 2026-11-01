import { describe, expect, it } from 'vitest'
import { createInputEncoder } from './encode'

const utf8 = (s: string) => Array.from(new TextEncoder().encode(s))

describe('createInputEncoder', () => {
  it('joins a surrogate pair split across onData calls', () => {
    const enc = createInputEncoder()
    const emoji = '😀'
    const first = enc(emoji[0])
    const second = enc(emoji[1])
    expect(Array.from(first)).toEqual([])
    expect([...first, ...second]).toEqual(utf8(emoji))
  })

  it('passes whole strings through unchanged', () => {
    const enc = createInputEncoder()
    expect(Array.from(enc('中文 😀 ┌─┐\r\x03'))).toEqual(utf8('中文 😀 ┌─┐\r\x03'))
  })

  it('replaces a high surrogate that never gets its partner', () => {
    const enc = createInputEncoder()
    enc('a\ud83d')
    expect(Array.from(enc('b'))).toEqual(utf8('\ufffdb'))
  })
})

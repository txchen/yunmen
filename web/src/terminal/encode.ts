// xterm's onData can deliver one character as two strings holding the two
// halves of a UTF-16 surrogate pair (Firefox fires one keypress per half for
// emoji and other non-BMP input). Encoding each string on its own turns both
// halves into U+FFFD, so a trailing high surrogate waits for the next call.
export function createInputEncoder(): (s: string) => Uint8Array {
  const encoder = new TextEncoder()
  let pendingHigh = ''
  return (s: string) => {
    s = pendingHigh + s
    pendingHigh = ''
    const last = s.charCodeAt(s.length - 1)
    if (last >= 0xd800 && last <= 0xdbff) {
      pendingHigh = s.slice(-1)
      s = s.slice(0, -1)
    }
    return encoder.encode(s)
  }
}

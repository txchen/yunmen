// Drives the real Web UI in headless Firefox (WebDriver BiDi) against a
// running gateway. Invoked by scripts/e2e-pty.sh with WEB=1.
//
// env: ORIGIN, PASSWORD, CODE (fresh TOTP), SECRET, TOTP_STEP, TOTP_STEP_FILE,
// BIDI (ws url), WORKHOME (dir to
// upload into), UPLOAD (local file path), SHOTS (screenshot dir)
import fs from 'node:fs'
import { createHmac } from 'node:crypto'

const { ORIGIN, PASSWORD, CODE, SECRET, TOTP_STEP, TOTP_STEP_FILE, BIDI, WORKHOME, UPLOAD, SHOTS } = process.env
const ws = new WebSocket(BIDI)
let seq = 0
const pending = new Map()
ws.onmessage = (e) => {
  const m = JSON.parse(e.data)
  if (m.id && pending.has(m.id)) {
    pending.get(m.id)(m)
    pending.delete(m.id)
  }
}
const send = (method, params) =>
  new Promise((resolve, reject) => {
    const id = ++seq
    pending.set(id, (m) => (m.type === 'error' ? reject(new Error(`${method}: ${m.error} ${m.message}`)) : resolve(m.result)))
    ws.send(JSON.stringify({ id, method, params }))
  })
await new Promise((r) => (ws.onopen = r))
await send('session.new', { capabilities: {} })
const ctx = (await send('browsingContext.getTree', {})).contexts[0].context
await send('browsingContext.setViewport', { context: ctx, viewport: { width: 1200, height: 700 } })

let failed = 0
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  web: ${name}${ok ? '' : ' ' + detail}`)
  if (!ok) failed++
}
const js = async (expression) => {
  const r = await send('script.evaluate', { expression, target: { context: ctx }, awaitPromise: true })
  if (r.type === 'exception') throw new Error(r.exceptionDetails.text)
  return r.result.value
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const waitFor = async (expression, timeout = 15000) => {
  const end = Date.now() + timeout
  while (Date.now() < end) {
    if (await js(`!!(${expression})`)) return true
    await sleep(150)
  }
  return false
}
const shot = async (name) => {
  if (!SHOTS) return
  const s = await send('browsingContext.captureScreenshot', { context: ctx })
  fs.writeFileSync(`${SHOTS}/${name}.png`, Buffer.from(s.data, 'base64'))
}
const clickText = (sel, text) =>
  js(`(() => { const el = [...document.querySelectorAll(${JSON.stringify(sel)})].find(e => e.textContent.trim() === ${JSON.stringify(text)}); if (el) el.click(); return !!el })()`)
const setInput = (sel, value) =>
  js(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); el.value = ${JSON.stringify(value)}; el.dispatchEvent(new Event('input', { bubbles: true })); return true })()`)
const termText = (pane = 'visible') =>
  `[...document.querySelectorAll('.pane')].filter(p => ${pane === 'visible' ? "p.style.display !== 'none'" : 'true'}).map(p => p.querySelector('.xterm-rows')?.innerText ?? '').join('\\n')`
const keys = async (text) => {
  await js(`document.querySelector('.pane:not([style*="display: none"]) .xterm-helper-textarea').focus()`)
  const actions = []
  for (const ch of text) {
    actions.push({ type: 'keyDown', value: ch }, { type: 'keyUp', value: ch })
  }
  await send('input.performActions', { context: ctx, actions: [{ type: 'key', id: 'kb', actions }] })
}
const ENTER = '\uE007'
const ctrl = async (ch) => {
  await send('input.performActions', {
    context: ctx,
    actions: [{ type: 'key', id: 'kb', actions: [{ type: 'keyDown', value: '\uE009' }, { type: 'keyDown', value: ch }, { type: 'keyUp', value: ch }, { type: 'keyUp', value: '\uE009' }] }],
  })
}

// Generate one fresh code for the sign-out/sign-in regression, respecting the
// server's replay protection and +/- one-step acceptance window.
async function nextCode() {
  if (!/^[A-Z2-7]+$/.test(SECRET ?? '') || !/^\d+$/.test(TOTP_STEP ?? '') || !TOTP_STEP_FILE) {
    throw new Error('SECRET, TOTP_STEP and TOTP_STEP_FILE must be set (run via scripts/e2e-pty.sh with WEB=1)')
  }
  const step = Math.max(Math.floor(Date.now() / 30000), Number(TOTP_STEP) + 1)
  while (step > Math.floor(Date.now() / 30000) + 1) await sleep(250)
  const bits = [...SECRET].map((c) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c).toString(2).padStart(5, '0')).join('')
  const secret = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)))
  fs.writeFileSync(TOTP_STEP_FILE, String(step))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))
  const h = createHmac('sha1', secret).update(counter).digest()
  return String((h.readUInt32BE(h[19] & 15) & 0x7fffffff) % 1000000).padStart(6, '0')
}

try {
  const preload = await send('script.addPreloadScript', {
    functionDeclaration: `() => {
      const original = window.fetch.bind(window)
      let failed = false
      window.fetch = (url, opts) => {
        if (!failed && String(url).endsWith('/auth/session')) {
          failed = true
          return Promise.reject(new TypeError('temporary network failure'))
        }
        return original(url, opts)
      }
    }`,
  })
  await send('browsingContext.navigate', { context: ctx, url: ORIGIN + '/', wait: 'complete' })
  await send('script.removePreloadScript', { script: preload.script })
  check('initial network failure is shown', await waitFor(`document.body.innerText.includes('Cannot reach the Yunmen server')`))
  await clickText('button', 'Retry')
  check('retry after network recovery shows the login form', await waitFor(`document.querySelector('input[type=password]')`))
  await setInput('input[type=password]', PASSWORD)
  await setInput('input[autocomplete=one-time-code], form input:not([type=password])', CODE)
  await js(`document.querySelector('form button[type=submit]').click()`)
  check('login with password and TOTP', await waitFor(`[...document.querySelectorAll('button')].some(b => b.textContent.trim() === 'Connect')`))

  await clickText('button', 'Connect')
  check('terminal tab opens a shell', await waitFor(`${termText()}.includes('bash-')`))
  await keys(`printf 'o:\\344\\270\\255\\360\\237\\230\\200\\342\\224\\214:\\n'` + ENTER)
  check('unicode output rendered (remote emits CJK, emoji, box drawing)', await waitFor(`${termText()}.includes('o:中😀┌:')`), await js(termText()))
  await js(`(() => { window.__ev = []; const ta = document.querySelector('.xterm-helper-textarea'); for (const t of ['keydown','keypress','input']) ta.addEventListener(t, e => window.__ev.push(t + ':' + JSON.stringify(e.key ?? e.data) + ':' + (e.charCode ?? '')), true) })()`)
  await keys(`echo 'i:中文 😀 ┌─┐:'` + ENTER)
  check('unicode keyboard input reaches the shell', await waitFor(`/^i:中文 😀 ┌─┐:$/m.test(${termText()})`), JSON.stringify(await js(`window.__ev.filter(e => !/^"[ -~]"$/.test(e.split(':')[1]))`)) + ' ' + (await js(termText())).slice(-200))

  await keys('stty size' + ENTER)
  await sleep(500)
  const before = await js(termText())
  await send('browsingContext.setViewport', { context: ctx, viewport: { width: 900, height: 500 } })
  await sleep(600)
  await keys('clear; stty size' + ENTER)
  await sleep(800)
  const after = await js(termText())
  const sizeOf = (t) => (t.match(/^(\d+ \d+)$/m) || [])[1]
  check('browser resize reaches the PTY', sizeOf(before) && sizeOf(after) && sizeOf(before) !== sizeOf(after), `${sizeOf(before)} -> ${sizeOf(after)}`)

  await keys('sleep 30; echo SLEPT' + ENTER)
  await sleep(500)
  await ctrl('c')
  await sleep(400)
  await keys('echo after-$((40+2))' + ENTER)
  check('Ctrl-C interrupts the remote program', await waitFor(`/^after-42$/m.test(${termText()}) && !/^SLEPT$/m.test(${termText()})`))

  await keys('vim -u NONE -N web.txt' + ENTER)
  await sleep(800)
  await keys('iweb 中文')
  await send('input.performActions', { context: ctx, actions: [{ type: 'key', id: 'kb', actions: [{ type: 'keyDown', value: '\uE00C' }, { type: 'keyUp', value: '\uE00C' }] }] })
  await sleep(300)
  await keys(':wq' + ENTER)
  await sleep(600)
  await keys('cat web.txt' + ENTER)
  check('vim from the browser', await waitFor(`/^web 中文$/m.test(${termText()})`))
  await shot('terminal')

  await clickText('button', 'Connect')
  check('second independent terminal tab', await waitFor(`document.querySelectorAll('.tab').length === 2 && ${termText()}.includes('bash-') && !${termText()}.includes('after-42')`))

  await clickText('button', 'Files')
  check('files listing loads without a shell', await waitFor(`document.querySelector('.files-table')`))
  for (const part of WORKHOME.split('/').filter(Boolean)) {
    await waitFor(`document.querySelector('.files-table')`)
    if (part === WORKHOME.split('/').filter(Boolean)[0]) {
      await js(`document.querySelector('.crumbs a').click()`)
      await waitFor(`[...document.querySelectorAll('.files-table a')].some(a => a.textContent.trim() === ${JSON.stringify(part)})`)
    }
    await clickText('.files-table a', part)
    await sleep(400)
  }
  check('navigated to the work directory', await waitFor(`[...document.querySelectorAll('.files-table a')].some(a => a.textContent.trim() === 'web.txt') || document.querySelector('.files-table').innerText.includes('web.txt')`))

  const input = await send('script.evaluate', { expression: `document.querySelector('.files input[type=file]')`, target: { context: ctx }, awaitPromise: false })
  await send('input.setFiles', { context: ctx, element: { sharedId: input.result.sharedId }, files: [UPLOAD] })
  check('upload completes', await waitFor(`document.querySelector('.upload-row.done')`, 30000), await js(`document.querySelector('.uploads')?.innerText`))
  const name = UPLOAD.split('/').pop()
  check('uploaded bytes identical on the target', fs.existsSync(`${WORKHOME}/${name}`) && Buffer.compare(fs.readFileSync(`${WORKHOME}/${name}`), fs.readFileSync(UPLOAD)) === 0)

  await send('input.setFiles', { context: ctx, element: { sharedId: input.result.sharedId }, files: [] })
  await send('input.setFiles', { context: ctx, element: { sharedId: input.result.sharedId }, files: [UPLOAD] })
  check('second upload of the same name refused', await waitFor(`document.querySelector('.upload-row.failed')?.innerText.includes('already exists')`, 15000), await js(`document.querySelector('.uploads')?.innerText`))

  const href = await js(`[...document.querySelectorAll('.files-table tr')].find(r => r.innerText.includes(${JSON.stringify(name)}))?.querySelector('a[download]')?.href`)
  const dl = await js(`fetch(${JSON.stringify(href)}).then(r => r.arrayBuffer()).then(b => b.byteLength)`)
  check('download link returns the file', dl === fs.statSync(UPLOAD).size, `${dl}`)
  await shot('files')

  await clickText('a', 'Keys')
  check('key library lists the imported host key and where it is used', await waitFor(`document.body.innerText.includes('box key') && document.body.innerText.includes('SHA256:')`), await js(`document.body.innerText.slice(0, 400)`))
  await clickText('a', 'Hosts')
  check('terminal tabs survive visiting another page', await waitFor(`document.querySelectorAll('.tab').length >= 2`))

  await js(`document.querySelectorAll('.tab')[0].click()`)
  await sleep(300)
  await keys('exit 4' + ENTER)
  check('remote exit shown without clearing output', await waitFor(`document.querySelector('.term-ended') && ${termText()}.includes('after-42')`), await js(`document.querySelector('.term-ended')?.innerText`))
  check('exit status shown', await js(`document.querySelector('.term-ended').innerText.includes('4')`))
  await shot('ended')

  // A failed logout must keep the current workspace and explain the failure.
  await js(`window.__realFetch = window.fetch; window.fetch = (url, opts) => String(url).endsWith('/auth/logout') ? Promise.reject(new TypeError('offline')) : window.__realFetch(url, opts)`)
  await clickText('button', 'Sign out')
  check('failed sign-out preserves the session and shows an error', await waitFor(`document.querySelector('[role=alert]')?.textContent.includes('Could not sign out') && document.querySelectorAll('.tab').length >= 2`))
  await js(`window.fetch = window.__realFetch; delete window.__realFetch`)
  await clickText('button', 'Sign out')
  check('sign-out reaches the login form', await waitFor(`document.querySelector('input[type=password]') && !document.querySelector('.topbar')`))
  await setInput('input[type=password]', PASSWORD)
  await setInput('input[autocomplete=one-time-code]', await nextCode())
  await js(`document.querySelector('form button[type=submit]').click()`)
  check('signing in again reloads hosts and discards old tabs', await waitFor(`[...document.querySelectorAll('button')].some(b => b.textContent.trim() === 'Connect') && document.querySelectorAll('.tab').length === 0`))

} catch (e) {
  check('driver', false, e.stack)
}
await send('session.end', {}).catch(() => {})
process.exit(failed ? 1 : 0)

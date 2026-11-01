<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { Unicode11Addon } from '@xterm/addon-unicode11'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { TerminalSession, terminalUrl, type SessionState } from '../terminal/session'
import { describeEnd } from '../terminal/reasons'
import { formatTime } from '../format'
import { createInputEncoder } from '../terminal/encode'

const props = defineProps<{ hostId: string; active: boolean }>()
const emit = defineEmits<{ status: [SessionState['kind']] }>()

const FONT =
  '"JetBrains Mono", "Cascadia Mono", "SF Mono", Menlo, Consolas, "DejaVu Sans Mono", "Noto Sans Mono CJK SC", ' +
  '"Noto Sans CJK SC", "Microsoft YaHei", "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", monospace'

const el = ref<HTMLElement>()
const state = ref<SessionState>({ kind: 'connecting' })
const notice = ref('')
const ended = computed(() => (state.value.kind === 'ended' ? state.value : null))
const endInfo = computed(() => (ended.value ? describeEnd(ended.value.reason) : null))

const encodeInput = createInputEncoder()
let term: Terminal
let fit: FitAddon
let session: TerminalSession | null = null
let observer: ResizeObserver | null = null
let resizeTimer: ReturnType<typeof setTimeout> | undefined
let noticeTimer: ReturnType<typeof setTimeout> | undefined

function fitIfVisible() {
  // Hidden tabs (v-show) and a deactivated workspace measure 0x0; fitting then would shrink the PTY.
  if (!el.value || el.value.clientWidth === 0 || el.value.clientHeight === 0) return
  fit.fit()
}

function input(bytes: Uint8Array) {
  if (!session || session.state.kind === 'ended') return
  if (session.sendInput(bytes)) return
  notice.value = 'Paste refused: more than 4 MiB of input is still waiting to be sent. Nothing from this paste was sent.'
  clearTimeout(noticeTimer)
  noticeTimer = setTimeout(() => (notice.value = ''), 8000)
}

function connect() {
  state.value = { kind: 'connecting' }
  emit('status', 'connecting')
  session = new TerminalSession({
    url: terminalUrl(location),
    hostId: props.hostId,
    cols: term.cols,
    rows: term.rows,
    write: (data, done) => term.write(data, done),
    onState: (s) => {
      state.value = s
      emit('status', s.kind)
    },
  })
  session.start()
}

function reconnect() {
  term.reset()
  fitIfVisible()
  connect()
  term.focus()
}

onMounted(() => {
  term = new Terminal({
    allowProposedApi: true,
    fontFamily: FONT,
    fontSize: 13,
    cursorBlink: true,
    scrollback: 5000,
    theme: { background: '#0d1117', foreground: '#d6dde6', cursor: '#d6dde6', selectionBackground: '#3a4a63' },
  })
  fit = new FitAddon()
  term.loadAddon(fit)
  term.loadAddon(new Unicode11Addon())
  term.unicode.activeVersion = '11'
  term.loadAddon(new WebLinksAddon())
  term.open(el.value!)
  fitIfVisible()
  term.onData((s) => input(encodeInput(s)))
  term.onBinary((s) => input(Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff)))
  connect()

  observer = new ResizeObserver(() => {
    clearTimeout(resizeTimer)
    resizeTimer = setTimeout(() => {
      fitIfVisible()
      session?.resize(term.cols, term.rows)
    }, 50)
  })
  observer.observe(el.value!)
  if (props.active) term.focus()
})

watch(
  () => props.active,
  (active) => {
    if (active) requestAnimationFrame(() => term.focus())
  },
)

onBeforeUnmount(() => {
  observer?.disconnect()
  clearTimeout(resizeTimer)
  clearTimeout(noticeTimer)
  session?.close()
  term.dispose()
})
</script>

<template>
  <div class="terminal-tab">
    <div class="term-status">
      <template v-if="state.kind === 'connecting'">Connecting…</template>
      <template v-else-if="state.kind === 'ready'">
        Connected. The server closes this terminal at {{ formatTime(state.expiresAt) }}.
      </template>
      <template v-else>Disconnected.</template>
    </div>
    <div v-if="ended && endInfo" class="term-ended" :class="endInfo.severity">
      <div class="term-ended-main">
        <strong>{{ endInfo.text }}</strong>
        <span v-if="ended.message">{{ ended.message }}</span>
        <span v-if="ended.exitStatus !== undefined">Exit status {{ ended.exitStatus }}.</span>
        <span v-if="ended.signal">Signal {{ ended.signal }}.</span>
      </div>
      <div class="term-ended-actions">
        <button class="primary" @click="reconnect">Reconnect (new shell)</button>
        <span class="muted">
          Nothing is replayed. Run <code>tmux new -A -s main</code> on the host to keep work across disconnects.
        </span>
      </div>
    </div>
    <div v-if="notice" class="term-notice">{{ notice }}</div>
    <div ref="el" class="term-host" />
  </div>
</template>

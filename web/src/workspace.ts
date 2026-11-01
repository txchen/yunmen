import { reactive } from 'vue'
import type { Host } from './api'

export type TabKind = 'terminal' | 'files'

export interface Tab {
  id: string
  kind: TabKind
  hostId: string
  // Per-host terminal number, so several terminals on one host stay distinguishable.
  n: number
  status: 'connecting' | 'ready' | 'ended' | null
}

let nextId = 1

export const workspace = reactive({
  hosts: [] as Host[],
  tabs: [] as Tab[],
  activeId: null as string | null,

  host(id: string): Host | undefined {
    return this.hosts.find((h) => h.id === id)
  },

  title(tab: Tab): string {
    const label = this.host(tab.hostId)?.alias ?? '(deleted host)'
    return tab.kind === 'files' ? `${label} files` : `${label} #${tab.n}`
  },

  openTerminal(hostId: string) {
    const n = Math.max(0, ...this.tabs.filter((t) => t.kind === 'terminal' && t.hostId === hostId).map((t) => t.n)) + 1
    const tab: Tab = { id: `t${nextId++}`, kind: 'terminal', hostId, n, status: 'connecting' }
    this.tabs.push(tab)
    this.activeId = tab.id
  },

  openFiles(hostId: string) {
    const existing = this.tabs.find((t) => t.kind === 'files' && t.hostId === hostId)
    if (existing) {
      this.activeId = existing.id
      return
    }
    const tab: Tab = { id: `t${nextId++}`, kind: 'files', hostId, n: 0, status: null }
    this.tabs.push(tab)
    this.activeId = tab.id
  },

  closeTab(id: string) {
    const i = this.tabs.findIndex((t) => t.id === id)
    if (i < 0) return
    this.tabs.splice(i, 1)
    if (this.activeId === id) this.activeId = this.tabs[Math.min(i, this.tabs.length - 1)]?.id ?? null
  },

  reset() {
    this.tabs = []
    this.activeId = null
    this.hosts = []
  },
})

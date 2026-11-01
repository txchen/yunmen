<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, type Host } from '../api'
import { workspace } from '../workspace'
import HostEditor from '../components/HostEditor.vue'
import TerminalTab from '../components/TerminalTab.vue'
import FilesTab from '../components/FilesTab.vue'

defineOptions({ name: 'WorkspaceView' })

const filter = ref('')
const error = ref('')
// undefined: closed, null: adding a new host.
const editing = ref<Host | null | undefined>(undefined)

const visibleHosts = computed(() => {
  const q = filter.value.trim().toLowerCase()
  if (!q) return workspace.hosts
  return workspace.hosts.filter((h) =>
    [h.name, h.alias, h.address, h.username].some((v) => v.toLowerCase().includes(q)),
  )
})

async function loadHosts() {
  try {
    workspace.hosts = await api.hosts()
    error.value = ''
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  }
}

function onDeleted(id: string) {
  editing.value = undefined
  for (const t of workspace.tabs.filter((t) => t.kind === 'files' && t.hostId === id)) workspace.closeTab(t.id)
  void loadHosts()
}

onMounted(loadHosts)
</script>

<template>
  <div class="workspace">
    <aside class="sidebar">
      <div class="sidebar-head">
        <input v-model="filter" type="search" placeholder="Filter hosts" />
        <button class="primary" title="Add host" @click="editing = null">+ Add</button>
      </div>
      <p v-if="error" class="error">{{ error }}</p>
      <p v-if="!error && workspace.hosts.length === 0" class="muted pad">No hosts yet.</p>
      <ul class="host-list">
        <li v-for="h in visibleHosts" :key="h.id" class="host">
          <div class="host-name">{{ h.name || h.alias }}</div>
          <div class="muted small">{{ h.alias }} · {{ h.username }}@{{ h.address }}:{{ h.port }}</div>
          <div class="host-actions">
            <button class="primary" @click="workspace.openTerminal(h.id)">Connect</button>
            <button @click="workspace.openFiles(h.id)">Files</button>
            <button @click="editing = h">Edit</button>
          </div>
        </li>
      </ul>
    </aside>

    <section class="main">
      <div v-if="workspace.tabs.length" class="tabbar">
        <div
          v-for="t in workspace.tabs"
          :key="t.id"
          class="tab"
          :class="{ active: t.id === workspace.activeId }"
          @click="workspace.activeId = t.id"
        >
          <span v-if="t.kind === 'terminal'" class="dot" :class="t.status ?? ''" />
          <span>{{ workspace.title(t) }}</span>
          <button class="close" title="Close tab" @click.stop="workspace.closeTab(t.id)">×</button>
        </div>
      </div>
      <div v-else class="empty muted">Pick a host and press Connect or Files.</div>
      <div class="panes">
        <div v-for="t in workspace.tabs" v-show="t.id === workspace.activeId" :key="t.id" class="pane">
          <TerminalTab
            v-if="t.kind === 'terminal'"
            :host-id="t.hostId"
            :active="t.id === workspace.activeId"
            @status="(s) => (t.status = s)"
          />
          <FilesTab v-else :host-id="t.hostId" />
        </div>
      </div>
    </section>

    <HostEditor
      v-if="editing !== undefined"
      :key="editing?.id ?? 'new'"
      :host="editing"
      @close="editing = undefined"
      @saved="loadHosts"
      @deleted="onDeleted"
    />
  </div>
</template>

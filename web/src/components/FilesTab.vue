<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { api, ApiError, type FileEntry, type Listing } from '../api'
import { uploadFile } from '../files/upload'
import { formatSize, formatTime } from '../format'

const props = defineProps<{ hostId: string }>()

interface UploadRow {
  id: number
  name: string
  size: number
  confirmed: number
  status: 'uploading' | 'done' | 'failed' | 'cancelled'
  message: string
  ctrl: AbortController
}

const listing = ref<Listing | null>(null)
const loading = ref(false)
const error = ref('')
const unavailable = ref(false)
const uploads = reactive<UploadRow[]>([])
const picker = ref<HTMLInputElement>()
let nextUpload = 1

const TYPE_LABEL: Record<FileEntry['type'], string> = { dir: 'dir', file: 'file', symlink: 'link', other: 'other' }
const TYPE_ICON: Record<FileEntry['type'], string> = { dir: '📁', file: '📄', symlink: '🔗', other: '⚙' }

const crumbs = computed(() => {
  const path = listing.value?.path ?? ''
  const parts = path.split('/').filter(Boolean)
  return [{ name: '/', path: '/' }, ...parts.map((name, i) => ({ name, path: '/' + parts.slice(0, i + 1).join('/') }))]
})

function join(dir: string, name: string) {
  return dir === '/' ? `/${name}` : `${dir}/${name}`
}

function parent(path: string) {
  const i = path.lastIndexOf('/')
  return i <= 0 ? '/' : path.slice(0, i)
}

function isDirLike(e: FileEntry) {
  return e.type === 'dir' || (e.type === 'symlink' && e.target === 'dir')
}

async function load(path: string) {
  loading.value = true
  error.value = ''
  try {
    listing.value = await api.listFiles(props.hostId, path)
    unavailable.value = false
  } catch (err) {
    if (err instanceof ApiError && err.status === 501) unavailable.value = true
    else error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

function open(e: FileEntry) {
  if (listing.value && e.validName && isDirLike(e)) void load(join(listing.value.path, e.name))
}

function pick() {
  const file = picker.value?.files?.[0]
  if (picker.value) picker.value.value = ''
  if (!file || !listing.value) return
  const directory = listing.value.path
  const row = reactive<UploadRow>({
    id: nextUpload++,
    name: file.name,
    size: file.size,
    confirmed: 0,
    status: 'uploading',
    message: '',
    ctrl: new AbortController(),
  })
  uploads.push(row)
  uploadFile(props.hostId, directory, file, { signal: row.ctrl.signal, onProgress: (n) => (row.confirmed = n) })
    .then((path) => {
      row.status = 'done'
      row.message = `Saved as ${path}`
      if (listing.value?.path === directory) void load(directory)
    })
    .catch((err: unknown) => {
      if (row.ctrl.signal.aborted) {
        row.status = 'cancelled'
        row.message = 'Cancelled; the partial upload was removed.'
      } else {
        row.status = 'failed'
        row.message = err instanceof Error ? err.message : String(err)
      }
    })
}

function dismiss(row: UploadRow) {
  uploads.splice(uploads.indexOf(row), 1)
}

function percent(row: UploadRow) {
  return row.size === 0 ? 100 : Math.floor((row.confirmed / row.size) * 100)
}

onMounted(() => load(''))
</script>

<template>
  <div class="files">
    <p v-if="unavailable" class="notice">Files unavailable on this host (no SFTP); terminals still work.</p>
    <template v-else>
      <div class="files-toolbar">
        <button :disabled="!listing || listing.path === '/'" title="Parent directory" @click="load(parent(listing!.path))">
          ↑ Parent
        </button>
        <nav class="crumbs">
          <template v-for="(c, i) in crumbs" :key="c.path">
            <span v-if="i > 1" class="muted">/</span>
            <a href="#" @click.prevent="load(c.path)">{{ c.name }}</a>
          </template>
        </nav>
        <span class="spacer" />
        <button :disabled="!listing" @click="load(listing!.path)">Refresh</button>
        <button class="primary" :disabled="!listing" @click="picker?.click()">Upload file…</button>
        <input ref="picker" type="file" hidden @change="pick" />
      </div>

      <div v-if="uploads.length" class="uploads">
        <div v-for="row in uploads" :key="row.id" class="upload-row" :class="row.status">
          <span class="upload-name">{{ row.name }}</span>
          <progress :value="row.confirmed" :max="row.size || 1" />
          <span class="muted">{{ percent(row) }}% of {{ formatSize(row.size) }}</span>
          <span v-if="row.message" class="upload-msg">{{ row.message }}</span>
          <button v-if="row.status === 'uploading'" @click="row.ctrl.abort()">Cancel</button>
          <button v-else @click="dismiss(row)">Dismiss</button>
        </div>
      </div>

      <p v-if="error" class="error">{{ error }}</p>
      <p v-if="loading && !listing" class="muted">Loading…</p>
      <p v-if="listing?.truncated" class="notice">Only the first 5000 entries are shown.</p>

      <table v-if="listing" class="table files-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th class="num">Size</th>
            <th>Modified</th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in listing.entries" :key="e.name" :class="{ invalid: !e.validName }">
            <td>
              <span class="icon">{{ TYPE_ICON[e.type] }}</span>
              <a v-if="e.validName && isDirLike(e)" href="#" @click.prevent="open(e)">{{ e.name }}</a>
              <span v-else :title="e.validName ? '' : 'This name cannot be opened or downloaded'">{{ e.name }}</span>
            </td>
            <td class="muted">
              {{ TYPE_LABEL[e.type] }}<template v-if="e.type === 'symlink'"> → {{ e.target ?? 'unresolved' }}</template>
            </td>
            <td class="num">{{ e.type === 'file' ? formatSize(e.size) : '' }}</td>
            <td class="muted">{{ formatTime(e.modTime) }}</td>
            <td>
              <a
                v-if="e.validName && (e.type === 'file' || (e.type === 'symlink' && e.target === 'file'))"
                :href="api.downloadUrl(hostId, join(listing.path, e.name))"
                download
                >Download</a
              >
            </td>
          </tr>
          <tr v-if="listing.entries.length === 0">
            <td colspan="5" class="muted">Empty directory</td>
          </tr>
        </tbody>
      </table>
    </template>
  </div>
</template>

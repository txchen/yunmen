<script setup lang="ts">
import { nextTick, onMounted, reactive, ref } from 'vue'
import { api, ApiError, type NewKey, type SshKey } from '../api'
import { formatTime } from '../format'
import PublicKeyBox from '../components/PublicKeyBox.vue'

const keys = ref<SshKey[]>([])
const error = ref('')
const notice = ref('')

const renaming = reactive({ id: '', label: '', busy: false })
const renameInput = ref<HTMLInputElement[]>([])

const form = reactive({ label: '', mode: 'generate' as 'generate' | 'import', privateKey: '', passphrase: '' })
const creating = ref(false)
const createError = ref('')
const created = ref<SshKey | null>(null)

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

async function load() {
  try {
    keys.value = await api.keys()
    error.value = ''
  } catch (err) {
    error.value = describe(err)
  }
}

async function startRename(k: SshKey) {
  renaming.id = k.id
  renaming.label = k.label
  await nextTick()
  renameInput.value[0]?.focus()
}

async function saveRename() {
  const label = renaming.label.trim()
  if (!label) return
  renaming.busy = true
  try {
    await api.renameKey(renaming.id, label)
    renaming.id = ''
    notice.value = ''
    await load()
  } catch (err) {
    error.value = describe(err)
  } finally {
    renaming.busy = false
  }
}

async function remove(k: SshKey) {
  if (!confirm(`Delete key "${k.label}"? Any terminal or transfer still using it will end.`)) return
  notice.value = ''
  let failure = ''
  try {
    await api.deleteKey(k.id)
    notice.value = `Deleted "${k.label}".`
    if (created.value?.id === k.id) created.value = null
  } catch (err) {
    const usedBy = err instanceof ApiError && err.status === 409 ? err.body.usedBy : undefined
    failure = Array.isArray(usedBy)
      ? `"${k.label}" is still used by: ${usedBy.join(', ')}. Switch those hosts to another key first.`
      : describe(err)
  }
  await load()
  if (failure) error.value = failure
}

async function create() {
  const label = form.label.trim()
  let input: NewKey
  if (form.mode === 'generate') input = { label, generate: true }
  else if (form.passphrase) input = { label, privateKey: form.privateKey, passphrase: form.passphrase }
  else input = { label, privateKey: form.privateKey }
  creating.value = true
  createError.value = ''
  try {
    created.value = await api.createKey(input)
    Object.assign(form, { label: '', privateKey: '', passphrase: '' })
    await load()
  } catch (err) {
    createError.value =
      err instanceof ApiError && err.status === 409 ? `This key is already in the library. (${err.message})` : describe(err)
  } finally {
    creating.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="page-head">
      <h1>SSH keys</h1>
      <button @click="load">Refresh</button>
    </div>
    <p v-if="notice" class="notice">{{ notice }}</p>
    <p v-if="error" class="error">{{ error }}</p>
    <table class="table">
      <thead>
        <tr>
          <th>Label</th>
          <th>Type</th>
          <th>Fingerprint</th>
          <th>Used by</th>
          <th>Created</th>
          <th />
        </tr>
      </thead>
      <tbody>
        <tr v-for="k in keys" :key="k.id">
          <td>
            <form v-if="renaming.id === k.id" class="inline-form" @submit.prevent="saveRename">
              <input ref="renameInput" v-model="renaming.label" required @keydown.esc="renaming.id = ''" />
              <button type="submit" class="primary" :disabled="renaming.busy || !renaming.label.trim()">Save</button>
              <button type="button" @click="renaming.id = ''">Cancel</button>
            </form>
            <template v-else>{{ k.label }}</template>
          </td>
          <td><code>{{ k.keyType }}</code></td>
          <td><code>{{ k.fingerprint }}</code></td>
          <td>{{ k.usedBy.length ? k.usedBy.join(', ') : '-' }}</td>
          <td>{{ formatTime(k.createdAt) }}</td>
          <td>
            <button v-if="renaming.id !== k.id" @click="startRename(k)">Rename</button>
            <button class="danger" @click="remove(k)">Delete</button>
          </td>
        </tr>
        <tr v-if="keys.length === 0">
          <td colspan="6" class="muted">No keys yet.</td>
        </tr>
      </tbody>
    </table>

    <form class="card new-key" @submit.prevent="create">
      <h2>New key</h2>
      <label>
        Label
        <input v-model="form.label" required placeholder="laptop key" />
      </label>
      <label class="inline"><input v-model="form.mode" type="radio" value="generate" /> Generate Ed25519 key on the gateway</label>
      <label class="inline"><input v-model="form.mode" type="radio" value="import" /> Import private key</label>
      <template v-if="form.mode === 'import'">
        <textarea
          v-model="form.privateKey"
          rows="5"
          spellcheck="false"
          autocomplete="off"
          required
          placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
        />
        <label>
          Passphrase <span class="muted">(optional)</span>
          <input v-model="form.passphrase" type="password" autocomplete="off" />
        </label>
      </template>
      <p v-if="createError" class="error">{{ createError }}</p>
      <div class="actions">
        <button
          type="submit"
          class="primary"
          :disabled="creating || !form.label.trim() || (form.mode === 'import' && !form.privateKey.trim())"
        >
          {{ creating ? 'Working…' : form.mode === 'generate' ? 'Generate' : 'Import' }}
        </button>
      </div>
      <div v-if="created" class="created">
        <p>Added "{{ created.label }}" <code>{{ created.fingerprint }}</code>.</p>
        <PublicKeyBox :public-key="created.publicKey" />
      </div>
    </form>
  </div>
</template>

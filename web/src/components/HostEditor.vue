<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { api, ApiError, type AuthKind, type Host, type HostInput, type ProbeResult, type SshKey } from '../api'
import { IMPORT_KEY, resolveHostAuth } from '../hostAuth'
import PublicKeyBox from './PublicKeyBox.vue'

const props = defineProps<{ host: Host | null }>()
const emit = defineEmits<{ close: []; saved: [Host]; deleted: [string] }>()

const saved = props.host
const form = reactive({
  name: saved?.name ?? '',
  alias: saved?.alias ?? '',
  address: saved?.address ?? '',
  port: saved?.port ?? 22,
  username: saved?.username ?? '',
  authKind: (saved?.authKind ?? 'key') as AuthKind,
  keyChoice: saved?.keyId ?? '',
  privateKey: '',
  passphrase: '',
  keyLabel: '',
  password: '',
})

const keys = ref<SshKey[]>([])
const keysError = ref('')
const selectedKey = computed(() => keys.value.find((k) => k.id === form.keyChoice) ?? null)

async function loadKeys() {
  try {
    keys.value = await api.keys()
    keysError.value = ''
    if (!saved && form.keyChoice === '' && keys.value.length === 0) form.keyChoice = IMPORT_KEY
  } catch (err) {
    keysError.value = `Could not load the key library: ${err instanceof Error ? err.message : String(err)}`
  }
}

onMounted(loadKeys)

const probe = ref<(ProbeResult & { forEndpoint: string }) | null>(null)
const verified = ref(false)
const busy = ref(false)
const probeError = ref('')
const saveError = ref('')
const savedWithoutSftp = ref(false)

const endpoint = computed(() => `${form.address.trim()}:${form.port}`)
const endpointChanged = computed(() => !saved || endpoint.value !== `${saved.address}:${saved.port}`)
const probeCurrent = computed(() => (probe.value?.forEndpoint === endpoint.value ? probe.value : null))
const keepsCredential = computed(() => !!saved && form.authKind === saved.authKind)
const resolvedAuth = computed(() => resolveHostAuth(form, saved))

watch(endpoint, () => {
  verified.value = false
})

const blocker = computed(() => {
  if (!form.alias.trim() || !form.address.trim() || !form.username.trim()) return 'Fill in alias, address and username.'
  if (!Number.isInteger(form.port) || form.port < 1 || form.port > 65535) return 'Port must be 1 to 65535.'
  if (resolvedAuth.value.blocker) return resolvedAuth.value.blocker
  if (endpointChanged.value && !probeCurrent.value) return 'Check the host key first.'
  if (probeCurrent.value && !verified.value) return 'Confirm that you verified the fingerprint.'
  return ''
})

async function checkHostKey() {
  busy.value = true
  probeError.value = ''
  verified.value = false
  const forEndpoint = endpoint.value
  try {
    probe.value = { ...(await api.probe(form.address.trim(), form.port)), forEndpoint }
  } catch (err) {
    probe.value = null
    probeError.value =
      err instanceof ApiError && err.status === 502
        ? `Could not reach the host to read its key: ${err.message}`
        : err instanceof Error
          ? err.message
          : String(err)
  } finally {
    busy.value = false
  }
}

function describeSaveError(err: unknown): string {
  if (!(err instanceof ApiError)) return err instanceof Error ? err.message : String(err)
  if (err.status === 422)
    return `Authentication failed: the host rejected these credentials. Nothing was saved. (${err.message})`
  if (err.status === 502)
    return `Network or host key problem while testing the connection${err.reason ? ` (${err.reason})` : ''}. Nothing was saved. ${err.message}`
  return err.message
}

async function save() {
  if (blocker.value) return
  busy.value = true
  saveError.value = ''
  const input: HostInput = {
    alias: form.alias.trim(),
    name: form.name.trim(),
    address: form.address.trim(),
    port: form.port,
    username: form.username.trim(),
    auth: resolvedAuth.value.auth,
    observationId: probeCurrent.value?.observationId,
  }
  try {
    const res = saved ? await api.updateHost(saved.id, { ...input, revision: saved.revision }) : await api.createHost(input)
    emit('saved', res.host)
    if (res.sftpAvailable) emit('close')
    else savedWithoutSftp.value = true
  } catch (err) {
    saveError.value = describeSaveError(err)
  } finally {
    busy.value = false
  }
}

async function remove() {
  if (!saved || !confirm(`Delete host "${saved.alias}"? Its open terminals and transfers will be closed.`)) return
  busy.value = true
  try {
    await api.deleteHost(saved.id)
    emit('deleted', saved.id)
  } catch (err) {
    saveError.value = err instanceof Error ? err.message : String(err)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="overlay">
    <div class="dialog" role="dialog" aria-modal="true">
      <h2>{{ saved ? `Edit ${saved.alias}` : 'Add host' }}</h2>

      <template v-if="savedWithoutSftp">
        <p>Saved.</p>
        <p class="notice">Files unavailable on this host (no SFTP); terminals work.</p>
        <div class="actions">
          <button class="primary" @click="emit('close')">Close</button>
        </div>
      </template>

      <form v-else @submit.prevent="save">
        <div class="grid2">
          <label>
            Alias
            <input v-model="form.alias" required pattern="[a-z0-9][a-z0-9._\-]{0,62}" placeholder="home" />
          </label>
          <label>
            Name <span class="muted">(optional)</span>
            <input v-model="form.name" placeholder="Home server" />
          </label>
          <label>
            Address
            <input v-model="form.address" required placeholder="10.0.0.2 or host.example" />
          </label>
          <label>
            Port
            <input v-model.number="form.port" type="number" min="1" max="65535" required />
          </label>
          <label>
            Username
            <input v-model="form.username" required autocomplete="off" />
          </label>
        </div>

        <fieldset>
          <legend>Authentication</legend>
          <label class="inline"><input v-model="form.authKind" type="radio" value="key" /> Private key</label>
          <label class="inline"><input v-model="form.authKind" type="radio" value="password" /> Password</label>
          <template v-if="form.authKind === 'key'">
            <p v-if="keepsCredential" class="muted">
              Saved key {{ saved?.keyLabel ?? '' }} <code>{{ saved?.keyFingerprint }}</code>.
            </p>
            <div class="key-picker">
              <select v-model="form.keyChoice">
                <option v-if="!(keepsCredential && saved?.keyId)" value="" :disabled="!keepsCredential">
                  {{ keepsCredential ? 'Keep the saved key' : 'Choose a key…' }}
                </option>
                <option v-for="k in keys" :key="k.id" :value="k.id">{{ k.label }} ({{ k.fingerprint }})</option>
                <option :value="IMPORT_KEY">Import a new key…</option>
              </select>
              <button type="button" title="Reload the key library" @click="loadKeys">Refresh</button>
              <a href="/keys" target="_blank" rel="noopener">Manage keys</a>
            </div>
            <p v-if="keysError" class="error">{{ keysError }}</p>
            <PublicKeyBox v-if="selectedKey" :public-key="selectedKey.publicKey" />
            <template v-if="form.keyChoice === IMPORT_KEY">
              <textarea
                v-model="form.privateKey"
                rows="5"
                spellcheck="false"
                autocomplete="off"
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
              />
              <label>
                Passphrase <span class="muted">(optional)</span>
                <input v-model="form.passphrase" type="password" autocomplete="off" />
              </label>
              <label>
                Key label <span class="muted">(optional, for the key library)</span>
                <input v-model="form.keyLabel" autocomplete="off" />
              </label>
            </template>
          </template>
          <template v-else>
            <p v-if="keepsCredential" class="muted">Password saved. Leave empty to keep it.</p>
            <input v-model="form.password" type="password" autocomplete="off" placeholder="Password" />
          </template>
        </fieldset>

        <fieldset>
          <legend>Host key</legend>
          <p v-if="saved" class="muted">
            Pinned: {{ saved.hostKeyType }} <code>{{ saved.hostKeyFingerprint }}</code>
          </p>
          <button type="button" :disabled="busy || !form.address.trim()" @click="checkHostKey">
            {{ saved && !endpointChanged ? 'Re-verify host key' : 'Check host key' }}
          </button>
          <p v-if="probeError" class="error">{{ probeError }}</p>
          <div v-if="probeCurrent" class="probe">
            <div>Endpoint: <code>{{ probeCurrent.endpoint }}</code></div>
            <div>Key type: <code>{{ probeCurrent.keyType }}</code></div>
            <div>Fingerprint: <code class="fingerprint">{{ probeCurrent.fingerprint }}</code></div>
            <p>
              Compare this fingerprint with one you obtain independently, for example by running
              <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code> on the target itself. Do not continue if
              they differ.
            </p>
            <label class="inline"><input v-model="verified" type="checkbox" /> I verified this fingerprint</label>
          </div>
        </fieldset>

        <p v-if="saveError" class="error">{{ saveError }}</p>
        <div class="actions">
          <button v-if="saved" type="button" class="danger" :disabled="busy" @click="remove">Delete host</button>
          <span class="spacer" />
          <span v-if="blocker" class="muted">{{ blocker }}</span>
          <button type="button" @click="emit('close')">Cancel</button>
          <button type="submit" class="primary" :disabled="busy || !!blocker">{{ busy ? 'Working…' : 'Save' }}</button>
        </div>
      </form>
    </div>
  </div>
</template>

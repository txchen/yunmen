<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, ApiError, type Pairing } from '../api'
import { auth, refreshSession } from '../auth'
import { formatTime } from '../format'

const route = useRoute()
const router = useRouter()

const raw = ref(typeof route.query.code === 'string' ? route.query.code.toUpperCase() : '')
const pairing = ref<Pairing | null>(null)
const password = ref('')
const totp = ref('')
const busy = ref(false)
const error = ref('')
const result = ref('')

// Accepts "k7qm2xpa", "K7QM-2XPA" or stray spaces, and sends the canonical dashed form.
const userCode = computed(() => {
  const c = raw.value.toUpperCase().replace(/[^A-Z0-9]/g, '')
  return c.length === 8 ? `${c.slice(0, 4)}-${c.slice(4)}` : c
})

function onCodeInput(e: Event) {
  raw.value = (e.target as HTMLInputElement).value.toUpperCase()
}

function message(err: unknown, notFound: string): string {
  if (err instanceof ApiError && err.status === 404) return notFound
  if (err instanceof ApiError && err.status === 429) return 'Too many failed attempts. Wait a few minutes.'
  return err instanceof Error ? err.message : String(err)
}

async function lookup() {
  busy.value = true
  error.value = ''
  result.value = ''
  pairing.value = null
  try {
    pairing.value = await api.lookupPairing(userCode.value)
  } catch (err) {
    error.value = message(err, 'No pending request with that code. It may have expired; run `yunmen login` again.')
  } finally {
    busy.value = false
  }
}

async function approve() {
  if (!pairing.value) return
  busy.value = true
  error.value = ''
  try {
    await api.approvePairing(pairing.value.userCode, password.value, totp.value.trim())
    result.value = `Approved "${pairing.value.label}". The CLI will finish signing in shortly.`
    reset()
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      await refreshSession()
      if (!auth.session) {
        await router.push({ name: 'login', query: { redirect: route.fullPath } })
        return
      }
      error.value = 'Wrong password or code.'
    } else {
      error.value = message(err, 'The request is gone. It may have expired or been answered already.')
    }
    totp.value = ''
  } finally {
    busy.value = false
  }
}

async function deny() {
  if (!pairing.value) return
  busy.value = true
  error.value = ''
  try {
    await api.denyPairing(pairing.value.userCode)
    result.value = `Denied "${pairing.value.label}".`
    reset()
  } catch (err) {
    error.value = message(err, 'The request is gone. It may have expired or been answered already.')
  } finally {
    busy.value = false
  }
}

function reset() {
  pairing.value = null
  password.value = ''
  totp.value = ''
  raw.value = ''
}
</script>

<template>
  <div class="page narrow-page">
    <h1>Approve a CLI device</h1>
    <p v-if="result" class="notice">{{ result }}</p>

    <form v-if="!pairing" class="card" @submit.prevent="lookup">
      <label>
        Code shown by the CLI
        <input
          :value="raw"
          class="code-input"
          autocomplete="off"
          spellcheck="false"
          placeholder="K7QM-2XPA"
          maxlength="12"
          required
          @input="onCodeInput"
        />
      </label>
      <p v-if="error" class="error">{{ error }}</p>
      <button class="primary" type="submit" :disabled="busy || userCode.length < 9">Look up</button>
    </form>

    <form v-else class="card" @submit.prevent="approve">
      <dl class="facts">
        <dt>Code</dt>
        <dd><code>{{ pairing.userCode }}</code></dd>
        <dt>Device label</dt>
        <dd>{{ pairing.label }}</dd>
        <dt>Requested</dt>
        <dd>{{ formatTime(pairing.requestedAt) }}</dd>
        <dt>Expires</dt>
        <dd>{{ formatTime(pairing.expiresAt) }}</dd>
        <dt>Service principal</dt>
        <dd><code>{{ pairing.servicePrincipal }}</code></dd>
      </dl>
      <p class="warning">Only approve if you just ran <code>yunmen login</code> yourself.</p>
      <label>
        Password
        <input v-model="password" type="password" autocomplete="current-password" required />
      </label>
      <label>
        Authenticator code
        <input v-model="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required />
      </label>
      <p v-if="error" class="error">{{ error }}</p>
      <div class="actions">
        <button type="button" @click="reset">Back</button>
        <span class="spacer" />
        <button type="button" class="danger" :disabled="busy" @click="deny">Deny</button>
        <button type="submit" class="primary" :disabled="busy">Approve</button>
      </div>
    </form>
  </div>
</template>

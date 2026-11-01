<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, ApiError } from '../api'
import { auth, refreshSession } from '../auth'
import { copyText } from '../clipboard'

const route = useRoute()
const router = useRouter()
const password = ref('')
const totp = ref('')
const busy = ref(false)
const error = ref('')
const codes = ref<string[]>([])
const copyStatus = ref('')

const remaining = computed(() => auth.session?.recoveryCodesRemaining ?? 0)
const codesText = computed(() => codes.value.join('\n') + '\n')

async function regenerate() {
  busy.value = true
  error.value = ''
  copyStatus.value = ''
  try {
    const res = await api.regenerateRecoveryCodes(password.value, totp.value.trim())
    codes.value = res.codes
    password.value = ''
    await refreshSession()
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      await refreshSession()
      if (!auth.session) {
        await router.push({ name: 'login', query: { redirect: route.fullPath } })
        return
      }
      error.value = 'Wrong password or code.'
    } else if (err instanceof ApiError && err.status === 429) {
      error.value = 'Too many failed attempts. Wait a few minutes.'
    } else {
      error.value = err instanceof Error ? err.message : String(err)
    }
  } finally {
    totp.value = ''
    busy.value = false
  }
}

async function copyAll() {
  copyStatus.value = await copyText(codesText.value)
}

function download() {
  const url = URL.createObjectURL(new Blob([codesText.value], { type: 'text/plain' }))
  const a = document.createElement('a')
  a.href = url
  a.download = 'yunmen-recovery-codes.txt'
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
</script>

<template>
  <div class="page narrow-page">
    <h1>Settings</h1>
    <h2>Recovery codes</h2>
    <p :class="remaining <= 3 ? 'warning' : ''">
      Recovery codes remaining: {{ remaining }}<template v-if="remaining <= 3">. Generate new codes before you run out.</template>
    </p>

    <div v-if="codes.length" class="card">
      <p class="warning">
        Save these codes now. They are shown only once, and the old codes no longer work.
      </p>
      <div class="code-grid">
        <code v-for="c in codes" :key="c">{{ c }}</code>
      </div>
      <div class="actions">
        <button type="button" @click="copyAll">Copy all</button>
        <button type="button" @click="download">Download as .txt</button>
        <span v-if="copyStatus" class="small">{{ copyStatus }}</span>
      </div>
    </div>

    <form class="card" @submit.prevent="regenerate">
      <p class="muted small">Generating new codes replaces all existing ones.</p>
      <label>
        Password
        <input v-model="password" type="password" autocomplete="current-password" required />
      </label>
      <label>
        Authenticator code
        <input v-model="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required />
      </label>
      <p v-if="error" class="error">{{ error }}</p>
      <button class="primary" type="submit" :disabled="busy">
        {{ busy ? 'Working…' : 'Generate new recovery codes' }}
      </button>
    </form>
  </div>
</template>

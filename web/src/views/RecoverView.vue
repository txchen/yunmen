<script setup lang="ts">
import { ref } from 'vue'
import QRCode from 'qrcode'
import { api, ApiError, type RecoveryChallenge } from '../api'
import { auth } from '../auth'
import { formatTime } from '../format'

const step = ref<'start' | 'enroll' | 'done'>('start')
const password = ref('')
const recoveryCode = ref('')
const code = ref('')
const challenge = ref<RecoveryChallenge | null>(null)
const qr = ref('')
const busy = ref(false)
const error = ref('')

function describe(err: unknown, wrong: string): string {
  if (!(err instanceof ApiError)) return 'Cannot reach the server.'
  if (err.status === 401) return wrong
  if (err.status === 429) return 'Too many failed attempts. Wait a few minutes and try again.'
  if (err.status === 403) return 'Cloudflare Access assertion missing. Reload the page to sign in through Access.'
  return err.message
}

async function start() {
  busy.value = true
  error.value = ''
  try {
    const c = await api.startRecovery(password.value, recoveryCode.value.trim())
    qr.value = await QRCode.toDataURL(c.otpauthUri, { margin: 2, width: 220 })
    challenge.value = c
    password.value = ''
    step.value = 'enroll'
  } catch (err) {
    error.value = describe(err, 'Wrong password or recovery code.')
  } finally {
    busy.value = false
  }
}

async function finish() {
  if (!challenge.value) return
  busy.value = true
  error.value = ''
  try {
    await api.finishRecovery(challenge.value.challengeId, code.value.trim())
    auth.session = null
    step.value = 'done'
  } catch (err) {
    if (err instanceof ApiError && err.status === 410) {
      restart('This recovery attempt expired or the recovery code was already used. Start again.')
      return
    }
    error.value = describe(err, 'Wrong code. Check that the authenticator shows the new Yunmen entry.')
  } finally {
    code.value = ''
    busy.value = false
  }
}

function restart(message = '') {
  challenge.value = null
  qr.value = ''
  recoveryCode.value = ''
  step.value = 'start'
  error.value = message
}
</script>

<template>
  <div class="center">
    <form v-if="step === 'start'" class="card narrow" @submit.prevent="start">
      <h1>Replace authenticator</h1>
      <p class="muted small">Use one of the recovery codes you saved at setup. It does not sign you in by itself.</p>
      <label>
        Password
        <input v-model="password" type="password" autocomplete="current-password" required autofocus />
      </label>
      <label>
        Recovery code
        <input
          v-model="recoveryCode"
          class="code-input"
          autocomplete="off"
          spellcheck="false"
          placeholder="XXXXX-XXXXX"
          required
        />
      </label>
      <p v-if="error" class="error">{{ error }}</p>
      <div class="actions">
        <RouterLink to="/login">Back to sign in</RouterLink>
        <span class="spacer" />
        <button class="primary" type="submit" :disabled="busy">{{ busy ? 'Checking…' : 'Continue' }}</button>
      </div>
    </form>

    <form v-else-if="step === 'enroll' && challenge" class="card narrow" @submit.prevent="finish">
      <h1>Set up the new authenticator</h1>
      <p class="muted small">Scan this code with your authenticator app, or enter the secret manually.</p>
      <img class="qr" :src="qr" alt="QR code for the new authenticator" />
      <label>
        Secret
        <input :value="challenge.secret" class="secret" readonly spellcheck="false" />
      </label>
      <p class="muted small">Finish before {{ formatTime(challenge.expiresAt) }}.</p>
      <label>
        Code from the new authenticator
        <input
          v-model="code"
          inputmode="numeric"
          autocomplete="one-time-code"
          pattern="[0-9]{6}"
          maxlength="6"
          placeholder="123456"
          required
        />
      </label>
      <p v-if="error" class="error">{{ error }}</p>
      <div class="actions">
        <button type="button" @click="restart()">Start over</button>
        <span class="spacer" />
        <button class="primary" type="submit" :disabled="busy">{{ busy ? 'Checking…' : 'Replace authenticator' }}</button>
      </div>
    </form>

    <div v-else class="card narrow">
      <h1>Done</h1>
      <p class="notice">
        Authenticator replaced. All sessions and CLI devices were signed out; sign in with your new code.
      </p>
      <div class="actions">
        <span class="spacer" />
        <RouterLink v-slot="{ navigate }" to="/login" custom>
          <button class="primary" @click="navigate">Sign in</button>
        </RouterLink>
      </div>
    </div>
  </div>
</template>

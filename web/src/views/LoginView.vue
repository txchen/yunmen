<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, ApiError } from '../api'
import { auth, refreshSession, safeRedirect } from '../auth'

const route = useRoute()
const router = useRouter()
const password = ref('')
const code = ref('')
const busy = ref(false)
const error = ref('')

const loginErrors: Record<number, string> = {
  401: 'Wrong password or code.',
  429: 'Too many failed attempts. Wait a few minutes and try again.',
  503: 'The owner account is not initialized on the server yet.',
}

async function submit() {
  busy.value = true
  error.value = ''
  try {
    await api.login(password.value, code.value.trim())
    await refreshSession()
    await router.replace(safeRedirect(route.query.redirect))
  } catch (err) {
    if (err instanceof ApiError && err.status === 403) auth.problem = 'access'
    else if (err instanceof ApiError) error.value = loginErrors[err.status] ?? err.message
    else error.value = 'Cannot reach the server.'
    code.value = ''
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="center">
    <form class="card narrow" @submit.prevent="submit">
      <h1>Yunmen</h1>
      <label>
        Password
        <input v-model="password" type="password" autocomplete="current-password" required autofocus />
      </label>
      <label>
        Authenticator code
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
      <button class="primary" type="submit" :disabled="busy">{{ busy ? 'Signing in…' : 'Sign in' }}</button>
    </form>
  </div>
</template>

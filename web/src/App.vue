<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { auth, refreshSession, signOut as endSession } from './auth'
import { formatTime } from './format'
import { workspace } from './workspace'

const route = useRoute()
const router = useRouter()

const signingOut = ref(false)
const signOutError = ref('')

// Expiry, recovery and explicit logout all discard the previous workspace.
watch(
  () => auth.session,
  (session) => {
    if (!session) {
      workspace.reset()
      signOutError.value = ''
    }
  },
  { flush: 'sync' },
)

// A sign-out error refers to the page where it happened.
watch(
  () => route.fullPath,
  () => {
    signOutError.value = ''
  },
)

async function signOut() {
  signingOut.value = true
  signOutError.value = ''
  try {
    await endSession()
    await router.push({ name: 'login' })
  } catch {
    signOutError.value = 'Could not sign out. Your session may still be active. Try again.'
  } finally {
    signingOut.value = false
  }
}

function reload() {
  location.reload()
}

async function retry() {
  await refreshSession()
  if (!auth.problem) {
    await router.replace(
      auth.session || route.meta.public ? route.fullPath : { name: 'login', query: { redirect: route.fullPath } },
    )
  }
}
</script>

<template>
  <div v-if="auth.problem === 'access'" class="fatal">
    <h1>Cloudflare Access assertion missing</h1>
    <p>
      Yunmen did not receive a valid Cloudflare Access assertion with this request (HTTP 403). Reload the page to sign
      in through Cloudflare Access again. If this persists, check that this hostname is protected by the Access
      application Yunmen expects.
    </p>
    <button class="primary" @click="reload">Reload</button>
  </div>
  <div v-else-if="auth.problem === 'unreachable'" class="fatal">
    <h1>Cannot reach the Yunmen server</h1>
    <p>The session check failed. The server may be restarting.</p>
    <button class="primary" @click="retry">Retry</button>
  </div>
  <div v-else class="app">
    <header v-if="auth.session && route.name !== 'login'" class="topbar">
      <span class="brand">Yunmen</span>
      <nav>
        <RouterLink to="/hosts">Hosts</RouterLink>
        <RouterLink to="/keys">Keys</RouterLink>
        <RouterLink to="/devices">Devices</RouterLink>
        <RouterLink to="/approve">Approve device</RouterLink>
        <RouterLink to="/settings">Settings</RouterLink>
      </nav>
      <span class="spacer" />
      <span class="muted">Session expires {{ formatTime(auth.session.expiresAt) }}</span>
      <button :disabled="signingOut" @click="signOut">{{ signingOut ? 'Signing out…' : 'Sign out' }}</button>
    </header>
    <main class="content">
      <p v-if="signOutError" class="error" role="alert">{{ signOutError }}</p>
      <RouterView v-slot="{ Component }">
        <KeepAlive :key="auth.session ? 'signed-in' : 'signed-out'" include="WorkspaceView">
          <component :is="Component" v-if="auth.session || route.meta.public" />
        </KeepAlive>
      </RouterView>
    </main>
  </div>
</template>

<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router'
import { api } from './api'
import { auth, refreshSession } from './auth'
import { formatTime } from './format'
import { workspace } from './workspace'

const route = useRoute()
const router = useRouter()

async function signOut() {
  try {
    await api.logout()
  } catch {
    // The session is discarded locally either way.
  }
  workspace.reset()
  auth.session = null
  await router.push({ name: 'login' })
}

function reload() {
  location.reload()
}

async function retry() {
  await refreshSession()
  if (!auth.problem) await router.replace(route.fullPath)
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
        <RouterLink to="/devices">Devices</RouterLink>
        <RouterLink to="/approve">Approve device</RouterLink>
      </nav>
      <span class="spacer" />
      <span class="muted">Session expires {{ formatTime(auth.session.expiresAt) }}</span>
      <button @click="signOut">Sign out</button>
    </header>
    <main class="content">
      <RouterView v-slot="{ Component }">
        <KeepAlive include="WorkspaceView">
          <component :is="Component" />
        </KeepAlive>
      </RouterView>
    </main>
  </div>
</template>

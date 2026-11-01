<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, type Device } from '../api'
import { formatTime } from '../format'

const devices = ref<Device[]>([])
const error = ref('')
const notice = ref('')

async function load() {
  try {
    devices.value = await api.devices()
    error.value = ''
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  }
}

async function revoke(d: Device) {
  if (!confirm(`Revoke device "${d.label}"? Its CLI token stops working and its terminals are closed.`)) return
  try {
    const { closedTerminals } = await api.revokeDevice(d.id)
    notice.value = `Revoked "${d.label}". Closed ${closedTerminals} terminal${closedTerminals === 1 ? '' : 's'}.`
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  }
  await load()
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="page-head">
      <h1>Devices</h1>
      <button @click="load">Refresh</button>
    </div>
    <p v-if="notice" class="notice">{{ notice }}</p>
    <p v-if="error" class="error">{{ error }}</p>
    <table class="table">
      <thead>
        <tr>
          <th>Label</th>
          <th>Service principal</th>
          <th>Authorized</th>
          <th>Expires</th>
          <th>Last used</th>
          <th>Status</th>
          <th class="num">Active terminals</th>
          <th />
        </tr>
      </thead>
      <tbody>
        <tr v-for="d in devices" :key="d.id">
          <td>{{ d.label }}</td>
          <td><code>{{ d.servicePrincipal }}</code></td>
          <td>{{ formatTime(d.authorizedAt) }}</td>
          <td>{{ formatTime(d.expiresAt) }}</td>
          <td>{{ d.lastUsedAt ? formatTime(d.lastUsedAt) : 'never' }}</td>
          <td><span class="badge" :class="d.status">{{ d.status }}</span></td>
          <td class="num">{{ d.activeTerminals }}</td>
          <td><button v-if="d.status === 'active'" class="danger" @click="revoke(d)">Revoke</button></td>
        </tr>
        <tr v-if="devices.length === 0">
          <td colspan="8" class="muted">No devices. Run <code>yunmen login</code> on a machine to pair one.</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

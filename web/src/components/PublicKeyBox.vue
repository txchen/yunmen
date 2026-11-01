<script setup lang="ts">
import { ref, watch } from 'vue'
import { copyText } from '../clipboard'

const props = defineProps<{ publicKey: string }>()
const status = ref('')

watch(
  () => props.publicKey,
  () => {
    status.value = ''
  },
)

async function copy() {
  status.value = await copyText(props.publicKey)
}
</script>

<template>
  <div class="pubkey">
    <textarea :value="publicKey" readonly rows="3" spellcheck="false" @focus="($event.target as HTMLTextAreaElement).select()" />
    <div class="actions">
      <button type="button" @click="copy">Copy</button>
      <span v-if="status" class="small">{{ status }}</span>
      <span class="muted small">Add this line to <code>~/.ssh/authorized_keys</code> on each target host.</span>
    </div>
  </div>
</template>

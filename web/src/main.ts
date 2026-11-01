import { createApp } from 'vue'
import '@xterm/xterm/css/xterm.css'
import './style.css'
import App from './App.vue'
import { router } from './router'

createApp(App).use(router).mount('#app')

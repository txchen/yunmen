import { createRouter, createWebHistory } from 'vue-router'
import { onUnauthorized } from './api'
import { auth, refreshSession, safeRedirect } from './auth'
import LoginView from './views/LoginView.vue'
import WorkspaceView from './views/WorkspaceView.vue'
import DevicesView from './views/DevicesView.vue'
import ApproveView from './views/ApproveView.vue'
import KeysView from './views/KeysView.vue'
import SettingsView from './views/SettingsView.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/hosts' },
    { path: '/login', name: 'login', component: LoginView, meta: { public: true } },
    { path: '/recover', name: 'recover', component: () => import('./views/RecoverView.vue'), meta: { public: true } },
    { path: '/hosts', name: 'hosts', component: WorkspaceView },
    { path: '/devices', name: 'devices', component: DevicesView },
    { path: '/approve', name: 'approve', component: ApproveView },
    { path: '/keys', name: 'keys', component: KeysView },
    { path: '/settings', name: 'settings', component: SettingsView },
    { path: '/:rest(.*)*', redirect: '/hosts' },
  ],
})

router.beforeEach(async (to) => {
  if (!auth.checked) await refreshSession()
  if (to.name === 'login' && auth.session) return safeRedirect(to.query.redirect)
  if (to.meta.public || auth.problem) return true
  if (!auth.session) return { name: 'login', query: { redirect: to.fullPath } }
  return true
})

onUnauthorized(() => {
  auth.session = null
  const current = router.currentRoute.value
  if (current.name !== 'login') void router.push({ name: 'login', query: { redirect: current.fullPath } })
})

import axios from 'axios'

const rawBaseUrl =
  import.meta.env.VITE_API_URL ||
  import.meta.env.VITE_BACKEND_URL ||
  '/api'

const baseURL = rawBaseUrl.endsWith('/') ? rawBaseUrl.slice(0, -1) : rawBaseUrl

const api = axios.create({
  baseURL,
  timeout: 60000,
  withCredentials: true, // Required for HttpOnly cookie auth
})

// Core analysis
export const analyzeURL     = (url)  => api.post('/analyze/url',     { url })
export const analyzeMessage = (text) => api.post('/analyze/message',  { text })
export const analyzeEmail   = (data) => api.post('/analyze/email',    data)

// QR code — multipart
export const analyzeQR = (formData) =>
  api.post('/analyze/qr', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 60000,
  })

// File upload — multipart
export const analyzeFile = (formData) =>
  api.post('/analyze/file', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 60000,
  })

// History
export const getHistory    = (limit = 50, scanType = null) =>
  api.get(`/history?limit=${limit}${scanType ? `&scan_type=${scanType}` : ''}`)
export const getScanDetail = (id)   => api.get(`/history/${id}`)
export const clearHistory  = ()     => api.delete('/history')

// Stats + Demo
export const getStats       = ()   => api.get('/stats')
export const getEvaluation  = ()   => api.get('/evaluation')
export const getDemoCases   = ()   => api.get('/demo-cases')
export const runDemoCase    = (id) => api.post(`/demo-cases/${id}/run`)

// System
export const getHealth    = ()  => api.get('/health')
export const getReadiness = ()  => api.get('/readiness')

// Theme settings (public)
export const getThemeSettings = () => api.get('/settings/theme')

// ── Auth ──────────────────────────────────────────────────────────────────
export const authLogin        = (username, password) => api.post('/auth/login', { username, password })
export const authLogout       = ()                   => api.post('/auth/logout')
export const authMe           = ()                   => api.get('/auth/me')
export const authChangePassword = (current_password, new_password) =>
  api.post('/auth/change-password', { current_password, new_password })

// ── Admin ─────────────────────────────────────────────────────────────────
export const adminDashboardStats = () => api.get('/admin/dashboard-stats')
export const adminProfile        = () => api.get('/admin/profile')
export const adminNotifications  = () => api.get('/admin/notifications')
export const adminMarkRead       = (id) => api.post(`/admin/notifications/${id}/read`)

// ── Super Admin ───────────────────────────────────────────────────────────
export const superAdminStats       = ()       => api.get('/superadmin/stats')
export const superAdminUsers       = ()       => api.get('/superadmin/users')
export const superAdminCreateUser  = (data)   => api.post('/superadmin/users', data)
export const superAdminGetUser     = (id)     => api.get(`/superadmin/users/${id}`)
export const superAdminUpdateUser  = (id, d)  => api.patch(`/superadmin/users/${id}`, d)
export const superAdminResetPw     = (id)     => api.post(`/superadmin/users/${id}/reset-password`)
export const superAdminDeleteUser  = (id)     => api.delete(`/superadmin/users/${id}`)
export const superAdminAuditLog    = (limit)  => api.get(`/superadmin/audit-log?limit=${limit || 100}`)
export const superAdminSessions    = ()       => api.get('/superadmin/sessions')
export const superAdminRevokeSession = (id)   => api.post(`/superadmin/sessions/${id}/revoke`)
export const superAdminGetSettings = ()       => api.get('/superadmin/settings')
export const superAdminUpdateTheme = (data)   => api.patch('/superadmin/settings/theme', data)
export const superAdminSystemHealth = ()      => api.get('/superadmin/system-health')
export const superAdminGetIntegrations = ()   => api.get('/superadmin/integrations')
export const superAdminUpdateIntegrations = (d) => api.patch('/superadmin/integrations', d)
export const superAdminGetFeatures = ()       => api.get('/superadmin/features')
export const superAdminUpdateFeatures = (d)   => api.patch('/superadmin/features', d)
export const superAdminGetErrors = (limit)    => api.get(`/superadmin/errors?limit=${limit || 50}`)


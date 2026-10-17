import axios from 'axios'

const rawBaseUrl =
  import.meta.env.VITE_API_URL ||
  (import.meta.env.PROD ? 'https://scamshield-yj85.onrender.com' : '/api')

const baseURL = rawBaseUrl.endsWith('/') ? rawBaseUrl.slice(0, -1) : rawBaseUrl

const api = axios.create({
  baseURL,
  timeout: 30000, // 30 second timeout
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
export const getStats    = ()   => api.get('/stats')
export const getDemoCases = ()  => api.get('/demo-cases')
export const runDemoCase  = (id) => api.post(`/demo-cases/${id}/run`)

// System
export const getHealth    = ()  => api.get('/health')
export const getReadiness = ()  => api.get('/readiness')

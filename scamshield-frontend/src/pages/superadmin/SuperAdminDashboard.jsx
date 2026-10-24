import React, { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Users, LogOut, Plus, Trash2, Edit2, RefreshCcw,
  Lock, Unlock, AlertTriangle, CheckCircle, Activity, Database,
  BarChart2, Settings, Clock, Eye, EyeOff, X, Save,
  Terminal, Bell, ChevronRight, Key, ShieldOff, ShieldCheck,
  Cpu, Server, Sliders, Globe, Radio, AlertOctagon, CheckCircle2,
  HardDrive
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext'
import { useTheme } from '../../context/ThemeContext'
import {
  superAdminStats, superAdminUsers, superAdminCreateUser,
  superAdminUpdateUser, superAdminResetPw, superAdminDeleteUser,
  superAdminAuditLog, superAdminGetSettings, superAdminUpdateTheme,
  superAdminSystemHealth, superAdminGetIntegrations, superAdminUpdateIntegrations,
  superAdminGetFeatures, superAdminUpdateFeatures, superAdminGetErrors,
  authChangePassword
} from '../../api'
import { ALL_PERMISSIONS } from '../../utils'

// ── Helpers ────────────────────────────────────────────────────────────────
function StatCard({ label, value, color = '#22d3ee', icon: Icon, sub }) {
  return (
    <div className="glass" style={{
      borderRadius: 12, padding: '16px 18px',
      borderColor: `${color}22`,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <span style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</span>
        {Icon && <Icon size={14} style={{ color }} />}
      </div>
      <div style={{ fontSize: '1.8rem', fontWeight: 900, color }}>{value ?? '—'}</div>
      {sub && <div style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.3)', marginTop: 2 }}>{sub}</div>}
    </div>
  )
}

function TabBtn({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      style={{
        background: active ? 'rgba(34,211,238,0.12)' : 'transparent',
        border: active ? '1px solid rgba(34,211,238,0.35)' : '1px solid transparent',
        color: active ? '#22d3ee' : 'rgba(255,255,255,0.5)',
        borderRadius: 10, padding: '8px 14px', cursor: 'pointer',
        fontSize: '0.82rem', fontWeight: active ? 700 : 400,
        transition: 'all 0.2s', whiteSpace: 'nowrap',
        display: 'flex', alignItems: 'center', gap: 6,
      }}
    >
      {children}
    </button>
  )
}

// Permission labels
const PERM_LABELS = {
  view_stats: 'View Statistics',
  view_history: 'View Scan History',
  clear_history: 'Clear Scan History',
  manage_users: 'Manage Users',
  view_audit_log: 'View Audit Log',
  manage_settings: 'Manage Settings',
  view_errors: 'View Errors',
  view_analytics: 'View Analytics',
  manage_integrations: 'Manage Integrations',
}

// ── Modal: Create Admin ────────────────────────────────────────────────────
function CreateAdminModal({ onClose, onCreated }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [email, setEmail] = useState('')
  const [permissions, setPermissions] = useState(['view_stats', 'view_history', 'view_analytics'])
  const [showPw, setShowPw] = useState(false)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState(null)

  const togglePerm = (p) => {
    setPermissions(prev => prev.includes(p) ? prev.filter(x => x !== p) : [...prev, p])
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSubmitting(true)
    try {
      const res = await superAdminCreateUser({ username, password, email: email || undefined, permissions })
      setResult(res.data)
      onCreated()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to create admin.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', zIndex: 300,
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20,
      backdropFilter: 'blur(6px)',
    }}>
      <div className="glass" style={{
        width: '100%', maxWidth: 480, borderRadius: 20, padding: 26,
        border: '1px solid rgba(34,211,238,0.25)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 800, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Plus size={18} style={{ color: '#22d3ee' }} /> Create Administrator
          </h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.4)', cursor: 'pointer' }}>
            <X size={18} />
          </button>
        </div>

        {result ? (
          <div>
            <div style={{ textAlign: 'center', padding: '16px 0' }}>
              <CheckCircle size={36} style={{ color: '#10b981', margin: '0 auto 10px', display: 'block' }} />
              <p style={{ fontWeight: 700, marginBottom: 4 }}>Admin created successfully!</p>
              <p style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.4)', marginBottom: 16 }}>
                Username: <strong style={{ color: '#22d3ee' }}>{username}</strong>
              </p>
            </div>
            <button className="btn-primary" onClick={onClose} style={{ width: '100%' }}>Done</button>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: 12 }}>
              <label style={{ display: 'block', fontSize: '0.74rem', color: 'rgba(255,255,255,0.45)', marginBottom: 6, textTransform: 'uppercase' }}>Username</label>
              <input type="text" className="input-field" value={username} onChange={e => setUsername(e.target.value)} placeholder="e.g. sec_officer" required />
            </div>

            <div style={{ marginBottom: 12 }}>
              <label style={{ display: 'block', fontSize: '0.74rem', color: 'rgba(255,255,255,0.45)', marginBottom: 6, textTransform: 'uppercase' }}>Initial Password</label>
              <div style={{ position: 'relative' }}>
                <input type={showPw ? 'text' : 'password'} className="input-field" style={{ paddingRight: 40 }} value={password} onChange={e => setPassword(e.target.value)} placeholder="Min 8 characters" required />
                <button type="button" onClick={() => setShowPw(s => !s)} style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'rgba(255,255,255,0.4)', cursor: 'pointer' }}>
                  {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: '0.74rem', color: 'rgba(255,255,255,0.45)', marginBottom: 6, textTransform: 'uppercase' }}>Email (Optional)</label>
              <input type="email" className="input-field" value={email} onChange={e => setEmail(e.target.value)} placeholder="admin@domain.com" />
            </div>

            <div style={{ marginBottom: 18 }}>
              <label style={{ display: 'block', fontSize: '0.74rem', color: 'rgba(255,255,255,0.45)', marginBottom: 8, textTransform: 'uppercase' }}>Module Permissions</label>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                {Object.entries(PERM_LABELS).map(([perm, label]) => (
                  <label key={perm} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.78rem', color: 'rgba(255,255,255,0.7)', cursor: 'pointer' }}>
                    <input type="checkbox" checked={permissions.includes(perm)} onChange={() => togglePerm(perm)} />
                    <span>{label}</span>
                  </label>
                ))}
              </div>
            </div>

            {error && (
              <div style={{ background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)', borderRadius: 10, padding: '10px 14px', marginBottom: 14, fontSize: '0.82rem', color: '#ff2d55' }}>
                {error}
              </div>
            )}

            <div style={{ display: 'flex', gap: 10 }}>
              <button type="button" className="btn-ghost" onClick={onClose} style={{ flex: 1 }}>Cancel</button>
              <button type="submit" className="btn-primary" disabled={submitting} style={{ flex: 1 }}>
                {submitting ? 'Creating…' : 'Create Admin'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

// ── Main SuperAdmin Dashboard ──────────────────────────────────────────────
export default function SuperAdminDashboard() {
  const navigate = useNavigate()
  const { user, logout, loading } = useAuth()
  const { setTheme: applyThemeContext } = useTheme()

  const [tab, setTab] = useState('overview')
  const [stats, setStats] = useState(null)
  const [users, setUsers] = useState([])
  const [auditLog, setAuditLog] = useState([])
  const [settings, setSettings] = useState(null)
  const [systemHealth, setSystemHealth] = useState(null)
  const [integrations, setIntegrations] = useState(null)
  const [features, setFeatures] = useState(null)
  const [errorLog, setErrorLog] = useState([])

  const [pageLoading, setPageLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [actionMsg, setActionMsg] = useState('')
  const [lastRefresh, setLastRefresh] = useState(null)

  // Password change state
  const [cpCurrentPw, setCpCurrentPw] = useState('')
  const [cpNewPw, setCpNewPw] = useState('')
  const [cpConfirmPw, setCpConfirmPw] = useState('')
  const [cpError, setCpError] = useState('')
  const [cpSuccess, setCpSuccess] = useState(false)
  const [cpSubmitting, setCpSubmitting] = useState(false)

  // Theme slider state
  const [neonGlow, setNeonGlow] = useState(0.35)
  const [bgOverlay, setBgOverlay] = useState(0.72)
  const [animIntensity, setAnimIntensity] = useState(1.0)

  // Integrations form state
  const [vtKey, setVtKey] = useState('')
  const [sbKey, setSbKey] = useState('')
  const [abuseKey, setAbuseKey] = useState('')

  useEffect(() => {
    if (!loading && (!user || user.role !== 'superadmin')) {
      navigate('/admin/login', { replace: true })
    }
  }, [user, loading, navigate])

  const fetchAll = useCallback(async () => {
    try {
      const [statsRes, usersRes, settingsRes, healthRes] = await Promise.allSettled([
        superAdminStats(),
        superAdminUsers(),
        superAdminGetSettings(),
        superAdminSystemHealth(),
      ])
      if (statsRes.status === 'fulfilled') setStats(statsRes.value.data)
      if (usersRes.status === 'fulfilled') setUsers(usersRes.value.data)
      if (settingsRes.status === 'fulfilled') {
        const s = settingsRes.value.data
        setSettings(s)
        if (s.neon_glow_intensity) setNeonGlow(parseFloat(s.neon_glow_intensity))
        if (s.bg_overlay_strength) setBgOverlay(parseFloat(s.bg_overlay_strength))
        if (s.animation_intensity) setAnimIntensity(parseFloat(s.animation_intensity))
      }
      if (healthRes.status === 'fulfilled') setSystemHealth(healthRes.value.data)
      setLastRefresh(new Date())
    } catch { /* silent */ }
    finally { setPageLoading(false) }
  }, [])

  const fetchAuditLog = useCallback(async () => {
    try {
      const res = await superAdminAuditLog(100)
      setAuditLog(res.data)
    } catch { /* silent */ }
  }, [])

  const fetchIntegrations = useCallback(async () => {
    try {
      const res = await superAdminGetIntegrations()
      setIntegrations(res.data)
      if (res.data.virustotal?.api_key) setVtKey(res.data.virustotal.api_key)
      if (res.data.safebrowsing?.api_key) setSbKey(res.data.safebrowsing.api_key)
      if (res.data.abuseipdb?.api_key) setAbuseKey(res.data.abuseipdb.api_key)
    } catch { /* silent */ }
  }, [])

  const fetchFeatures = useCallback(async () => {
    try {
      const res = await superAdminGetFeatures()
      setFeatures(res.data)
    } catch { /* silent */ }
  }, [])

  const fetchErrors = useCallback(async () => {
    try {
      const res = await superAdminGetErrors(50)
      setErrorLog(res.data)
    } catch { /* silent */ }
  }, [])

  useEffect(() => {
    if (user?.role === 'superadmin') {
      fetchAll()
    }
  }, [user, fetchAll])

  useEffect(() => {
    if (tab === 'audit') fetchAuditLog()
    if (tab === 'health') superAdminSystemHealth().then(r => setSystemHealth(r.data))
    if (tab === 'integrations') fetchIntegrations()
    if (tab === 'features') fetchFeatures()
    if (tab === 'errors') fetchErrors()
  }, [tab, fetchAuditLog, fetchIntegrations, fetchFeatures, fetchErrors])

  const showMsg = (msg) => {
    setActionMsg(msg)
    setTimeout(() => setActionMsg(''), 4000)
  }

  const handleToggleSuspend = async (u) => {
    try {
      await superAdminUpdateUser(u.id, { is_suspended: !u.is_suspended })
      showMsg(`${u.is_suspended ? 'Activated' : 'Suspended'}: ${u.username}`)
      fetchAll()
    } catch (err) {
      showMsg('Error: ' + (err?.response?.data?.detail || 'Failed'))
    }
  }

  const handleToggleActive = async (u) => {
    try {
      await superAdminUpdateUser(u.id, { is_active: !u.is_active })
      showMsg(`${u.is_active ? 'Deactivated' : 'Activated'}: ${u.username}`)
      fetchAll()
    } catch (err) {
      showMsg('Error: ' + (err?.response?.data?.detail || 'Failed'))
    }
  }

  const handleResetPw = async (u) => {
    if (!window.confirm(`Reset password for ${u.username}? A temporary password will be generated.`)) return
    try {
      const res = await superAdminResetPw(u.id)
      alert(`Temporary password for ${u.username}:\n\n${res.data.temp_password}\n\nShare this securely. It will not be shown again.`)
      showMsg(`Password reset for ${u.username}`)
    } catch (err) {
      showMsg('Error: ' + (err?.response?.data?.detail || 'Failed'))
    }
  }

  const handleDelete = async (u) => {
    if (!window.confirm(`Permanently delete admin account "${u.username}"? This cannot be undone.`)) return
    try {
      await superAdminDeleteUser(u.id)
      showMsg(`Deleted: ${u.username}`)
      fetchAll()
    } catch (err) {
      showMsg('Error: ' + (err?.response?.data?.detail || 'Failed'))
    }
  }

  const handleChangeTheme = async (themeKey) => {
    try {
      await superAdminUpdateTheme({ active_theme: themeKey })
      applyThemeContext(themeKey, neonGlow, bgOverlay, animIntensity)
      showMsg(`Theme set to ${themeKey}`)
      fetchAll()
    } catch (err) {
      showMsg('Error: ' + (err?.response?.data?.detail || 'Failed'))
    }
  }

  const handleSaveThemeSliders = async () => {
    try {
      await superAdminUpdateTheme({
        neon_glow_intensity: neonGlow,
        bg_overlay_strength: bgOverlay,
        animation_intensity: animIntensity,
      })
      applyThemeContext(settings?.active_theme || 'cyan_sentinel', neonGlow, bgOverlay, animIntensity)
      showMsg('Visual effects saved to database!')
      fetchAll()
    } catch (err) {
      showMsg('Error: ' + (err?.response?.data?.detail || 'Failed'))
    }
  }

  const handleSaveIntegrations = async (e) => {
    e.preventDefault()
    try {
      await superAdminUpdateIntegrations({
        virustotal: { enabled: Boolean(vtKey), api_key: vtKey },
        safebrowsing: { enabled: Boolean(sbKey), api_key: sbKey },
        abuseipdb: { enabled: Boolean(abuseKey), api_key: abuseKey },
      })
      showMsg('Integrations updated successfully!')
      fetchIntegrations()
    } catch (err) {
      showMsg('Error: ' + (err?.response?.data?.detail || 'Failed'))
    }
  }

  const handleToggleFeature = async (featureKey) => {
    if (!features) return
    const updated = !features[featureKey]
    try {
      await superAdminUpdateFeatures({ [featureKey]: updated })
      setFeatures(prev => ({ ...prev, [featureKey]: updated }))
      showMsg(`Updated feature ${featureKey}: ${updated ? 'Enabled' : 'Disabled'}`)
    } catch (err) {
      showMsg('Error: ' + (err?.response?.data?.detail || 'Failed'))
    }
  }

  const handleChangePw = async (e) => {
    e.preventDefault()
    setCpError('')
    if (cpNewPw.length < 8) { setCpError('New password must be at least 8 characters.'); return }
    if (cpNewPw !== cpConfirmPw) { setCpError('Passwords do not match.'); return }
    setCpSubmitting(true)
    try {
      await authChangePassword(cpCurrentPw, cpNewPw)
      setCpSuccess(true)
      setCpCurrentPw(''); setCpNewPw(''); setCpConfirmPw('')
    } catch (err) {
      setCpError(err?.response?.data?.detail || 'Failed to change password.')
    } finally {
      setCpSubmitting(false)
    }
  }

  const handleLogout = async () => {
    await logout()
    navigate('/admin/login', { replace: true })
  }

  if (loading || pageLoading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh' }}>
        <div className="radar" />
      </div>
    )
  }

  const THEMES = {
    cyan_sentinel: { name: 'Cyan Sentinel', color: '#22d3ee', desc: 'Neon Sentinel core aesthetic' },
    orange_volt: { name: 'Orange Volt', color: '#f97316', desc: 'Volt Runner high-energy heuristic' },
    purple_void: { name: 'Purple Void', color: '#a855f7', desc: 'Void Architect cosmic depth' },
  }

  const activeTheme = settings?.active_theme || 'cyan_sentinel'

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', padding: '0 16px 80px' }}>

      {/* Action message toast */}
      {actionMsg && (
        <div style={{
          position: 'fixed', bottom: 24, right: 24, zIndex: 400,
          background: 'rgba(13,19,33,0.95)', border: '1px solid rgba(34,211,238,0.4)',
          borderRadius: 12, padding: '12px 20px', fontSize: '0.88rem',
          animation: 'fade-in-up 0.3s ease',
          boxShadow: '0 10px 40px rgba(0,0,0,0.6), 0 0 20px rgba(34,211,238,0.2)',
        }}>
          {actionMsg}
        </div>
      )}

      {/* Top Header */}
      <div style={{ paddingTop: 24, marginBottom: 26, display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 46, height: 46, borderRadius: 12,
            background: 'linear-gradient(135deg, rgba(8,145,178,0.4), rgba(168,85,247,0.35))',
            border: '1px solid rgba(34,211,238,0.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 25px rgba(34,211,238,0.2)',
          }}>
            <Shield size={22} style={{ color: '#22d3ee' }} />
          </div>
          <div>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 900 }}>
              <span className="shimmer-text">Super Admin</span> Control Panel
            </h1>
            <p style={{ fontSize: '0.76rem', color: 'rgba(255,255,255,0.4)' }}>
              Master Account: <strong style={{ color: '#22d3ee' }}>{user?.username}</strong> · Full System Authority
              {lastRefresh && ` · Refreshed ${lastRefresh.toLocaleTimeString()}`}
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn-ghost" onClick={fetchAll} style={{ fontSize: '0.8rem', padding: '7px 14px' }}>↺ Refresh</button>
          <button className="btn-ghost" onClick={handleLogout} style={{ fontSize: '0.8rem', padding: '7px 14px', display: 'flex', alignItems: 'center', gap: 6 }}>
            <LogOut size={14} /> Logout
          </button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 24, flexWrap: 'wrap', overflowX: 'auto', paddingBottom: 4 }}>
        {[
          { id: 'overview',     label: 'Overview',           icon: Activity },
          { id: 'users',        label: 'Administrators',      icon: Users },
          { id: 'health',       label: 'Models & System',     icon: Cpu },
          { id: 'integrations', label: 'Threat Feeds',        icon: Globe },
          { id: 'features',     label: 'Features & Controls',  icon: Sliders },
          { id: 'audit',        label: 'Audit Log',           icon: Terminal },
          { id: 'errors',       label: 'Errors & Warnings',   icon: AlertOctagon },
          { id: 'theme',        label: 'Theme & 3D Settings', icon: Sliders },
          { id: 'security',     label: 'Security Status',     icon: Lock },
          { id: 'account',      label: 'Master Account',      icon: Key },
        ].map(t => {
          const Icon = t.icon
          return (
            <TabBtn key={t.id} active={tab === t.id} onClick={() => setTab(t.id)}>
              <Icon size={14} />
              <span>{t.label}</span>
            </TabBtn>
          )
        })}
      </div>

      {/* ── Tab: Overview ────────────────────────────────────────────────── */}
      {tab === 'overview' && stats && (
        <div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: 12, marginBottom: 24 }}>
            <StatCard label="Total Users" value={stats.users.total} color="#22d3ee" icon={Users} />
            <StatCard label="Active" value={stats.users.active} color="#10b981" icon={CheckCircle} />
            <StatCard label="Suspended" value={stats.users.suspended} color="#f59e0b" icon={ShieldOff} />
            <StatCard label="Total Scans" value={stats.scans.total} color="#3b82f6" icon={Activity} />
            <StatCard label="Audit Events" value={stats.audit.total_events} color="#a855f7" icon={Terminal} />
            <StatCard label="DB Size" value={`${(stats.database.size_bytes / 1024).toFixed(0)} KB`} color="#38bdf8" icon={Database} sub="SQLite (WAL Mode)" />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginBottom: 24 }}>
            <div className="glass" style={{ borderRadius: 14, padding: '18px 20px' }}>
              <h3 style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 14 }}>
                Authentication Health (Last 7 Days)
              </h3>
              <div style={{ display: 'flex', gap: 24 }}>
                <div>
                  <div style={{ fontSize: '2.1rem', fontWeight: 900, color: '#10b981' }}>{stats.logins.last_7d}</div>
                  <div style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)' }}>Successful Logins</div>
                </div>
                <div>
                  <div style={{ fontSize: '2.1rem', fontWeight: 900, color: '#ff2d55' }}>{stats.logins.failed_7d}</div>
                  <div style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)' }}>Failed Attempts</div>
                </div>
              </div>
            </div>

            <div className="glass" style={{ borderRadius: 14, padding: '18px 20px' }}>
              <h3 style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 14 }}>
                Threat Risk Distribution
              </h3>
              <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
                {Object.entries(stats.scans.by_risk || {}).map(([risk, cnt]) => (
                  <div key={risk} style={{ minWidth: 60 }}>
                    <div style={{ fontSize: '1.2rem', fontWeight: 800 }}>{cnt}</div>
                    <div style={{ fontSize: '0.72rem', textTransform: 'capitalize', color: 'rgba(255,255,255,0.5)' }}>{risk}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: Administrators ──────────────────────────────────────────── */}
      {tab === 'users' && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
            <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Administrator Accounts ({users.length})
            </h2>
            <button className="btn-primary" onClick={() => setShowCreateModal(true)} style={{ fontSize: '0.8rem', padding: '7px 14px', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Plus size={14} /> New Administrator
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {users.map(u => (
              <div key={u.id} className="glass" style={{
                borderRadius: 14, padding: '16px 20px',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                flexWrap: 'wrap', gap: 12,
                borderColor: u.is_suspended ? 'rgba(255,45,85,0.2)' : undefined,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <div style={{
                    width: 36, height: 36, borderRadius: 10,
                    background: u.role === 'superadmin' ? 'rgba(34,211,238,0.15)' : 'rgba(168,85,247,0.15)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <Shield size={16} style={{ color: u.role === 'superadmin' ? '#22d3ee' : '#a855f7' }} />
                  </div>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: '0.92rem', display: 'flex', alignItems: 'center', gap: 8 }}>
                      {u.username}
                      <span className="tag" style={{
                        fontSize: '0.66rem',
                        background: u.role === 'superadmin' ? 'rgba(34,211,238,0.1)' : 'rgba(168,85,247,0.1)',
                        color: u.role === 'superadmin' ? '#22d3ee' : '#a855f7',
                      }}>
                        {u.role}
                      </span>
                      {u.is_suspended && <span className="tag" style={{ background: 'rgba(255,45,85,0.15)', color: '#ff2d55', fontSize: '0.65rem' }}>SUSPENDED</span>}
                      {u.must_change_password && <span className="tag" style={{ background: 'rgba(245,158,11,0.15)', color: '#f59e0b', fontSize: '0.65rem' }}>PWD CHANGE REQ</span>}
                    </div>
                    <div style={{ fontSize: '0.74rem', color: 'rgba(255,255,255,0.35)', marginTop: 2 }}>
                      {u.email || 'No email'} · Created: {new Date(u.created_at).toLocaleDateString()}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  {u.role !== 'superadmin' && (
                    <>
                      <button onClick={() => handleToggleSuspend(u)} className="btn-ghost" style={{ fontSize: '0.74rem', padding: '5px 10px' }}>
                        {u.is_suspended ? 'Unsuspend' : 'Suspend'}
                      </button>
                      <button onClick={() => handleResetPw(u)} className="btn-ghost" style={{ fontSize: '0.74rem', padding: '5px 10px' }}>
                        Reset Pwd
                      </button>
                      <button onClick={() => handleDelete(u)} className="btn-ghost" style={{ fontSize: '0.74rem', padding: '5px 10px', color: '#ff2d55', borderColor: 'rgba(255,45,85,0.2)' }}>
                        <Trash2 size={12} />
                      </button>
                    </>
                  )}
                  {u.id === user.sub && (
                    <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.3)' }}>Current Session</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Tab: System & Threat Models ──────────────────────────────────── */}
      {tab === 'health' && (
        <div>
          <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
            Detection Models & Heuristics Status
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16, marginBottom: 24 }}>
            {systemHealth?.detection_models && Object.entries(systemHealth.detection_models).map(([key, model]) => (
              <div key={key} className="glass" style={{ borderRadius: 16, padding: '18px 20px', border: '1px solid rgba(34,211,238,0.2)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                  <div style={{ fontWeight: 800, fontSize: '0.98rem', color: '#f1f5f9' }}>{model.name}</div>
                  <span className="tag" style={{ background: 'rgba(16,185,129,0.12)', color: '#10b981', border: '1px solid rgba(16,185,129,0.3)', fontSize: '0.68rem' }}>
                    ● {model.status.toUpperCase()}
                  </span>
                </div>
                <div style={{ fontSize: '0.74rem', color: 'rgba(255,255,255,0.4)', marginBottom: 12 }}>
                  Version: {model.version}
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {model.capabilities?.map((cap) => (
                    <span key={cap} style={{ background: 'rgba(255,255,255,0.05)', borderRadius: 6, padding: '3px 8px', fontSize: '0.7rem', color: 'rgba(255,255,255,0.7)' }}>
                      {cap}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
            Database Integrity & Table Telemetry
          </h2>
          <div className="glass" style={{ borderRadius: 16, padding: '20px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 14 }}>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)' }}>Database Status</span>
                <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#10b981', marginTop: 2 }}>
                  {systemHealth?.database?.status === 'ok' ? 'Connected & Healthy' : systemHealth?.database?.status}
                </div>
              </div>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)' }}>Journal Mode</span>
                <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#22d3ee', marginTop: 2 }}>
                  {systemHealth?.database?.journal_mode || 'WAL'}
                </div>
              </div>
              <div>
                <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)' }}>Disk Footprint</span>
                <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#a855f7', marginTop: 2 }}>
                  {((systemHealth?.database?.size_bytes || 0) / 1024).toFixed(0)} KB
                </div>
              </div>
            </div>

            <div style={{ marginTop: 18, borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 14 }}>
              <span style={{ fontSize: '0.74rem', color: 'rgba(255,255,255,0.45)', textTransform: 'uppercase' }}>Record Counts by Table:</span>
              <div style={{ display: 'flex', gap: 16, marginTop: 8, flexWrap: 'wrap' }}>
                {Object.entries(systemHealth?.database?.tables || {}).map(([tbl, cnt]) => (
                  <div key={tbl} style={{ background: 'rgba(255,255,255,0.04)', borderRadius: 8, padding: '6px 12px' }}>
                    <span style={{ fontSize: '0.74rem', color: 'rgba(255,255,255,0.5)' }}>{tbl}: </span>
                    <strong style={{ fontSize: '0.82rem', color: '#fff' }}>{cnt}</strong>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: Integrations ────────────────────────────────────────────── */}
      {tab === 'integrations' && (
        <div>
          <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
            External Threat Intelligence Feeds & API Integrations
          </h2>

          <div className="glass" style={{ borderRadius: 16, padding: '22px', marginBottom: 20 }}>
            <p style={{ fontSize: '0.82rem', color: 'rgba(255,255,255,0.5)', marginBottom: 18 }}>
              Configure external reputation feeds. Keys are stored safely server-side with parameterized queries and never committed to source.
            </p>

            <form onSubmit={handleSaveIntegrations}>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', fontSize: '0.76rem', color: 'rgba(255,255,255,0.6)', marginBottom: 6 }}>
                  VirusTotal API Key (Optional)
                </label>
                <input
                  type="text"
                  className="input-field mono"
                  value={vtKey}
                  onChange={e => setVtKey(e.target.value)}
                  placeholder="e.g. 4a2b9f..."
                />
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', fontSize: '0.76rem', color: 'rgba(255,255,255,0.6)', marginBottom: 6 }}>
                  Google Safe Browsing v4 Key (Optional)
                </label>
                <input
                  type="text"
                  className="input-field mono"
                  value={sbKey}
                  onChange={e => setSbKey(e.target.value)}
                  placeholder="e.g. AIzaSy..."
                />
              </div>

              <div style={{ marginBottom: 20 }}>
                <label style={{ display: 'block', fontSize: '0.76rem', color: 'rgba(255,255,255,0.6)', marginBottom: 6 }}>
                  AbuseIPDB API Key (Optional)
                </label>
                <input
                  type="text"
                  className="input-field mono"
                  value={abuseKey}
                  onChange={e => setAbuseKey(e.target.value)}
                  placeholder="e.g. 81f092..."
                />
              </div>

              <button type="submit" className="btn-primary">
                Save Integration Settings
              </button>
            </form>
          </div>
        </div>
      )}

      {/* ── Tab: Feature Controls ────────────────────────────────────────── */}
      {tab === 'features' && features && (
        <div>
          <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
            Application Feature Toggles & System Policies
          </h2>

          <div className="glass" style={{ borderRadius: 16, padding: '20px' }}>
            {[
              { key: 'rate_limiting', label: 'Rate Limiting Protection', desc: 'Enforces 5 max failed logins per 15 min and API request throttles' },
              { key: 'public_scans', label: 'Public Threat Scans', desc: 'Allows guest visitors to run URL and Message scans without an account' },
              { key: 'debug_logging', label: 'Verbose Debug Logging', desc: 'Logs expanded forensic payloads into the audit trail' },
            ].map(({ key, label, desc }) => (
              <div key={key} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '14px 0', borderBottom: '1px solid rgba(255,255,255,0.06)',
              }}>
                <div>
                  <div style={{ fontWeight: 700, fontSize: '0.92rem' }}>{label}</div>
                  <div style={{ fontSize: '0.76rem', color: 'rgba(255,255,255,0.4)', marginTop: 2 }}>{desc}</div>
                </div>
                <button
                  onClick={() => handleToggleFeature(key)}
                  style={{
                    padding: '6px 16px', borderRadius: 20, cursor: 'pointer', fontSize: '0.78rem', fontWeight: 700,
                    background: features[key] ? 'rgba(16,185,129,0.2)' : 'rgba(255,45,85,0.15)',
                    border: `1px solid ${features[key] ? '#10b981' : '#ff2d55'}`,
                    color: features[key] ? '#10b981' : '#ff2d55',
                  }}
                >
                  {features[key] ? 'ENABLED' : 'DISABLED'}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Tab: Audit Log ───────────────────────────────────────────────── */}
      {tab === 'audit' && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Audit Trail ({auditLog.length} events recorded)
            </h2>
            <button className="btn-ghost" onClick={fetchAuditLog} style={{ fontSize: '0.78rem', padding: '5px 12px' }}>↺ Reload</button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {auditLog.map(ev => (
              <div key={ev.id} className="glass" style={{
                borderRadius: 10, padding: '10px 16px',
                display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap',
                borderColor: ev.outcome === 'failure' ? 'rgba(255,45,85,0.2)' : undefined,
              }}>
                <span style={{
                  fontSize: '0.68rem', padding: '2px 8px', borderRadius: 99, flexShrink: 0,
                  background: ev.outcome === 'failure' ? 'rgba(255,45,85,0.15)' : 'rgba(16,185,129,0.12)',
                  color: ev.outcome === 'failure' ? '#ff2d55' : '#10b981',
                }}>
                  {ev.outcome}
                </span>
                <code style={{ fontSize: '0.78rem', color: '#22d3ee', flexShrink: 0 }}>{ev.action}</code>
                <span style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.5)', flex: 1 }}>
                  Actor: <strong>{ev.actor_username || 'system'}</strong>
                  {ev.ip_address && ` (${ev.ip_address})`}
                  {ev.target_type && ` → ${ev.target_type}`}
                </span>
                <span style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.28)', flexShrink: 0 }}>
                  {new Date(ev.created_at).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Tab: Errors & Warnings ───────────────────────────────────────── */}
      {tab === 'errors' && (
        <div>
          <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
            Operational Errors & Incident Log ({errorLog.length})
          </h2>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {errorLog.length === 0 ? (
              <div className="glass" style={{ borderRadius: 14, padding: '30px', textAlign: 'center' }}>
                <CheckCircle2 size={32} style={{ color: '#10b981', margin: '0 auto 10px', display: 'block' }} />
                <p style={{ color: 'rgba(255,255,255,0.5)' }}>Clean system health: No recent runtime errors or security incident failures.</p>
              </div>
            ) : (
              errorLog.map(err => (
                <div key={err.id} className="glass" style={{
                  borderRadius: 12, padding: '12px 18px',
                  border: '1px solid rgba(255,45,85,0.25)',
                  background: 'rgba(255,45,85,0.04)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span style={{ color: '#ff2d55', fontWeight: 700, fontSize: '0.84rem' }}>{err.action}</span>
                    <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.3)' }}>{new Date(err.created_at).toLocaleString()}</span>
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.6)' }}>
                    Actor: {err.actor_username || 'anonymous'} {err.ip_address ? `(${err.ip_address})` : ''} · Metadata: {err.metadata}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* ── Tab: Theme & 3D Settings ─────────────────────────────────────── */}
      {tab === 'theme' && (
        <div>
          <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
            Visual Themes & 3D Multiverse Controls
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: 16, marginBottom: 24 }}>
            {Object.entries(THEMES).map(([key, { name, color, desc }]) => (
              <div
                key={key}
                className="glass"
                style={{
                  borderRadius: 16, padding: '20px', cursor: 'pointer',
                  borderColor: activeTheme === key ? `${color}70` : undefined,
                  background: activeTheme === key ? `${color}10` : undefined,
                  transition: 'all 0.2s',
                  boxShadow: activeTheme === key ? `0 0 25px ${color}30` : undefined,
                }}
                onClick={() => handleChangeTheme(key)}
              >
                <div style={{
                  width: 44, height: 44, borderRadius: 12,
                  background: `${color}20`, border: `1px solid ${color}45`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  marginBottom: 12,
                }}>
                  <Shield size={20} style={{ color }} />
                </div>
                <div style={{ fontWeight: 700, fontSize: '0.98rem', marginBottom: 4 }}>{name}</div>
                <div style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)', marginBottom: 8 }}>{desc}</div>
                {activeTheme === key && (
                  <div style={{ fontSize: '0.72rem', color, display: 'flex', alignItems: 'center', gap: 4 }}>
                    <CheckCircle size={12} /> Default Active Theme
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Sliders for Neon Glow, Overlay, Animation */}
          <div className="glass" style={{ borderRadius: 16, padding: '22px', marginBottom: 20 }}>
            <h3 style={{ fontSize: '0.88rem', fontWeight: 800, marginBottom: 18 }}>
              Fine-Tune Visual Intensity & Overlay
            </h3>

            <div style={{ marginBottom: 18 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: '0.8rem' }}>
                <span style={{ color: 'rgba(255,255,255,0.7)' }}>Neon Glow Intensity</span>
                <span style={{ color: '#22d3ee', fontWeight: 700 }}>{neonGlow.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0.1"
                max="0.9"
                step="0.05"
                value={neonGlow}
                onChange={e => setNeonGlow(parseFloat(e.target.value))}
                style={{ width: '100%' }}
              />
            </div>

            <div style={{ marginBottom: 18 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: '0.8rem' }}>
                <span style={{ color: 'rgba(255,255,255,0.7)' }}>Background Dark Overlay Strength</span>
                <span style={{ color: '#a855f7', fontWeight: 700 }}>{bgOverlay.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0.3"
                max="0.95"
                step="0.05"
                value={bgOverlay}
                onChange={e => setBgOverlay(parseFloat(e.target.value))}
                style={{ width: '100%' }}
              />
            </div>

            <div style={{ marginBottom: 22 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: '0.8rem' }}>
                <span style={{ color: 'rgba(255,255,255,0.7)' }}>3D Animation & Motion Speed</span>
                <span style={{ color: '#f97316', fontWeight: 700 }}>{animIntensity.toFixed(2)}x</span>
              </div>
              <input
                type="range"
                min="0.2"
                max="2.0"
                step="0.1"
                value={animIntensity}
                onChange={e => setAnimIntensity(parseFloat(e.target.value))}
                style={{ width: '100%' }}
              />
            </div>

            <button className="btn-primary" onClick={handleSaveThemeSliders}>
              Save Visual Configuration to Database
            </button>
          </div>
        </div>
      )}

      {/* ── Tab: Security Status ─────────────────────────────────────────── */}
      {tab === 'security' && (
        <div>
          <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
            Security Defenses & Active Protections
          </h2>
          <div className="glass" style={{ borderRadius: 16, padding: '20px' }}>
            {[
              { label: 'Password Storage', status: 'Bcrypt direct hashing (cost=12)', ok: true },
              { label: 'Session Management', status: 'HttpOnly SameSite=Lax JWT cookies', ok: true },
              { label: 'Brute-Force Shield', status: 'Automatic 15-min lockout after 5 fails', ok: true },
              { label: 'SQL Injection Defense', status: 'Strict parameterization with SQLite query builder', ok: true },
              { label: 'Data Persistence', status: 'Persistent SQLite WAL journal mode', ok: true },
              { label: 'Role Escalation Prevention', status: 'Superadmin-only route authorization dependency guards', ok: true },
            ].map(({ label, status, ok }) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14 }}>
                <CheckCircle2 size={16} style={{ color: '#10b981', flexShrink: 0 }} />
                <span style={{ flex: 1, fontSize: '0.86rem', fontWeight: 600 }}>{label}</span>
                <span style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.45)' }}>{status}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Tab: Master Account ──────────────────────────────────────────── */}
      {tab === 'account' && (
        <div style={{ maxWidth: 480 }}>
          <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
            Change Master Super Admin Password
          </h2>
          <div className="glass" style={{ borderRadius: 16, padding: '24px' }}>
            {cpSuccess ? (
              <div style={{ textAlign: 'center', padding: '20px 0' }}>
                <CheckCircle size={40} style={{ color: '#10b981', margin: '0 auto 14px', display: 'block' }} />
                <p style={{ fontWeight: 700, marginBottom: 6 }}>Password changed successfully.</p>
                <button className="btn-ghost" onClick={() => setCpSuccess(false)} style={{ marginTop: 10 }}>Change Again</button>
              </div>
            ) : (
              <form onSubmit={handleChangePw}>
                <div style={{ marginBottom: 14 }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: 'rgba(255,255,255,0.45)', marginBottom: 6, textTransform: 'uppercase' }}>Current Password</label>
                  <input type="password" className="input-field" value={cpCurrentPw} onChange={e => setCpCurrentPw(e.target.value)} placeholder="Current password" required />
                </div>
                <div style={{ marginBottom: 14 }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: 'rgba(255,255,255,0.45)', marginBottom: 6, textTransform: 'uppercase' }}>New Password</label>
                  <input type="password" className="input-field" value={cpNewPw} onChange={e => setCpNewPw(e.target.value)} placeholder="Min 8 characters" required />
                </div>
                <div style={{ marginBottom: 20 }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: 'rgba(255,255,255,0.45)', marginBottom: 6, textTransform: 'uppercase' }}>Confirm New Password</label>
                  <input type="password" className="input-field" value={cpConfirmPw} onChange={e => setCpConfirmPw(e.target.value)} placeholder="Repeat new password" required />
                </div>
                {cpError && (
                  <div style={{ background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)', borderRadius: 10, padding: '10px 14px', marginBottom: 14, fontSize: '0.84rem', color: '#ff2d55' }}>
                    {cpError}
                  </div>
                )}
                <button type="submit" className="btn-primary" disabled={cpSubmitting} style={{ width: '100%' }}>
                  {cpSubmitting ? 'Saving…' : 'Change Master Password'}
                </button>
              </form>
            )}
          </div>
        </div>
      )}

      {/* Create Admin Modal */}
      {showCreateModal && (
        <CreateAdminModal
          onClose={() => setShowCreateModal(false)}
          onCreated={fetchAll}
        />
      )}
    </div>
  )
}

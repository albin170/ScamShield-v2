import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Lock, User, Eye, EyeOff, AlertTriangle } from 'lucide-react'
import { useAuth } from '../../context/AuthContext'
import { authChangePassword } from '../../api'

export default function AdminLogin({ isSuperAdminMode = false }) {
  const navigate = useNavigate()
  const { user, login, loading, refreshUser } = useAuth()


  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  // First-login password change state
  const [mustChange, setMustChange] = useState(false)
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')

  // Redirect if already logged in
  useEffect(() => {
    if (!loading && user) {
      if (user.role === 'superadmin') navigate('/superadmin/dashboard', { replace: true })
      else navigate('/admin/dashboard', { replace: true })
    }
  }, [user, loading, navigate])

  async function handleLogin(e) {
    e.preventDefault()
    if (!username.trim() || !password.trim()) {
      setError('Please enter both username and password.')
      return
    }
    setError('')
    setSubmitting(true)
    try {
      const data = await login(username.trim(), password)
      if (data.must_change_password) {
        setMustChange(true)
      } else if (data.role === 'superadmin') {
        navigate('/superadmin/dashboard', { replace: true })
      } else {
        navigate('/admin/dashboard', { replace: true })
      }
    } catch (err) {
      const detail = err?.response?.data?.detail
      if (err?.response?.status === 429) {
        setError('Too many failed attempts. Account temporarily locked.')
      } else {
        setError(detail || 'Login failed. Check your credentials.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  async function handleChangePassword(e) {
    e.preventDefault()
    if (newPw.length < 8) {
      setError('New password must be at least 8 characters.')
      return
    }
    if (newPw !== confirmPw) {
      setError('Passwords do not match.')
      return
    }
    setError('')
    setSubmitting(true)
    try {
      await authChangePassword(password, newPw)
      // Re-fetch user state
      await refreshUser()
      navigate(user?.role === 'superadmin' ? '/superadmin/dashboard' : '/admin/dashboard', { replace: true })
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to change password.')
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) return null

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: 20,
      position: 'relative',
    }}>
      {/* Ambient glow effects */}
      <div style={{
        position: 'fixed', top: '20%', left: '30%', width: 500, height: 500,
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(34,211,238,0.06) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />
      <div style={{
        position: 'fixed', bottom: '20%', right: '30%', width: 400, height: 400,
        borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(168,85,247,0.05) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />

      <div style={{
        width: '100%',
        maxWidth: 420,
        animation: 'fade-in-up 0.5s ease forwards',
      }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{
            width: 64, height: 64, borderRadius: 18,
            background: 'linear-gradient(135deg, rgba(8,145,178,0.4), rgba(168,85,247,0.3))',
            border: '1px solid rgba(34,211,238,0.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            margin: '0 auto 14px',
            boxShadow: '0 0 40px rgba(34,211,238,0.15)',
          }}>
            <Shield size={28} style={{ color: '#22d3ee' }} />
          </div>
          <h1 style={{ fontSize: '1.6rem', fontWeight: 900, marginBottom: 6 }}>
            Scam<span style={{ color: '#22d3ee' }}>Shield</span>
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.85rem' }}>
            {mustChange ? 'Change your password to continue' : (isSuperAdminMode || window.location.pathname.includes('superadmin') ? 'Super Admin Master Gateway' : 'Administrative Portal')}
          </p>
        </div>

        {/* Card */}
        <div className="glass" style={{
          borderRadius: 20,
          padding: 28,
          border: '1px solid rgba(34,211,238,0.2)',
          boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
        }}>
          {!mustChange ? (
            <form onSubmit={handleLogin} autoComplete="off">
              <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginBottom: 20 }}>
                <button
                  type="button"
                  onClick={() => navigate('/admin/login')}
                  style={{
                    padding: '6px 14px', borderRadius: 8, fontSize: '0.78rem', cursor: 'pointer',
                    background: !(isSuperAdminMode || window.location.pathname.includes('superadmin')) ? 'rgba(34,211,238,0.15)' : 'transparent',
                    border: !(isSuperAdminMode || window.location.pathname.includes('superadmin')) ? '1px solid rgba(34,211,238,0.4)' : '1px solid transparent',
                    color: !(isSuperAdminMode || window.location.pathname.includes('superadmin')) ? '#22d3ee' : 'rgba(255,255,255,0.4)',
                  }}
                >
                  Admin Login
                </button>
                <button
                  type="button"
                  onClick={() => navigate('/superadmin/login')}
                  style={{
                    padding: '6px 14px', borderRadius: 8, fontSize: '0.78rem', cursor: 'pointer',
                    background: (isSuperAdminMode || window.location.pathname.includes('superadmin')) ? 'rgba(168,85,247,0.18)' : 'transparent',
                    border: (isSuperAdminMode || window.location.pathname.includes('superadmin')) ? '1px solid rgba(168,85,247,0.45)' : '1px solid transparent',
                    color: (isSuperAdminMode || window.location.pathname.includes('superadmin')) ? '#c084fc' : 'rgba(255,255,255,0.4)',
                  }}
                >
                  Super Admin
                </button>
              </div>

              <h2 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: 20, textAlign: 'center' }}>
                {(isSuperAdminMode || window.location.pathname.includes('superadmin')) ? 'Super Admin Authentication' : 'Sign in to Admin Panel'}
              </h2>

              {/* Username */}
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', fontSize: '0.78rem', color: 'rgba(255,255,255,0.5)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Username
                </label>
                <div style={{ position: 'relative' }}>
                  <User size={15} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'rgba(255,255,255,0.3)' }} />
                  <input
                    id="admin-username"
                    type="text"
                    className="input-field"
                    style={{ paddingLeft: 38 }}
                    placeholder="Enter your username"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    autoComplete="username"
                    disabled={submitting}
                  />
                </div>
              </div>

              {/* Password */}
              <div style={{ marginBottom: 20 }}>
                <label style={{ display: 'block', fontSize: '0.78rem', color: 'rgba(255,255,255,0.5)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Password
                </label>
                <div style={{ position: 'relative' }}>
                  <Lock size={15} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'rgba(255,255,255,0.3)' }} />
                  <input
                    id="admin-password"
                    type={showPw ? 'text' : 'password'}
                    className="input-field"
                    style={{ paddingLeft: 38, paddingRight: 44 }}
                    placeholder="Enter your password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    autoComplete="current-password"
                    disabled={submitting}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw(s => !s)}
                    style={{
                      position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
                      background: 'none', border: 'none', cursor: 'pointer',
                      color: 'rgba(255,255,255,0.3)', padding: 4,
                    }}
                    tabIndex={-1}
                  >
                    {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>

              {error && (
                <div style={{
                  background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)',
                  borderRadius: 10, padding: '10px 14px', marginBottom: 16,
                  display: 'flex', alignItems: 'center', gap: 8,
                }}>
                  <AlertTriangle size={15} style={{ color: '#ff2d55', flexShrink: 0 }} />
                  <span style={{ fontSize: '0.85rem', color: 'rgba(255,255,255,0.75)' }}>{error}</span>
                </div>
              )}

              <button
                id="admin-login-btn"
                type="submit"
                className="btn-primary"
                disabled={submitting}
                style={{ width: '100%', justifyContent: 'center', display: 'flex', alignItems: 'center', gap: 8 }}
              >
                {submitting ? (
                  <>
                    <span style={{ width: 15, height: 15, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'radar-spin 0.7s linear infinite', display: 'inline-block' }} />
                    Signing in…
                  </>
                ) : (
                  'Sign In'
                )}
              </button>

              <p style={{ textAlign: 'center', marginTop: 18, fontSize: '0.78rem', color: 'rgba(255,255,255,0.25)' }}>
                Super admin? Use the same login with your super admin credentials.
              </p>
            </form>
          ) : (
            /* First-login password change form */
            <form onSubmit={handleChangePassword}>
              <div style={{
                background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.3)',
                borderRadius: 10, padding: '10px 14px', marginBottom: 20,
                fontSize: '0.84rem', color: 'rgba(255,255,255,0.75)',
                display: 'flex', alignItems: 'center', gap: 8,
              }}>
                <AlertTriangle size={15} style={{ color: '#f59e0b', flexShrink: 0 }} />
                <span>You must set a new password before continuing.</span>
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', fontSize: '0.78rem', color: 'rgba(255,255,255,0.5)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  New Password
                </label>
                <input
                  type="password"
                  className="input-field"
                  placeholder="At least 8 characters"
                  value={newPw}
                  onChange={e => setNewPw(e.target.value)}
                  disabled={submitting}
                />
              </div>

              <div style={{ marginBottom: 20 }}>
                <label style={{ display: 'block', fontSize: '0.78rem', color: 'rgba(255,255,255,0.5)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Confirm Password
                </label>
                <input
                  type="password"
                  className="input-field"
                  placeholder="Repeat new password"
                  value={confirmPw}
                  onChange={e => setConfirmPw(e.target.value)}
                  disabled={submitting}
                />
              </div>

              {error && (
                <div style={{
                  background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)',
                  borderRadius: 10, padding: '10px 14px', marginBottom: 16,
                  display: 'flex', alignItems: 'center', gap: 8,
                }}>
                  <AlertTriangle size={15} style={{ color: '#ff2d55', flexShrink: 0 }} />
                  <span style={{ fontSize: '0.85rem', color: 'rgba(255,255,255,0.75)' }}>{error}</span>
                </div>
              )}

              <button
                id="change-password-btn"
                type="submit"
                className="btn-primary"
                disabled={submitting}
                style={{ width: '100%', justifyContent: 'center', display: 'flex' }}
              >
                {submitting ? 'Saving…' : 'Set New Password'}
              </button>
            </form>
          )}
        </div>

        <p style={{ textAlign: 'center', marginTop: 20, fontSize: '0.75rem', color: 'rgba(255,255,255,0.2)' }}>
          ScamShield v3.0 • Admin Portal
        </p>
      </div>
    </div>
  )
}

import React, { useState, useEffect } from 'react'
import { useNavigate, NavLink } from 'react-router-dom'
import {
  Shield, LogOut, Activity, AlertTriangle, Users, Clock,
  TrendingUp, CheckCircle, BarChart2, Settings, Lock
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext'
import { adminDashboardStats, adminProfile, getStats, getHistory } from '../../api'
import { getRiskMeta } from '../../utils'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from 'recharts'

function StatCard({ label, value, color, icon: Icon, sub }) {
  return (
    <div className="glass" style={{
      borderRadius: 14, padding: '18px 20px',
      borderColor: `${color}25`, display: 'flex', flexDirection: 'column', gap: 6,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</span>
        {Icon && <Icon size={15} style={{ color }} />}
      </div>
      <div style={{ fontSize: '1.9rem', fontWeight: 900, color }}>{value ?? '—'}</div>
      {sub && <div style={{ fontSize: '0.73rem', color: 'rgba(255,255,255,0.3)' }}>{sub}</div>}
    </div>
  )
}

function AccessDenied({ permission }) {
  return (
    <div className="glass" style={{
      borderRadius: 14, padding: '24px 20px', textAlign: 'center',
      borderColor: 'rgba(255,45,85,0.2)',
    }}>
      <Lock size={28} style={{ color: '#ff2d55', margin: '0 auto 10px', display: 'block' }} />
      <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: '0.9rem' }}>
        Access Denied — you do not have the <code style={{ color: '#22d3ee' }}>{permission}</code> permission.
      </p>
    </div>
  )
}

export default function AdminDashboard() {
  const navigate = useNavigate()
  const { user, logout, loading } = useAuth()
  const [adminStats, setAdminStats] = useState(null)
  const [scanStats, setScanStats] = useState(null)
  const [recent, setRecent] = useState([])
  const [pageLoading, setPageLoading] = useState(true)
  const [lastRefresh, setLastRefresh] = useState(null)

  const canViewStats = user?.role === 'superadmin' || user?.permissions?.includes('view_stats')
  const canViewHistory = user?.role === 'superadmin' || user?.permissions?.includes('view_history')

  useEffect(() => {
    if (!loading && !user) navigate('/admin/login', { replace: true })
  }, [user, loading, navigate])

  const fetchData = async () => {
    try {
      const promises = [adminDashboardStats()]
      if (canViewStats) promises.push(getStats())
      if (canViewHistory) promises.push(getHistory(5))

      const results = await Promise.allSettled(promises)
      if (results[0].status === 'fulfilled') setAdminStats(results[0].value.data)
      if (canViewStats && results[1]?.status === 'fulfilled') setScanStats(results[1].value.data)
      if (canViewHistory) {
        const idx = canViewStats ? 2 : 1
        if (results[idx]?.status === 'fulfilled') setRecent(results[idx].value.data)
      }
      setLastRefresh(new Date())
    } catch { /* silent */ }
    finally { setPageLoading(false) }
  }

  useEffect(() => {
    if (user) fetchData()
  }, [user])

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

  const typeData = scanStats?.by_scan_type
    ? Object.entries(scanStats.by_scan_type).map(([k, v]) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), count: v }))
    : []

  return (
    <div style={{ maxWidth: 1060, margin: '0 auto', padding: '0 16px 60px' }}>
      {/* Header */}
      <div style={{ paddingTop: 24, marginBottom: 32, display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
            <div style={{
              width: 40, height: 40, borderRadius: 12,
              background: 'rgba(168,85,247,0.15)', border: '1px solid rgba(168,85,247,0.3)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Shield size={20} style={{ color: '#a855f7' }} />
            </div>
            <div>
              <h1 style={{ fontSize: '1.4rem', fontWeight: 900 }}>
                Admin <span style={{ color: '#a855f7' }}>Dashboard</span>
              </h1>
              <p style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.35)' }}>
                {user?.username} · {user?.role === 'superadmin' ? 'Super Admin' : 'Administrator'}
              </p>
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {lastRefresh && (
            <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.25)' }}>
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button className="btn-ghost" onClick={fetchData} style={{ fontSize: '0.8rem', padding: '7px 14px' }}>
            ↺ Refresh
          </button>
          {user?.role === 'superadmin' && (
            <NavLink to="/superadmin/dashboard" style={{ textDecoration: 'none' }}>
              <button className="btn-ghost" style={{ fontSize: '0.8rem', padding: '7px 14px', color: '#a855f7', borderColor: 'rgba(168,85,247,0.3)' }}>
                Super Admin ▶
              </button>
            </NavLink>
          )}
          <button onClick={handleLogout} className="btn-ghost" style={{ fontSize: '0.8rem', padding: '7px 14px', display: 'flex', alignItems: 'center', gap: 6 }}>
            <LogOut size={14} /> Logout
          </button>
        </div>
      </div>

      {/* Admin quick stats */}
      {adminStats && (
        <div style={{ marginBottom: 28 }}>
          <h2 style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 12 }}>
            Operations Today
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(155px, 1fr))', gap: 12 }}>
            <StatCard label="Today's Scans" value={adminStats.today_scans} color="#22d3ee" icon={Activity} />
            <StatCard label="Login Events" value={adminStats.today_login_events} color="#10b981" icon={CheckCircle} />
            <StatCard label="Failed Logins" value={adminStats.today_failed_logins} color="#f97316" icon={AlertTriangle} />
            <StatCard label="Active Admins" value={adminStats.total_admins} color="#a855f7" icon={Users} />
          </div>
        </div>
      )}

      {/* Scan Statistics */}
      {canViewStats ? (
        scanStats ? (
          <>
            <h2 style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 12 }}>
              Scan Statistics
            </h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(155px, 1fr))', gap: 12, marginBottom: 24 }}>
              <StatCard label="Total Scans" value={scanStats.total_scans} color="#38bdf8" icon={Activity} />
              <StatCard label="Critical" value={scanStats.critical_count} color="#ff2d55" icon={AlertTriangle} />
              <StatCard label="High Risk" value={scanStats.high_count} color="#f97316" />
              <StatCard label="Safe" value={scanStats.safe_count} color="#10b981" icon={CheckCircle} />
              <StatCard label="Avg Score" value={scanStats.average_risk_score ? `${scanStats.average_risk_score}/100` : '—'} color="#a855f7" icon={TrendingUp} />
            </div>

            {typeData.length > 0 && (
              <div className="glass" style={{ borderRadius: 14, padding: '18px 20px', marginBottom: 24 }}>
                <h3 style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 14 }}>
                  Scans by Type
                </h3>
                <ResponsiveContainer width="100%" height={160}>
                  <BarChart data={typeData} margin={{ top: 0, right: 10, bottom: 0, left: -20 }}>
                    <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'rgba(255,255,255,0.4)' }} />
                    <YAxis tick={{ fontSize: 11, fill: 'rgba(255,255,255,0.4)' }} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ background: '#0d1321', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }}
                      labelStyle={{ color: 'rgba(255,255,255,0.7)' }}
                    />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {typeData.map((_, i) => (
                        <Cell key={i} fill={['#22d3ee', '#a855f7', '#f97316', '#10b981', '#f59e0b'][i % 5]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </>
        ) : null
      ) : (
        <AccessDenied permission="view_stats" />
      )}

      {/* Recent scans */}
      {canViewHistory ? (
        recent.length > 0 && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <h2 style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                Recent Scans
              </h2>
              <NavLink to="/history" style={{ fontSize: '0.78rem', color: '#22d3ee', textDecoration: 'none' }}>
                View all →
              </NavLink>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {recent.map(item => {
                const meta = getRiskMeta(item.risk_level)
                return (
                  <div key={item.id} className="glass" style={{
                    borderRadius: 12, padding: '11px 16px',
                    display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap',
                  }}>
                    <span className={`tag severity-${item.risk_level}`} style={{ fontSize: '0.68rem', flexShrink: 0 }}>
                      {meta.label}
                    </span>
                    <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', flexShrink: 0 }}>
                      {item.scan_type}
                    </span>
                    <span className="mono" style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.6)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>
                      {item.input_preview}
                    </span>
                    <span style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.25)', flexShrink: 0 }}>
                      {new Date(item.created_at).toLocaleDateString()}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
        )
      ) : (
        <div style={{ marginTop: 16 }}><AccessDenied permission="view_history" /></div>
      )}
    </div>
  )
}

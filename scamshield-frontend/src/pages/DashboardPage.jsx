import React, { useState, useEffect } from 'react'
import { getStats, getHistory } from '../api'
import { getRiskMeta } from '../utils'
import { NavLink } from 'react-router-dom'
import {
  Shield, AlertTriangle, TrendingUp, Activity, Link2, MessageSquare,
  Mail, QrCode, FileText, ChevronRight, CheckCircle, Clock, Zap
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, Legend,
} from 'recharts'

const SCAN_TYPES = [
  { to: '/',        label: 'URL Scanner',      icon: Link2,        color: '#22d3ee', desc: 'Analyse suspicious links and domains' },
  { to: '/email',   label: 'Email Forensics',  icon: Mail,         color: '#a855f7', desc: 'Parse headers, detect spoofing & phishing' },
  { to: '/qr',      label: 'QR Code',          icon: QrCode,       color: '#22d3ee', desc: 'Decode QR images and check destinations' },
  { to: '/file',    label: 'File Analysis',    icon: FileText,     color: '#f59e0b', desc: 'Inspect attachment metadata safely' },
]

function StatCard({ label, value, color, icon: Icon }) {
  return (
    <div className="glass" style={{
      borderRadius: 14, padding: '18px 20px',
      borderColor: `${color}25`,
      display: 'flex', flexDirection: 'column', gap: 8,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</span>
        {Icon && <Icon size={16} style={{ color }} />}
      </div>
      <div style={{ fontSize: '2rem', fontWeight: 900, color }}>{value ?? '—'}</div>
    </div>
  )
}

function RiskBar({ label, value, total, color }) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5, fontSize: '0.8rem' }}>
        <span style={{ color: 'rgba(255,255,255,0.7)', textTransform: 'capitalize' }}>{label}</span>
        <span style={{ color: 'rgba(255,255,255,0.4)' }}>{value} ({pct}%)</span>
      </div>
      <div className="progress-bar">
        <div className="progress-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  )
}

const RISK_COLORS = {
  critical: '#ff2d55',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#22d3ee',
  safe:     '#10b981',
}

export default function DashboardPage() {
  const [stats, setStats]   = useState(null)
  const [recent, setRecent] = useState([])
  const [loading, setLoading] = useState(true)
  const [backendUp, setBackendUp] = useState(null)

  useEffect(() => {
    Promise.all([
      getStats().then(r => { setStats(r.data); setBackendUp(true) }),
      getHistory(5).then(r => setRecent(r.data)),
    ])
      .catch(() => setBackendUp(false))
      .finally(() => setLoading(false))
  }, [])

  // Distribution data for chart
  const distData = stats ? [
    { name: 'Critical', value: stats.critical_count, color: '#ff2d55' },
    { name: 'High',     value: stats.high_count,     color: '#f97316' },
    { name: 'Medium',   value: stats.medium_count,   color: '#f59e0b' },
    { name: 'Low',      value: stats.low_count,       color: '#22d3ee' },
    { name: 'Safe',     value: stats.safe_count,     color: '#10b981' },
  ].filter(d => d.value > 0) : []

  // By scan type chart
  const typeData = stats?.by_scan_type
    ? Object.entries(stats.by_scan_type).map(([k, v]) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), count: v }))
    : []

  return (
    <div style={{ maxWidth: 1060, margin: '0 auto', padding: '0 16px 60px' }}>

      {/* Hero */}
      <div style={{ paddingTop: 24, marginBottom: 36, display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
            <div style={{
              width: 48, height: 48, borderRadius: 14,
              background: 'rgba(34,211,238,0.12)', border: '1px solid rgba(34,211,238,0.3)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Shield size={24} style={{ color: '#22d3ee' }} />
            </div>
            <div>
              <h1 style={{ fontSize: 'clamp(1.4rem, 3vw, 1.9rem)', fontWeight: 900, lineHeight: 1.1 }}>
                <span className="shimmer-text">ScamShield</span> Dashboard
              </h1>
              <p style={{ fontSize: '0.82rem', color: 'rgba(255,255,255,0.4)', marginTop: 4 }}>
                Evidence-based cybersecurity threat detection
              </p>
            </div>
          </div>
        </div>
        {/* Backend status pill */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px', borderRadius: 99,
          background: backendUp === null ? 'rgba(255,255,255,0.05)' : backendUp ? 'rgba(16,185,129,0.1)' : 'rgba(255,45,85,0.1)',
          border: `1px solid ${backendUp === null ? 'rgba(255,255,255,0.1)' : backendUp ? 'rgba(16,185,129,0.3)' : 'rgba(255,45,85,0.3)'}`,
        }}>
          <div style={{
            width: 7, height: 7, borderRadius: '50%',
            background: backendUp === null ? '#94a3b8' : backendUp ? '#10b981' : '#ff2d55',
            animation: backendUp ? 'pulse-ring 2s infinite' : 'none',
          }} />
          <span style={{ fontSize: '0.78rem', color: backendUp ? '#10b981' : 'rgba(255,255,255,0.5)' }}>
            {backendUp === null ? 'Connecting…' : backendUp ? 'Backend Online' : 'Backend Offline'}
          </span>
        </div>
      </div>

      {/* Scan entry points */}
      <div style={{ marginBottom: 36 }}>
        <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 14 }}>
          Analysis Tools
        </h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 12 }}>
          {SCAN_TYPES.map(({ to, label, icon: Icon, color, desc }) => (
            <NavLink key={to} to={to} end={to === '/'} style={{ textDecoration: 'none' }}>
              {({ isActive }) => (
                <div className="glass" style={{
                  borderRadius: 14, padding: '18px 18px', cursor: 'pointer', transition: 'all 0.2s',
                  borderColor: isActive ? `${color}50` : undefined,
                  background: isActive ? `${color}08` : undefined,
                }}
                  onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-3px)'; e.currentTarget.style.borderColor = `${color}40` }}
                  onMouseLeave={e => { e.currentTarget.style.transform = 'none'; e.currentTarget.style.borderColor = isActive ? `${color}50` : '' }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                    <div style={{
                      width: 40, height: 40, borderRadius: 10,
                      background: `${color}18`, border: `1px solid ${color}35`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                      <Icon size={18} style={{ color }} />
                    </div>
                    <ChevronRight size={14} style={{ color: 'rgba(255,255,255,0.25)' }} />
                  </div>
                  <div style={{ fontWeight: 700, fontSize: '0.92rem', marginBottom: 5 }}>{label}</div>
                  <div style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.4)', lineHeight: 1.5 }}>{desc}</div>
                </div>
              )}
            </NavLink>
          ))}
          {/* Message scanner */}
          <NavLink to="/scan" style={{ textDecoration: 'none' }}>
            <div className="glass" style={{ borderRadius: 14, padding: '18px 18px', cursor: 'pointer', transition: 'all 0.2s' }}
              onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-3px)'; e.currentTarget.style.borderColor = 'rgba(249,115,22,0.4)' }}
              onMouseLeave={e => { e.currentTarget.style.transform = 'none'; e.currentTarget.style.borderColor = '' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(249,115,22,0.12)', border: '1px solid rgba(249,115,22,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <MessageSquare size={18} style={{ color: '#f97316' }} />
                </div>
                <ChevronRight size={14} style={{ color: 'rgba(255,255,255,0.25)' }} />
              </div>
              <div style={{ fontWeight: 700, fontSize: '0.92rem', marginBottom: 5 }}>Message Scanner</div>
              <div style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.4)', lineHeight: 1.5 }}>Detect SMS, WhatsApp, and social scams</div>
            </div>
          </NavLink>
        </div>
      </div>

      {/* Stats section */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '40px 0' }}>
          <div className="radar" style={{ margin: '0 auto' }} />
        </div>
      ) : !backendUp ? (
        <div className="glass" style={{ borderRadius: 14, padding: '28px 24px', textAlign: 'center', borderColor: 'rgba(255,45,85,0.2)' }}>
          <AlertTriangle size={32} style={{ color: '#ff2d55', margin: '0 auto 12px', display: 'block' }} />
          <p style={{ color: 'rgba(255,255,255,0.6)', fontSize: '0.92rem', marginBottom: 8 }}>Backend server is not reachable</p>
          <p style={{ color: 'rgba(255,255,255,0.35)', fontSize: '0.82rem' }}>
            Start the backend with: <span className="mono" style={{ color: '#22d3ee' }}>uvicorn main:app --port 8000</span>
          </p>
        </div>
      ) : stats ? (
        <>
          {/* Summary stats */}
          <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 14 }}>
            Detection Summary
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 12, marginBottom: 28 }}>
            <StatCard label="Total Scans" value={stats.total_scans} color="#38bdf8" icon={Activity} />
            <StatCard label="Critical" value={stats.critical_count} color="#ff2d55" icon={AlertTriangle} />
            <StatCard label="High Risk" value={stats.high_count} color="#f97316" icon={Zap} />
            <StatCard label="Safe" value={stats.safe_count} color="#10b981" icon={CheckCircle} />
            <StatCard label="Avg Score" value={stats.average_risk_score ? `${stats.average_risk_score}/100` : '—'} color="#a855f7" icon={TrendingUp} />
          </div>

          {/* Charts */}
          {stats.total_scans > 0 && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20, marginBottom: 28 }}>

              {/* Risk distribution bars */}
              <div className="glass" style={{ borderRadius: 14, padding: '18px 20px' }}>
                <h3 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.5)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 16 }}>
                  Risk Distribution
                </h3>
                {[
                  { label: 'Critical', value: stats.critical_count, color: '#ff2d55' },
                  { label: 'High',     value: stats.high_count,     color: '#f97316' },
                  { label: 'Medium',   value: stats.medium_count,   color: '#f59e0b' },
                  { label: 'Low',      value: stats.low_count,       color: '#22d3ee' },
                  { label: 'Safe',     value: stats.safe_count,     color: '#10b981' },
                ].map(({ label, value, color }) => (
                  <RiskBar key={label} label={label} value={value} total={stats.total_scans} color={color} />
                ))}
              </div>

              {/* By scan type */}
              {typeData.length > 0 && (
                <div className="glass" style={{ borderRadius: 14, padding: '18px 20px' }}>
                  <h3 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.5)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 16 }}>
                    Scans by Type
                  </h3>
                  <ResponsiveContainer width="100%" height={180}>
                    <BarChart data={typeData} margin={{ top: 0, right: 10, bottom: 0, left: -20 }}>
                      <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'rgba(255,255,255,0.4)' }} />
                      <YAxis tick={{ fontSize: 11, fill: 'rgba(255,255,255,0.4)' }} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{ background: '#0d1321', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }}
                        labelStyle={{ color: 'rgba(255,255,255,0.7)' }}
                      />
                      <Bar dataKey="count" fill="#22d3ee" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          )}

          {/* Empty state */}
          {stats.total_scans === 0 && (
            <div className="glass" style={{ borderRadius: 14, padding: '40px 24px', textAlign: 'center', marginBottom: 28 }}>
              <Shield size={40} style={{ color: 'rgba(34,211,238,0.3)', margin: '0 auto 16px', display: 'block' }} />
              <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: '0.95rem', marginBottom: 6 }}>No scans yet</p>
              <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: '0.82rem' }}>
                Start by scanning a suspicious URL, message, email, QR code, or file.
              </p>
            </div>
          )}

          {/* Recent scans */}
          {recent.length > 0 && (
            <>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                  Recent Scans
                </h2>
                <NavLink to="/history" style={{ fontSize: '0.78rem', color: '#22d3ee', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 4 }}>
                  View all <ChevronRight size={13} />
                </NavLink>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {recent.map(item => {
                  const meta = getRiskMeta(item.risk_level)
                  return (
                    <div key={item.id} className="glass" style={{
                      borderRadius: 12, padding: '12px 16px',
                      display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap',
                    }}>
                      <span className={`tag severity-${item.risk_level}`} style={{ fontSize: '0.7rem', flexShrink: 0 }}>
                        {meta.label}
                      </span>
                      <span style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', flexShrink: 0, textTransform: 'uppercase' }}>
                        {item.scan_type}
                      </span>
                      <span className="mono" style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.6)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>
                        {item.input_preview}
                      </span>
                      <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.3)', flexShrink: 0 }}>
                        {new Date(item.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  )
                })}
              </div>
            </>
          )}
        </>
      ) : null}
    </div>
  )
}

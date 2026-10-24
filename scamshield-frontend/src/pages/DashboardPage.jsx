import React, { useState, useEffect } from 'react'
import { getStats, getHistory } from '../api'
import { getRiskMeta, getVerdictMeta } from '../utils'
import { NavLink } from 'react-router-dom'
import {
  Shield, AlertTriangle, TrendingUp, Activity, Link2, MessageSquare,
  Mail, QrCode, FileText, ChevronRight, CheckCircle, Clock, Zap,
  Globe, Database, Server, RefreshCw, Cpu, CheckCircle2, XCircle
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'
import MultiverseHeroCards from '../components/MultiverseHeroCards'

const SCAN_TYPES = [
  { to: '/',        label: 'URL Scanner',      icon: Link2,        color: '#22d3ee', desc: 'Analyse suspicious links and domains with brand registry' },
  { to: '/email',   label: 'Email Forensics',  icon: Mail,         color: '#a855f7', desc: 'Parse headers, detect spoofing & SPF/DKIM' },
  { to: '/qr',      label: 'QR Code',          icon: QrCode,       color: '#22d3ee', desc: 'Decode QR images or scan via camera safely' },
  { to: '/file',    label: 'File Analysis',    icon: FileText,     color: '#f59e0b', desc: 'Inspect attachment metadata and embedded URLs' },
]

function StatCard({ label, value, color, icon: Icon, sub }) {
  return (
    <div className="glass" style={{
      borderRadius: 14, padding: '18px 20px',
      borderColor: `${color}25`,
      display: 'flex', flexDirection: 'column', gap: 6,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</span>
        {Icon && <Icon size={16} style={{ color }} />}
      </div>
      <div style={{ fontSize: '1.85rem', fontWeight: 900, color }}>{value ?? '—'}</div>
      {sub && <div style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.32)' }}>{sub}</div>}
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

export default function DashboardPage() {
  const [stats, setStats] = useState(null)
  const [recent, setRecent] = useState([])
  const [loading, setLoading] = useState(true)
  const [backendUp, setBackendUp] = useState(null)
  const [lastRefreshed, setLastRefreshed] = useState(null)

  const loadDashboardData = () => {
    setLoading(true)
    Promise.all([
      getStats().then(r => { setStats(r.data); setBackendUp(true) }),
      getHistory(5).then(r => setRecent(r.data)),
    ])
      .then(() => setLastRefreshed(new Date()))
      .catch(() => setBackendUp(false))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadDashboardData()
  }, [])

  // By scan type chart
  const typeData = stats?.by_scan_type
    ? Object.entries(stats.by_scan_type).map(([k, v]) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), count: v }))
    : []

  return (
    <div style={{ maxWidth: 1060, margin: '0 auto', padding: '0 16px 60px' }}>

      {/* Header */}
      <div style={{ paddingTop: 24, marginBottom: 36, display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 12, flexWrap: 'wrap' }}>
            <img
              src="/assets/scamshield-logo.png"
              alt="ScamShield Official Brand Identity"
              style={{ height: 56, width: 'auto', objectFit: 'contain', aspectRatio: '684 / 356' }}
            />
            <div>
              <h1 style={{ fontSize: 'clamp(1.3rem, 2.8vw, 1.8rem)', fontWeight: 900, lineHeight: 1.1 }}>
                <span className="shimmer-text">Threat Intelligence Command Center</span>
              </h1>
              <p style={{ fontSize: '0.82rem', color: 'rgba(255,255,255,0.45)', marginTop: 4 }}>
                Real-time multi-vector threat detection & persisted operational forensics
              </p>
            </div>
          </div>
        </div>

        {/* Backend status pill & refresh */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {lastRefreshed && (
            <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.3)' }}>
              Updated {lastRefreshed.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={loadDashboardData}
            className="btn-ghost"
            style={{ fontSize: '0.78rem', padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
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
      </div>

      {/* Multiverse Sentinel Matrix - 3 Themed Cards with Uploaded Artworks */}
      <MultiverseHeroCards />

      {/* Scan entry points */}
      <div style={{ marginBottom: 36 }}>
        <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 14 }}>
          What do you want to check?
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
          {/* Real deployment metrics */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, flexWrap: 'wrap', gap: 10 }}>
            <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Live Deployment Measurements
            </h2>
            <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.3)' }}>
              Source: Local SQLite database audit logs
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 12, marginBottom: 28 }}>
            <StatCard label="Total Scans" value={stats.total_scans} color="#38bdf8" icon={Activity} sub="Logged in this deployment" />
            <StatCard label="URL Scans" value={stats.url_scans_count ?? stats.by_scan_type?.url ?? 0} color="#22d3ee" icon={Link2} sub="Analyzed links" />
            <StatCard label="QR Scans" value={stats.qr_scans_count ?? stats.by_scan_type?.qr ?? 0} color="#a855f7" icon={QrCode} sub="Decoded payloads" />
            <StatCard label="Malicious" value={stats.malicious_count ?? (stats.critical_count + stats.high_count)} color="#ff2d55" icon={AlertTriangle} sub="Confirmed threats" />
            <StatCard label="Suspicious" value={stats.suspicious_count ?? stats.medium_count} color="#f59e0b" icon={Zap} sub="Elevated risk indicators" />
            <StatCard label="No Threat Found" value={stats.no_known_threat_count ?? (stats.safe_count + stats.low_count)} color="#10b981" icon={CheckCircle} sub="Passed heuristics" />
            <StatCard label="Unique URLs" value={stats.unique_urls_analyzed ?? '0'} color="#0891b2" icon={Globe} sub="Distinct addresses" />
          </div>

          {/* External Threat Intelligence Status & Benchmark Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 20, marginBottom: 28 }}>

            {/* External Threat Intelligence Status */}
            <div className="glass" style={{ borderRadius: 14, padding: '20px 22px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                <h3 style={{ fontSize: '0.85rem', fontWeight: 800, color: 'rgba(255,255,255,0.8)', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Server size={15} style={{ color: '#22d3ee' }} />
                  Threat Intelligence Status
                </h3>
                <span style={{ fontSize: '0.7rem', color: '#10b981', background: 'rgba(16,185,129,0.1)', padding: '3px 8px', borderRadius: 6 }}>
                  Active Feed
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {/* URLhaus */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: 10 }}>
                  <div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 700 }}>URLhaus (abuse.ch)</div>
                    <div style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)' }}>Verified malware/phishing feed (Free API)</div>
                  </div>
                  <span style={{ fontSize: '0.72rem', color: '#10b981', fontWeight: 700 }}>● Online</span>
                </div>

                {/* VirusTotal */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: 10 }}>
                  <div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 700 }}>VirusTotal v3</div>
                    <div style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)' }}>
                      {stats.threat_intel_providers?.VirusTotal?.configured ? 'API key active' : 'Server key not set (optional)'}
                    </div>
                  </div>
                  <span style={{ fontSize: '0.72rem', color: stats.threat_intel_providers?.VirusTotal?.configured ? '#10b981' : 'rgba(255,255,255,0.3)', fontWeight: 700 }}>
                    {stats.threat_intel_providers?.VirusTotal?.configured ? '● Connected' : '○ Standby'}
                  </span>
                </div>

                {/* Google Safe Browsing */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: 10 }}>
                  <div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 700 }}>Google Safe Browsing</div>
                    <div style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)' }}>
                      {stats.threat_intel_providers?.['Google Safe Browsing']?.configured ? 'API key active' : 'Server key not set (optional)'}
                    </div>
                  </div>
                  <span style={{ fontSize: '0.72rem', color: stats.threat_intel_providers?.['Google Safe Browsing']?.configured ? '#10b981' : 'rgba(255,255,255,0.3)', fontWeight: 700 }}>
                    {stats.threat_intel_providers?.['Google Safe Browsing']?.configured ? '● Connected' : '○ Standby'}
                  </span>
                </div>
              </div>
            </div>

            {/* Offline Model & Benchmark Evaluation Metrics */}
            <div className="glass" style={{ borderRadius: 14, padding: '20px 22px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                <h3 style={{ fontSize: '0.85rem', fontWeight: 800, color: 'rgba(255,255,255,0.8)', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Cpu size={15} style={{ color: '#a855f7' }} />
                  Verified Evaluation Metrics
                </h3>
                <NavLink to="/demo" style={{ fontSize: '0.74rem', color: '#a855f7', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 2 }}>
                  Run Tests <ChevronRight size={12} />
                </NavLink>
              </div>

              {stats.benchmark_evaluation ? (
                <div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
                    <div style={{ padding: '12px', background: 'rgba(168,85,247,0.08)', borderRadius: 10, border: '1px solid rgba(168,85,247,0.2)' }}>
                      <div style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase' }}>Precision</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 900, color: '#a855f7' }}>{stats.benchmark_evaluation.precision_pct}%</div>
                      <div style={{ fontSize: '0.68rem', color: 'rgba(255,255,255,0.3)' }}>{stats.benchmark_evaluation.false_positives} False Positives</div>
                    </div>
                    <div style={{ padding: '12px', background: 'rgba(16,185,129,0.08)', borderRadius: 10, border: '1px solid rgba(16,185,129,0.2)' }}>
                      <div style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase' }}>Accuracy</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 900, color: '#10b981' }}>{stats.benchmark_evaluation.accuracy_pct}%</div>
                      <div style={{ fontSize: '0.68rem', color: 'rgba(255,255,255,0.3)' }}>{stats.benchmark_evaluation.dataset_size} Verified Samples</div>
                    </div>
                  </div>

                  <p style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)', lineHeight: 1.5 }}>
                    Evaluated against documented regression dataset including genuine Instagram, Snapchat, YouTube, and verified threat samples.
                  </p>
                </div>
              ) : (
                <p style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.4)' }}>Evaluation dataset not loaded.</p>
              )}
            </div>
          </div>

          {/* Charts */}
          {stats.total_scans > 0 && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20, marginBottom: 28 }}>

              {/* Risk distribution bars */}
              <div className="glass" style={{ borderRadius: 14, padding: '18px 20px' }}>
                <h3 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.5)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 16 }}>
                  Risk Distribution (Deployment)
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
              <p style={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.95rem', marginBottom: 6, fontWeight: 700 }}>No scans recorded in this deployment yet</p>
              <p style={{ color: 'rgba(255,255,255,0.35)', fontSize: '0.82rem' }}>
                All statistics are calculated exclusively from actual scans. Start by scanning a URL or QR code above.
              </p>
            </div>
          )}

          {/* Recent scans */}
          {recent.length > 0 && (
            <>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                <h2 style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                  Recent Deployment Scans
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
                        {new Date(item.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
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

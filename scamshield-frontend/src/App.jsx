import React, { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, NavLink, useLocation, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth, useIsAdmin, useIsSuperAdmin } from './context/AuthContext'
import { ThemeProvider } from './context/ThemeContext'

// Existing pages
import DashboardPage from './pages/DashboardPage'
import ScanPage from './pages/ScanPage'
import HistoryPage from './pages/HistoryPage'
import DemoPage from './pages/DemoPage'
import LearnPage from './pages/LearnPage'
import EmailPage from './pages/EmailPage'
import QRPage from './pages/QRPage'
import FilePage from './pages/FilePage'

// New admin pages
import AdminLogin from './pages/admin/AdminLogin'
import AdminDashboard from './pages/admin/AdminDashboard'
import SuperAdminDashboard from './pages/superadmin/SuperAdminDashboard'

// New components
import ParticleCanvas from './components/ParticleCanvas'
import NotificationBell from './components/NotificationBell'
import HeroBackground from './components/HeroBackground'
import FuturisticCursor from './components/FuturisticCursor'
import MatrixRain from './components/MatrixRain'


import {
  Shield, LayoutDashboard, Link2, MessageSquare, Clock,
  FlaskConical, BookOpen, Mail, QrCode, FileText, Menu, X,
  Lock
} from 'lucide-react'

const NAV_SECTIONS = [
  {
    label: 'Main',
    items: [
      { to: '/dashboard', label: 'Dashboard',      icon: LayoutDashboard },
      { to: '/',          label: 'URL Scanner',     icon: Link2,           end: true },
      { to: '/scan',      label: 'Message Scanner', icon: MessageSquare },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { to: '/email', label: 'Email Forensics', icon: Mail },
      { to: '/qr',    label: 'QR Scanner',      icon: QrCode },
      { to: '/file',  label: 'File Analysis',   icon: FileText },
    ],
  },
  {
    label: 'Tools',
    items: [
      { to: '/history', label: 'History',   icon: Clock },
      { to: '/demo',    label: 'Benchmark', icon: FlaskConical },
      { to: '/learn',   label: 'Learn',     icon: BookOpen },
    ],
  },
]

// ── Protected Routes ────────────────────────────────────────────────────
function RequireAdmin({ children }) {
  const { user, loading } = useAuth()
  if (loading) return null
  if (!user) return <Navigate to="/admin/login" replace />
  if (user.role !== 'admin' && user.role !== 'superadmin') return <Navigate to="/admin/login" replace />
  return children
}

function RequireSuperAdmin({ children }) {
  const { user, loading } = useAuth()
  if (loading) return null
  if (!user || user.role !== 'superadmin') return <Navigate to="/admin/login" replace />
  return children
}

// ── Sidebar ─────────────────────────────────────────────────────────────
function Sidebar({ open, onClose }) {
  const { user } = useAuth()
  const isAdmin = useIsAdmin()

  return (
    <>
      {open && (
        <div
          onClick={onClose}
          style={{
            position: 'fixed', inset: 0,
            background: 'rgba(0,0,0,0.6)',
            zIndex: 90,
            backdropFilter: 'blur(4px)',
          }}
        />
      )}
      <aside style={{
        width: 248, flexShrink: 0,
        background: 'rgba(8,11,20,0.97)',
        borderRight: '1px solid rgba(99,179,237,0.09)',
        display: 'flex', flexDirection: 'column',
        position: 'fixed', top: 0, bottom: 0, left: 0,
        zIndex: 100,
        transform: open ? 'translateX(0)' : 'translateX(-100%)',
        transition: 'transform 0.28s cubic-bezier(0.4,0,0.2,1)',
      }}>
        {/* Logo */}
        <div style={{ padding: '16px 14px 14px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <NavLink
              to="/dashboard"
              onClick={onClose}
              className="brand-nav-link"
              aria-label="Go to ScamShield Dashboard"
              style={{ padding: 0 }}
            >
              <img
                src="/assets/scamshield-logo.png"
                alt="ScamShield Official Brand Artwork"
                style={{ height: 42, width: 'auto', objectFit: 'contain', aspectRatio: '684 / 356' }}
              />
            </NavLink>
            <button
              onClick={onClose}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.4)', padding: 4 }}
              aria-label="Close navigation"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ padding: '12px 10px', flex: 1, overflowY: 'auto' }}>
          {NAV_SECTIONS.map(({ label, items }) => (
            <div key={label} style={{ marginBottom: 18 }}>
              <div style={{ fontSize: '0.6rem', color: 'rgba(255,255,255,0.22)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 6, paddingLeft: 6 }}>
                {label}
              </div>
              {items.map(({ to, label: lbl, icon: Icon, end }) => (
                <NavLink
                  key={to} to={to} end={end}
                  className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
                  onClick={onClose}
                  style={{ display: 'flex', textDecoration: 'none', marginBottom: 2 }}
                >
                  <Icon size={16} />
                  <span>{lbl}</span>
                </NavLink>
              ))}
            </div>
          ))}

          {/* Admin section */}
          {isAdmin && (
            <div style={{ marginBottom: 18 }}>
              <div style={{ fontSize: '0.6rem', color: 'rgba(168,85,247,0.5)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 6, paddingLeft: 6 }}>
                Admin
              </div>
              <NavLink
                to="/admin/dashboard"
                className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
                onClick={onClose}
                style={{ display: 'flex', textDecoration: 'none', marginBottom: 2 }}
              >
                <Lock size={16} />
                <span>Admin Panel</span>
              </NavLink>
              {user?.role === 'superadmin' && (
                <NavLink
                  to="/superadmin/dashboard"
                  className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
                  onClick={onClose}
                  style={{ display: 'flex', textDecoration: 'none' }}
                >
                  <Shield size={16} style={{ color: '#22d3ee' }} />
                  <span style={{ color: '#22d3ee' }}>Super Admin</span>
                </NavLink>
              )}
            </div>
          )}
        </nav>

        {/* Footer */}
        <div style={{ padding: '14px 18px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
          {user && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8,
              padding: '8px 10px', borderRadius: 10,
              background: 'rgba(34,211,238,0.06)', border: '1px solid rgba(34,211,238,0.12)',
            }}>
              <div style={{
                width: 28, height: 28, borderRadius: 8,
                background: user.role === 'superadmin' ? 'rgba(34,211,238,0.2)' : 'rgba(168,85,247,0.15)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Shield size={13} style={{ color: user.role === 'superadmin' ? '#22d3ee' : '#a855f7' }} />
              </div>
              <div>
                <div style={{ fontSize: '0.75rem', fontWeight: 700 }}>{user.username}</div>
                <div style={{ fontSize: '0.6rem', color: 'rgba(255,255,255,0.35)', textTransform: 'uppercase' }}>
                  {user.role === 'superadmin' ? 'Super Admin' : 'Admin'}
                </div>
              </div>
            </div>
          )}
          <div style={{ fontSize: '0.66rem', color: 'rgba(255,255,255,0.18)', lineHeight: 1.7 }}>
            ScamShield v3.0<br />
            Protecting real people from real scams
          </div>
        </div>
      </aside>
    </>
  )
}

// ── Top Bar ──────────────────────────────────────────────────────────────
function TopBar({ onMenu }) {
  const location = useLocation()
  const allItems = NAV_SECTIONS.flatMap(s => s.items)
  const current = allItems.find(n =>
    n.end
      ? location.pathname === n.to
      : location.pathname === n.to || (n.to !== '/' && location.pathname.startsWith(n.to))
  )
  const Icon = current?.icon ?? Shield

  return (
    <header style={{
      position: 'fixed', top: 0, left: 0, right: 0, zIndex: 50,
      height: 54,
      background: 'rgba(8,11,20,0.9)',
      backdropFilter: 'blur(16px)',
      borderBottom: '1px solid rgba(99,179,237,0.09)',
      display: 'flex', alignItems: 'center', padding: '0 16px', gap: 12,
    }}>
      <button
        onClick={onMenu}
        style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.55)', display: 'flex', alignItems: 'center', padding: 4 }}
        aria-label="Open navigation"
      >
        <Menu size={21} />
      </button>
      {/* Top-Left Official Brand Artwork — Navigates directly to Real Dashboard */}
      <NavLink
        to="/dashboard"
        className="brand-nav-link"
        aria-label="ScamShield Dashboard"
      >
        <img
          src="/assets/scamshield-logo.png"
          alt="ScamShield Official Logo"
          className="brand-logo-desktop"
          style={{ height: 36, width: 'auto', objectFit: 'contain', aspectRatio: '684 / 356' }}
        />
        <div className="brand-logo-mobile">
          <img
            src="/shield-symbol.svg"
            alt="ScamShield Shield"
            style={{ width: 28, height: 28, objectFit: 'contain' }}
          />
          <span style={{ fontWeight: 900, fontSize: '0.98rem', letterSpacing: '-0.02em' }}>
            Scam<span style={{ color: '#22d3ee' }}>Shield</span>
          </span>
        </div>
      </NavLink>
      {current && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{ color: 'rgba(255,255,255,0.2)' }}>/</span>
          <Icon size={14} style={{ color: 'rgba(255,255,255,0.45)' }} />
          <span style={{ fontSize: '0.85rem', color: 'rgba(255,255,255,0.45)' }}>{current.label}</span>
        </div>
      )}

      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
        <NotificationBell />
        <NavLink to="/admin/login" style={{ textDecoration: 'none' }}>
          <button style={{
            background: 'none', border: '1px solid rgba(99,179,237,0.15)',
            borderRadius: 10, padding: '5px 12px', cursor: 'pointer',
            color: 'rgba(255,255,255,0.4)', fontSize: '0.78rem',
            display: 'flex', alignItems: 'center', gap: 5,
            transition: 'all 0.2s',
          }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(34,211,238,0.4)'; e.currentTarget.style.color = '#22d3ee' }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(99,179,237,0.15)'; e.currentTarget.style.color = 'rgba(255,255,255,0.4)' }}
          >
            <Lock size={12} /> Admin
          </button>
        </NavLink>
      </div>
    </header>
  )
}

// ── Main Layout ──────────────────────────────────────────────────────────
function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const location = useLocation()
  const isExcluded = location.pathname.startsWith('/admin/dashboard') || location.pathname.startsWith('/superadmin/dashboard')

  return (
    <div className="grid-bg" style={{ minHeight: '100vh', position: 'relative' }}>
      {/* Animated Desktop Futuristic Cursor */}
      <FuturisticCursor />

      {/* Horror Cyber Matrix Rain */}
      <MatrixRain opacity={0.14} />

      {/* Data-corruption noise film grain */}
      <div className="horror-noise-overlay" />

      {/* Multiverse Hero Parallax 3D Background with codeverse-art.webp */}
      {!isExcluded && <HeroBackground />}

      {/* Particle system */}
      <ParticleCanvas theme="cyan" />

      {/* Ambient glows */}
      <div style={{ position: 'fixed', top: -200, left: -200, width: 600, height: 600, borderRadius: '50%', background: 'radial-gradient(circle, rgba(34,211,238,0.04) 0%, transparent 70%)', pointerEvents: 'none', zIndex: 0 }} />
      <div style={{ position: 'fixed', bottom: -200, right: -200, width: 600, height: 600, borderRadius: '50%', background: 'radial-gradient(circle, rgba(168,85,247,0.04) 0%, transparent 70%)', pointerEvents: 'none', zIndex: 0 }} />
      <div style={{ position: 'fixed', top: '40%', right: '-10%', width: 400, height: 400, borderRadius: '50%', background: 'radial-gradient(circle, rgba(249,115,22,0.03) 0%, transparent 70%)', pointerEvents: 'none', zIndex: 0 }} />

      <TopBar onMenu={() => setSidebarOpen(o => !o)} />
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <main style={{ paddingTop: 54, minHeight: '100vh', position: 'relative', zIndex: 1 }}>
        <div style={{ maxWidth: 1100, margin: '0 auto' }}>
          <Routes>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/"          element={<ScanPage defaultTab="url" />} />
            <Route path="/scan"      element={<ScanPage defaultTab="message" />} />
            <Route path="/email"     element={<EmailPage />} />
            <Route path="/qr"        element={<QRPage />} />
            <Route path="/file"      element={<FilePage />} />
            <Route path="/history"   element={<HistoryPage />} />
            <Route path="/demo"      element={<DemoPage />} />
            <Route path="/learn"     element={<LearnPage />} />
            {/* Admin routes */}
            <Route path="/admin/login"      element={<AdminLogin />} />
            <Route path="/superadmin/login" element={<AdminLogin isSuperAdminMode={true} />} />
            <Route path="/admin/dashboard"  element={<RequireAdmin><AdminDashboard /></RequireAdmin>} />
            <Route path="/superadmin/dashboard" element={<RequireSuperAdmin><SuperAdminDashboard /></RequireSuperAdmin>} />
          </Routes>
        </div>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <AuthProvider>
          <Layout />
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  )
}


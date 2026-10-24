import React, { useState } from 'react'
import { BrowserRouter, Routes, Route, NavLink, useLocation } from 'react-router-dom'
import DashboardPage from './pages/DashboardPage'
import ScanPage from './pages/ScanPage'
import HistoryPage from './pages/HistoryPage'
import DemoPage from './pages/DemoPage'
import LearnPage from './pages/LearnPage'
import EmailPage from './pages/EmailPage'
import QRPage from './pages/QRPage'
import FilePage from './pages/FilePage'
import {
  Shield, LayoutDashboard, Link2, MessageSquare, Clock,
  FlaskConical, BookOpen, Mail, QrCode, FileText, ChevronLeft, Menu, X
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
      { to: '/history', label: 'History',  icon: Clock },
      { to: '/demo',    label: 'Benchmark',icon: FlaskConical },
      { to: '/learn',   label: 'Learn',    icon: BookOpen },
    ],
  },
]

function Sidebar({ open, onClose }) {
  return (
    <>
      {/* Overlay */}
      {open && (
        <div
          onClick={onClose}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 90 }}
        />
      )}
      <aside style={{
        width: 240, flexShrink: 0,
        background: 'rgba(8,11,20,0.97)',
        borderRight: '1px solid rgba(99,179,237,0.09)',
        display: 'flex', flexDirection: 'column',
        position: 'fixed', top: 0, bottom: 0, left: 0,
        zIndex: 100,
        transform: open ? 'translateX(0)' : 'translateX(-100%)',
        transition: 'transform 0.25s cubic-bezier(0.4,0,0.2,1)',
      }}>
        {/* Logo */}
        <div style={{ padding: '20px 18px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 11 }}>
              <div style={{
                width: 38, height: 38, borderRadius: 10,
                background: 'linear-gradient(135deg, rgba(8,145,178,0.4), rgba(168,85,247,0.3))',
                border: '1px solid rgba(34,211,238,0.3)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Shield size={18} style={{ color: '#22d3ee' }} />
              </div>
              <div>
                <div style={{ fontWeight: 900, fontSize: '1.05rem', letterSpacing: '-0.02em' }}>
                  Scam<span style={{ color: '#22d3ee' }}>Shield</span>
                </div>
                <div style={{ fontSize: '0.62rem', color: 'rgba(255,255,255,0.3)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                  Threat Detector
                </div>
              </div>
            </div>
            <button
              onClick={onClose}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.3)', padding: 4 }}
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ padding: '12px 10px', flex: 1, overflowY: 'auto' }}>
          {NAV_SECTIONS.map(({ label, items }) => (
            <div key={label} style={{ marginBottom: 18 }}>
              <div style={{ fontSize: '0.6rem', color: 'rgba(255,255,255,0.25)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 6, paddingLeft: 6 }}>
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
        </nav>

        {/* Footer */}
        <div style={{ padding: '14px 18px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
          <div style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.2)', lineHeight: 1.7 }}>
            ScamShield v2.0<br />
            Evidence-based detection<br />
            <span style={{ color: 'rgba(255,255,255,0.12)' }}>Vedathon 2.0</span>
          </div>
        </div>
      </aside>
    </>
  )
}

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
      background: 'rgba(8,11,20,0.88)', backdropFilter: 'blur(14px)',
      borderBottom: '1px solid rgba(99,179,237,0.09)',
      display: 'flex', alignItems: 'center', padding: '0 16px', gap: 12,
    }}>
      <button onClick={onMenu} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.55)', display: 'flex', alignItems: 'center', padding: 4 }}>
        <Menu size={21} />
      </button>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
        <Shield size={17} style={{ color: '#22d3ee' }} />
        <span style={{ fontWeight: 800, fontSize: '0.97rem' }}>Scam<span style={{ color: '#22d3ee' }}>Shield</span></span>
      </div>
      {current && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{ color: 'rgba(255,255,255,0.2)' }}>/</span>
          <Icon size={14} style={{ color: 'rgba(255,255,255,0.45)' }} />
          <span style={{ fontSize: '0.85rem', color: 'rgba(255,255,255,0.45)' }}>{current.label}</span>
        </div>
      )}
    </header>
  )
}

function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  return (
    <div className="grid-bg" style={{ minHeight: '100vh' }}>
      {/* Ambient glows */}
      <div style={{ position: 'fixed', top: -200, left: -200, width: 600, height: 600, borderRadius: '50%', background: 'radial-gradient(circle, rgba(34,211,238,0.035) 0%, transparent 70%)', pointerEvents: 'none' }} />
      <div style={{ position: 'fixed', bottom: -200, right: -200, width: 600, height: 600, borderRadius: '50%', background: 'radial-gradient(circle, rgba(168,85,247,0.035) 0%, transparent 70%)', pointerEvents: 'none' }} />

      <TopBar onMenu={() => setSidebarOpen(o => !o)} />
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <main style={{ paddingTop: 54, minHeight: '100vh', position: 'relative' }}>
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
          </Routes>
        </div>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Layout />
    </BrowserRouter>
  )
}

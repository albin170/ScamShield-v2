import React, { useState, useEffect, useRef } from 'react'
import { analyzeURL, analyzeMessage } from '../api'
import ResultPanel from '../components/ResultPanel'
import TypingPlaceholder from '../components/TypingPlaceholder'
import {
  Link2, MessageSquare, Scan, X, AlertTriangle, CheckCircle2,
  Clock, Camera, Sparkles, Play, AlertOctagon, ShieldAlert
} from 'lucide-react'

const SAMPLE_SCAM_URL = 'http://paypal-login-secure.tk/verify?account=suspended&redirect=http://evil.com'
const SAMPLE_INSTAGRAM_URL = 'https://www.instagram.com/scamshield_official/'
const SAMPLE_SNAPCHAT_URL = 'https://www.snapchat.com/add/secops_team'
const SAMPLE_YOUTUBE_URL = 'https://youtu.be/dQw4w9WgXcQ'
const SAMPLE_SCAM_MSG = `URGENT: Your SBI account has been BLOCKED due to unusual activity. Verify your Aadhaar number and OTP immediately at http://sbi-verify.tk/login or your account will be permanently suspended within 24 hours. Do not ignore this message.`
const SAMPLE_LEGIT_MSG = `Hi! Your Amazon order #112-3456789 for "Wireless Headphones" has been shipped. Expected delivery: Thursday. Track your order at amazon.com/orders.`

const STAGES = [
  'Validating syntax, punycode & internationalized domain structures',
  'Cross-referencing brand registry and homoglyph dictionaries',
  'Querying live threat intelligence feeds (URLhaus & safety indicators)',
  'Evaluating cryptographic signatures and scoring multi-signal heuristics',
]

export default function ScanPage({ defaultTab = 'url' }) {
  const [tab, setTab] = useState(defaultTab)
  const [urlInput, setUrlInput] = useState('')
  const [msgInput, setMsgInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [activeStage, setActiveStage] = useState(0)

  // Typing animation & edge glow state
  const [isTyping, setIsTyping] = useState(false)
  const typingTimeoutRef = useRef(null)

  // Cycle through real processing stages while loading
  useEffect(() => {
    if (!loading) {
      setActiveStage(0)
      return
    }
    const interval = setInterval(() => {
      setActiveStage(prev => (prev < STAGES.length - 1 ? prev + 1 : prev))
    }, 600)
    return () => clearInterval(interval)
  }, [loading])

  const handleUrlChange = (e) => {
    setUrlInput(e.target.value)
    setIsTyping(true)
    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current)
    typingTimeoutRef.current = setTimeout(() => setIsTyping(false), 450)
  }

  const handleMsgChange = (e) => {
    setMsgInput(e.target.value)
    setIsTyping(true)
    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current)
    typingTimeoutRef.current = setTimeout(() => setIsTyping(false), 450)
  }

  async function handleScan() {
    setError('')
    setResult(null)
    setLoading(true)
    setActiveStage(0)
    try {
      if (tab === 'url') {
        const res = await analyzeURL(urlInput.trim())
        setResult(res.data)
      } else {
        const res = await analyzeMessage(msgInput.trim())
        setResult(res.data)
      }
    } catch (err) {
      setError(err?.response?.data?.detail || 'Backend unreachable. Is the server running on port 8000?')
    } finally {
      setLoading(false)
    }
  }

  function loadSample(type) {
    setResult(null)
    setError('')
    if (type === 'scam-url')      { setTab('url'); setUrlInput(SAMPLE_SCAM_URL) }
    if (type === 'instagram-url') { setTab('url'); setUrlInput(SAMPLE_INSTAGRAM_URL) }
    if (type === 'snapchat-url')  { setTab('url'); setUrlInput(SAMPLE_SNAPCHAT_URL) }
    if (type === 'youtube-url')   { setTab('url'); setUrlInput(SAMPLE_YOUTUBE_URL) }
    if (type === 'scam-msg')      { setTab('message'); setMsgInput(SAMPLE_SCAM_MSG) }
    if (type === 'legit-msg')     { setTab('message'); setMsgInput(SAMPLE_LEGIT_MSG) }
  }

  const canScan = tab === 'url' ? urlInput.trim().length > 3 : msgInput.trim().length > 10

  return (
    <div style={{ maxWidth: 840, margin: '0 auto', padding: '0 16px 60px' }}>

      {/* ── Header ────────────────────────────────────────────────────── */}
      <div style={{ textAlign: 'center', marginBottom: 36, paddingTop: 20 }}>
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: 8,
          padding: '5px 14px', borderRadius: 99,
          background: 'rgba(255, 45, 85, 0.08)', border: '1px solid rgba(255, 45, 85, 0.25)',
          marginBottom: 14
        }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#ff2d55', boxShadow: '0 0 8px #ff2d55' }} />
          <span className="font-creepster" style={{ fontSize: '0.95rem', color: '#ff4d6d', letterSpacing: '0.08em' }}>
            ZERO-TRUST FORENSIC SCANNER
          </span>
        </div>
        <h1 style={{ fontSize: 'clamp(1.7rem, 4vw, 2.3rem)', fontWeight: 900, marginBottom: 10, letterSpacing: '-0.02em' }}>
          <span className="shimmer-text">Scam & Phishing Analysis</span>
        </h1>
        <p style={{ color: 'rgba(255,255,255,0.55)', fontSize: '0.92rem', maxWidth: 580, margin: '0 auto', lineHeight: 1.6 }}>
          Inspect suspicious links, SMS lures, and credential theft attempts backed by deterministic evidence and live threat intelligence.
        </p>
      </div>

      {/* ── Tab selector ──────────────────────────────────────────────── */}
      <div className="tab-bar" style={{ marginBottom: 20 }}>
        <button className={`tab-item ${tab === 'url' ? 'active' : ''}`} onClick={() => { setTab('url'); setResult(null); setError('') }}>
          <Link2 size={16} /> Link Scanner
        </button>
        <button className={`tab-item ${tab === 'message' ? 'active' : ''}`} onClick={() => { setTab('message'); setResult(null); setError('') }}>
          <MessageSquare size={16} /> Message Scanner
        </button>
      </div>

      {/* ── Input area ────────────────────────────────────────────────── */}
      <div className="glass" style={{ borderRadius: 16, padding: 22, marginBottom: 16 }}>
        {tab === 'url' ? (
          <div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.82rem', color: 'rgba(255,255,255,0.6)', marginBottom: 8, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              <Link2 size={13} style={{ color: '#22d3ee' }} /> Target URL Destination
            </label>
            <div className="has-typing-placeholder horror-input-wrapper" style={{ position: 'relative' }}>
              <TypingPlaceholder scanType="url" value={urlInput} />
              <input
                className={`input-field mono horror-input font-mono-tech ${isTyping ? 'typing-active' : ''} ${loading ? 'analyzing-active' : ''}`}
                placeholder="https://example.com/path?query=value"
                value={urlInput}
                onChange={handleUrlChange}
                onKeyDown={e => e.key === 'Enter' && canScan && !loading && handleScan()}
                aria-label="Target URL to inspect"
                autoComplete="off"
                spellCheck="false"
              />
              {urlInput && (
                <button
                  onClick={() => setUrlInput('')}
                  style={{
                    position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.3)',
                    zIndex: 4,
                  }}
                  aria-label="Clear URL input"
                >
                  <X size={16} />
                </button>
              )}
            </div>
          </div>
        ) : (
          <div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.82rem', color: 'rgba(255,255,255,0.6)', marginBottom: 8, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              <MessageSquare size={13} style={{ color: '#f97316' }} /> Suspicious Message Text
            </label>
            <div className="has-typing-placeholder horror-input-wrapper" style={{ position: 'relative' }}>
              <TypingPlaceholder scanType="message" value={msgInput} multiline={true} />
              <textarea
                className={`input-field horror-input font-mono-tech ${isTyping ? 'typing-active' : ''} ${loading ? 'analyzing-active' : ''}`}
                rows={5}
                placeholder="Paste the suspicious message content here…"
                value={msgInput}
                onChange={handleMsgChange}
                aria-label="Suspicious message content to inspect"
                spellCheck="false"
              />
            </div>
            <div style={{ textAlign: 'right', fontSize: '0.75rem', color: 'rgba(255,255,255,0.35)', marginTop: 4 }}>
              {msgInput.length} characters analyzed
            </div>
          </div>
        )}

        {/* ── Action row ─────────────────────────────────────────────── */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 18, flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)', marginRight: 4 }}>Examples:</span>
            <button className="btn-ghost" onClick={() => loadSample('instagram-url')} style={{ fontSize: '0.74rem', padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 5 }}>
              <Camera size={13} style={{ color: '#e1306c' }} /> Instagram
            </button>
            <button className="btn-ghost" onClick={() => loadSample('snapchat-url')} style={{ fontSize: '0.74rem', padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 5 }}>
              <Sparkles size={13} style={{ color: '#eab308' }} /> Snapchat
            </button>
            <button className="btn-ghost" onClick={() => loadSample('youtube-url')} style={{ fontSize: '0.74rem', padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 5 }}>
              <Play size={13} style={{ color: '#ef4444' }} /> YouTube
            </button>
            <button className="btn-ghost" onClick={() => loadSample('scam-url')} style={{ fontSize: '0.74rem', padding: '4px 10px', color: '#ff2d55', display: 'flex', alignItems: 'center', gap: 5 }}>
              <AlertOctagon size={13} style={{ color: '#ff2d55' }} /> Phishing Link
            </button>
            <button className="btn-ghost" onClick={() => loadSample('scam-msg')} style={{ fontSize: '0.74rem', padding: '4px 10px', color: '#ff2d55', display: 'flex', alignItems: 'center', gap: 5 }}>
              <ShieldAlert size={13} style={{ color: '#ff2d55' }} /> Smishing SMS
            </button>
          </div>

          <button
            className="btn-primary"
            onClick={handleScan}
            disabled={!canScan || loading}
            style={{ display: 'flex', alignItems: 'center', gap: 8 }}
          >
            {loading ? (
              <>
                <span style={{ width: 16, height: 16, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'radar-spin 0.7s linear infinite', display: 'inline-block' }} />
                Inspecting Indicators…
              </>
            ) : (
              <><Scan size={16} /> Execute Scan</>
            )}
          </button>
        </div>
      </div>

      {/* ── Error Alert ─────────────────────────────────────────────────── */}
      {error && (
        <div style={{
          background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)',
          borderRadius: 12, padding: '14px 18px', marginBottom: 20,
          display: 'flex', alignItems: 'center', gap: 10,
        }}>
          <AlertTriangle size={18} style={{ color: '#ff2d55', flexShrink: 0 }} />
          <span style={{ fontSize: '0.9rem', color: 'rgba(255,255,255,0.85)' }}>{error}</span>
        </div>
      )}

      {/* ── Loading with Transparent Pipeline Stages ───────────────────── */}
      {loading && (
        <div className="glass" style={{ borderRadius: 16, padding: '32px 24px', marginBottom: 24, textAlign: 'center' }}>
          <div className="radar" style={{ margin: '0 auto 20px' }} />
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: 6, color: '#22d3ee' }}>
            Analyzing Evidence Patterns
          </h3>
          <p style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.4)', marginBottom: 18 }}>
            Running multi-layer verification checks
          </p>
          <div style={{ maxWidth: 480, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 8, textAlign: 'left' }}>
            {STAGES.map((stg, idx) => {
              const isPast = idx < activeStage
              const isCurrent = idx === activeStage
              return (
                <div key={idx} style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  fontSize: '0.82rem',
                  color: isPast ? '#10b981' : isCurrent ? '#22d3ee' : 'rgba(255,255,255,0.3)',
                  fontWeight: isCurrent ? 700 : 400,
                  transition: 'all 0.3s ease',
                }}>
                  {isPast ? (
                    <CheckCircle2 size={15} style={{ color: '#10b981', flexShrink: 0 }} />
                  ) : isCurrent ? (
                    <span style={{ width: 12, height: 12, borderRadius: '50%', border: '2px solid #22d3ee', borderTopColor: 'transparent', animation: 'radar-spin 0.6s linear infinite', display: 'inline-block', flexShrink: 0 }} />
                  ) : (
                    <Clock size={14} style={{ opacity: 0.35, flexShrink: 0 }} />
                  )}
                  <span>{stg}</span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ── Forensic Result Panel ───────────────────────────────────────── */}
      {result && !loading && <ResultPanel result={result} />}
    </div>
  )
}

import React, { useState } from 'react'
import { analyzeURL, analyzeMessage } from '../api'
import ResultPanel from '../components/ResultPanel'
import { Link2, MessageSquare, Scan, X, AlertTriangle } from 'lucide-react'

const SAMPLE_SCAM_URL = 'http://paypal-login-secure.tk/verify?account=suspended&redirect=http://evil.com'
const SAMPLE_SAFE_URL = 'https://www.github.com/openai/whisper'
const SAMPLE_SCAM_MSG = `URGENT: Your SBI account has been BLOCKED due to unusual activity. Verify your Aadhaar number and OTP immediately at http://sbi-verify.tk/login or your account will be permanently suspended within 24 hours. Do not ignore this message.`
const SAMPLE_LEGIT_MSG = `Hi! Your Amazon order #112-3456789 for "Wireless Headphones" has been shipped. Expected delivery: Thursday. Track your order at amazon.com/orders.`

export default function ScanPage({ defaultTab = 'url' }) {
  const [tab, setTab] = useState(defaultTab)
  const [urlInput, setUrlInput] = useState('')
  const [msgInput, setMsgInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  async function handleScan() {
    setError('')
    setResult(null)
    setLoading(true)
    try {
      if (tab === 'url') {
        const res = await analyzeURL(urlInput.trim())
        setResult(res.data)
      } else {
        const res = await analyzeMessage(msgInput.trim())
        setResult(res.data)
      }
    } catch (err) {
      setError(err?.response?.data?.detail || 'Backend unreachable. Is the server running?')
    } finally {
      setLoading(false)
    }
  }

  function loadSample(type) {
    setResult(null)
    setError('')
    if (type === 'scam-url')  { setTab('url'); setUrlInput(SAMPLE_SCAM_URL) }
    if (type === 'safe-url')  { setTab('url'); setUrlInput(SAMPLE_SAFE_URL) }
    if (type === 'scam-msg')  { setTab('message'); setMsgInput(SAMPLE_SCAM_MSG) }
    if (type === 'legit-msg') { setTab('message'); setMsgInput(SAMPLE_LEGIT_MSG) }
  }

  const canScan = tab === 'url' ? urlInput.trim().length > 3 : msgInput.trim().length > 10

  return (
    <div style={{ maxWidth: 820, margin: '0 auto', padding: '0 16px 60px' }}>

      {/* ── Header ────────────────────────────────────────────────────── */}
      <div style={{ textAlign: 'center', marginBottom: 36, paddingTop: 20 }}>
        <h1 style={{ fontSize: 'clamp(1.6rem, 4vw, 2.2rem)', fontWeight: 900, marginBottom: 10 }}>
          <span className="shimmer-text">Threat Scanner</span>
        </h1>
        <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: '0.95rem', maxWidth: 500, margin: '0 auto' }}>
          Paste a URL or suspicious message. Get explainable, evidence-based risk analysis instantly.
        </p>
      </div>

      {/* ── Tab selector ──────────────────────────────────────────────── */}
      <div className="tab-bar" style={{ marginBottom: 20 }}>
        <button className={`tab-item ${tab === 'url' ? 'active' : ''}`} onClick={() => { setTab('url'); setResult(null); setError('') }}>
          <Link2 size={16} /> URL / Link
        </button>
        <button className={`tab-item ${tab === 'message' ? 'active' : ''}`} onClick={() => { setTab('message'); setResult(null); setError('') }}>
          <MessageSquare size={16} /> SMS / Email / Message
        </button>
      </div>

      {/* ── Input area ────────────────────────────────────────────────── */}
      <div className="glass" style={{ borderRadius: 16, padding: 20, marginBottom: 16 }}>
        {tab === 'url' ? (
          <div>
            <label style={{ display: 'block', fontSize: '0.82rem', color: 'rgba(255,255,255,0.5)', marginBottom: 8, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              URL or Link
            </label>
            <div style={{ position: 'relative' }}>
              <input
                className="input-field mono"
                placeholder="https://example.com/path?query=value"
                value={urlInput}
                onChange={e => setUrlInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && canScan && handleScan()}
              />
              {urlInput && (
                <button onClick={() => setUrlInput('')} style={{
                  position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.3)',
                }}>
                  <X size={16} />
                </button>
              )}
            </div>
          </div>
        ) : (
          <div>
            <label style={{ display: 'block', fontSize: '0.82rem', color: 'rgba(255,255,255,0.5)', marginBottom: 8, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              Message text (SMS, Email, Social Media)
            </label>
            <textarea
              className="input-field"
              rows={5}
              placeholder="Paste the suspicious message here…"
              value={msgInput}
              onChange={e => setMsgInput(e.target.value)}
            />
            <div style={{ textAlign: 'right', fontSize: '0.75rem', color: 'rgba(255,255,255,0.25)', marginTop: 4 }}>
              {msgInput.length} characters
            </div>
          </div>
        )}

        {/* ── Action row ─────────────────────────────────────────────── */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 16, flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.35)', alignSelf: 'center' }}>Try:</span>
            <button className="btn-ghost" onClick={() => loadSample('scam-url')} style={{ fontSize: '0.78rem', padding: '6px 12px' }}>
              🚨 Scam URL
            </button>
            <button className="btn-ghost" onClick={() => loadSample('safe-url')} style={{ fontSize: '0.78rem', padding: '6px 12px' }}>
              ✓ Safe URL
            </button>
            <button className="btn-ghost" onClick={() => loadSample('scam-msg')} style={{ fontSize: '0.78rem', padding: '6px 12px' }}>
              🚨 Scam SMS
            </button>
            <button className="btn-ghost" onClick={() => loadSample('legit-msg')} style={{ fontSize: '0.78rem', padding: '6px 12px' }}>
              ✓ Legit SMS
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
                Analyzing…
              </>
            ) : (
              <><Scan size={16} /> Analyze</>
            )}
          </button>
        </div>
      </div>

      {/* ── Error ─────────────────────────────────────────────────────── */}
      {error && (
        <div style={{
          background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)',
          borderRadius: 12, padding: '14px 18px', marginBottom: 20,
          display: 'flex', alignItems: 'center', gap: 10,
        }}>
          <AlertTriangle size={18} style={{ color: '#ff2d55', flexShrink: 0 }} />
          <span style={{ fontSize: '0.9rem', color: 'rgba(255,255,255,0.75)' }}>{error}</span>
        </div>
      )}

      {/* ── Loading radar ─────────────────────────────────────────────── */}
      {loading && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '60px 0', gap: 20 }}>
          <div className="radar" />
          <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.9rem' }}>Scanning for threats…</p>
        </div>
      )}

      {/* ── Result ────────────────────────────────────────────────────── */}
      {result && !loading && <ResultPanel result={result} />}
    </div>
  )
}

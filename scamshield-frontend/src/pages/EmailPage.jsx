import React, { useState } from 'react'
import { analyzeEmail } from '../api'
import ResultPanel from '../components/ResultPanel'
import { Mail, X, AlertTriangle, Scan, ChevronDown, ChevronUp, Info } from 'lucide-react'

const SAMPLE_PHISHING = {
  subject: 'URGENT: Your PayPal account has been limited',
  from_addr: 'service@paypal-secure-alert.tk',
  reply_to: 'collect@harvest-emails.xyz',
  raw_headers: `From: PayPal Security <service@paypal-secure-alert.tk>
Reply-To: collect@harvest-emails.xyz
To: victim@gmail.com
Subject: URGENT: Your PayPal account has been limited
Authentication-Results: mx.google.com;
   spf=fail (google.com: domain of service@paypal-secure-alert.tk does not designate) smtp.mailfrom=service@paypal-secure-alert.tk;
   dkim=fail header.i=@paypal-secure-alert.tk;
   dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=paypal-secure-alert.tk
Date: Mon, 17 Oct 2026 10:15:00 +0000`,
  body: `Dear Customer,

We have detected unusual activity on your PayPal account and it has been temporarily limited.

To restore full access, you must verify your identity IMMEDIATELY by clicking the link below:

http://paypal-verify.tk/confirm?account=suspended&redirect=http://evil.com

You must complete verification within 24 hours or your account will be permanently suspended.

Please also confirm:
- Your full name and date of birth
- Your credit card number and CVV
- Your current password
- An OTP will be sent to you — please share it to complete verification

Do not share this email with anyone.

PayPal Security Team`,
}

const SAMPLE_LEGIT = {
  subject: 'Your GitHub security alert',
  from_addr: 'noreply@github.com',
  reply_to: '',
  raw_headers: `From: GitHub <noreply@github.com>
To: user@example.com
Subject: Your GitHub security alert
Authentication-Results: mx.google.com;
   spf=pass (google.com: domain of noreply@github.com) smtp.mailfrom=noreply@github.com;
   dkim=pass header.i=@github.com;
   dmarc=pass (p=REJECT sp=REJECT dis=REJECT) header.from=github.com
Date: Mon, 17 Oct 2026 09:00:00 +0000`,
  body: `Hi there,

A new SSH key was added to your account.

If this was you, you can ignore this message. If you did not add a new SSH key, visit https://github.com/settings/keys to review your keys and remove any unrecognised ones.

Thanks,
The GitHub Team`,
}

function AuthBadge({ label, value }) {
  const colors = {
    pass: { bg: 'rgba(16,185,129,0.12)', border: 'rgba(16,185,129,0.35)', text: '#10b981' },
    fail: { bg: 'rgba(255,45,85,0.12)', border: 'rgba(255,45,85,0.35)', text: '#ff2d55' },
    softfail: { bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.35)', text: '#f59e0b' },
    neutral: { bg: 'rgba(148,163,184,0.12)', border: 'rgba(148,163,184,0.3)', text: '#94a3b8' },
    unknown: { bg: 'rgba(148,163,184,0.08)', border: 'rgba(148,163,184,0.2)', text: 'rgba(255,255,255,0.35)' },
  }
  const c = colors[value] || colors.unknown
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4,
      background: c.bg, border: `1px solid ${c.border}`,
      borderRadius: 10, padding: '10px 16px', minWidth: 80,
    }}>
      <span style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</span>
      <span style={{ fontSize: '0.9rem', fontWeight: 700, color: c.text, textTransform: 'uppercase' }}>{value}</span>
    </div>
  )
}

export default function EmailPage() {
  const [form, setForm] = useState({ subject: '', from_addr: '', reply_to: '', raw_headers: '', body: '' })
  const [showHeaders, setShowHeaders] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  function setField(field, val) {
    setForm(f => ({ ...f, [field]: val }))
  }

  function loadSample(type) {
    const s = type === 'phishing' ? SAMPLE_PHISHING : SAMPLE_LEGIT
    setForm(s)
    setResult(null)
    setError('')
  }

  async function handleScan() {
    setError('')
    setResult(null)
    setLoading(true)
    try {
      const res = await analyzeEmail(form)
      setResult(res.data)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Backend unreachable. Is the server running?')
    } finally {
      setLoading(false)
    }
  }

  const canScan = form.subject.trim() || form.from_addr.trim() || form.raw_headers.trim() || form.body.trim()

  return (
    <div style={{ maxWidth: 860, margin: '0 auto', padding: '0 16px 60px' }}>

      {/* Header */}
      <div style={{ textAlign: 'center', marginBottom: 32, paddingTop: 20 }}>
        <div style={{
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: 64, height: 64, borderRadius: 18,
          background: 'rgba(168,85,247,0.12)', border: '1px solid rgba(168,85,247,0.3)',
          marginBottom: 14,
        }}>
          <Mail size={28} style={{ color: '#a855f7' }} />
        </div>
        <h1 style={{ fontSize: 'clamp(1.5rem, 3.5vw, 2rem)', fontWeight: 900, marginBottom: 8 }}>
          <span className="shimmer-text">Email Forensics</span>
        </h1>
        <p style={{ color: 'rgba(255,255,255,0.45)', fontSize: '0.92rem', maxWidth: 520, margin: '0 auto' }}>
          Paste email headers and body to detect phishing, spoofing, SPF/DKIM/DMARC failures, and credential harvesting.
        </p>
      </div>

      {/* Quick disclaimer */}
      <div style={{
        background: 'rgba(168,85,247,0.07)', border: '1px solid rgba(168,85,247,0.2)',
        borderRadius: 12, padding: '12px 16px', marginBottom: 20,
        display: 'flex', gap: 10, alignItems: 'flex-start',
      }}>
        <Info size={15} style={{ color: '#a855f7', flexShrink: 0, marginTop: 2 }} />
        <p style={{ fontSize: '0.82rem', color: 'rgba(255,255,255,0.55)', lineHeight: 1.55 }}>
          <strong style={{ color: 'rgba(255,255,255,0.75)' }}>Privacy notice:</strong>{' '}
          Email content is sent to the local ScamShield backend only. No content is forwarded to third-party services.
          SPF/DKIM/DMARC results are read from header text — no live DNS lookup is performed.
        </p>
      </div>

      {/* Form */}
      <div className="glass" style={{ borderRadius: 16, padding: 22, marginBottom: 16 }}>

        {/* Basic fields */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.78rem', color: 'rgba(255,255,255,0.45)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Subject
            </label>
            <input
              className="input-field"
              placeholder="Email subject line"
              value={form.subject}
              onChange={e => setField('subject', e.target.value)}
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '0.78rem', color: 'rgba(255,255,255,0.45)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              From Address
            </label>
            <input
              className="input-field mono"
              placeholder="sender@example.com"
              value={form.from_addr}
              onChange={e => setField('from_addr', e.target.value)}
            />
          </div>
        </div>

        <div style={{ marginBottom: 14 }}>
          <label style={{ display: 'block', fontSize: '0.78rem', color: 'rgba(255,255,255,0.45)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Reply-To (optional)
          </label>
          <input
            className="input-field mono"
            placeholder="reply-to@differentdomain.com"
            value={form.reply_to}
            onChange={e => setField('reply_to', e.target.value)}
          />
        </div>

        {/* Raw headers toggle */}
        <button
          onClick={() => setShowHeaders(h => !h)}
          style={{
            background: 'transparent', border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: 8, color: 'rgba(255,255,255,0.5)', cursor: 'pointer',
            fontSize: '0.82rem', padding: '8px 14px', display: 'flex', alignItems: 'center', gap: 6,
            marginBottom: 14, width: '100%', justifyContent: 'space-between',
          }}
        >
          <span>Raw Email Headers (recommended for SPF/DKIM/DMARC analysis)</span>
          {showHeaders ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>

        {showHeaders && (
          <div style={{ marginBottom: 14 }}>
            <textarea
              className="input-field mono"
              rows={7}
              placeholder="Paste raw email headers here (From, Authentication-Results, Received, etc.)"
              value={form.raw_headers}
              onChange={e => setField('raw_headers', e.target.value)}
              style={{ fontSize: '0.78rem' }}
            />
            <div style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.3)', marginTop: 4 }}>
              In Gmail: Open email → ⋮ menu → "Show original". In Outlook: File → Properties → "Internet headers".
            </div>
          </div>
        )}

        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'block', fontSize: '0.78rem', color: 'rgba(255,255,255,0.45)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Email Body
          </label>
          <textarea
            className="input-field"
            rows={6}
            placeholder="Paste the email body text here…"
            value={form.body}
            onChange={e => setField('body', e.target.value)}
          />
          <div style={{ textAlign: 'right', fontSize: '0.72rem', color: 'rgba(255,255,255,0.25)', marginTop: 4 }}>
            {form.body.length} characters
          </div>
        </div>

        {/* Action row */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.35)', alignSelf: 'center' }}>Try:</span>
            <button className="btn-ghost" onClick={() => loadSample('phishing')} style={{ fontSize: '0.78rem', padding: '6px 12px' }}>
              🚨 Phishing Email
            </button>
            <button className="btn-ghost" onClick={() => loadSample('legit')} style={{ fontSize: '0.78rem', padding: '6px 12px' }}>
              ✓ Legitimate Email
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
                Analysing…
              </>
            ) : (
              <><Scan size={16} /> Analyse Email</>
            )}
          </button>
        </div>
      </div>

      {/* Error */}
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

      {/* Loading */}
      {loading && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '60px 0', gap: 20 }}>
          <div className="radar" />
          <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.9rem' }}>Analysing email headers and body…</p>
        </div>
      )}

      {/* Auth results summary (if available in result) */}
      {result && !loading && result.auth_results && (
        <div className="glass" style={{ borderRadius: 14, padding: '16px 20px', marginBottom: 20 }}>
          <div style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 12 }}>
            Email Authentication Results
          </div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <AuthBadge label="SPF" value={result.auth_results.spf || 'unknown'} />
            <AuthBadge label="DKIM" value={result.auth_results.dkim || 'unknown'} />
            <AuthBadge label="DMARC" value={result.auth_results.dmarc || 'unknown'} />
          </div>
          <p style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.3)', marginTop: 10, lineHeight: 1.5 }}>
            Authentication results are read from the 'Authentication-Results' header text only.
            ScamShield does not perform live DNS lookups to verify these values.
          </p>
        </div>
      )}

      {/* Result */}
      {result && !loading && <ResultPanel result={result} />}
    </div>
  )
}

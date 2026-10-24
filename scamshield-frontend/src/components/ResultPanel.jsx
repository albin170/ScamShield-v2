import React, { useState } from 'react'
import ScoreRing from './ScoreRing'
import EvidenceCard from './EvidenceCard'
import { getRiskMeta } from '../utils'
import { Shield, CheckCircle, Info, ExternalLink, Globe, Lock, LockOpen, Download, Copy, Check } from 'lucide-react'

function Section({ title, icon, children }) {
  return (
    <div style={{ marginBottom: 28 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
        {icon}
        <h3 style={{ fontSize: '0.9rem', fontWeight: 700, color: 'rgba(255,255,255,0.85)', letterSpacing: '0.05em', textTransform: 'uppercase' }}>{title}</h3>
        <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.07)', marginLeft: 8 }} />
      </div>
      {children}
    </div>
  )
}

/**
 * Full result panel rendered after analysis.
 */
export default function ResultPanel({ result }) {
  const meta = getRiskMeta(result.risk_level)
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    const reportText = `[ScamShield Audit Report]\nRisk: ${result.risk_level.toUpperCase()} (${result.risk_score}/100)\nSummary: ${result.summary}\nEvidence Count: ${result.evidence.length}\nDate: ${result.created_at || new Date().toISOString()}`
    navigator.clipboard.writeText(reportText)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleExport = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(result, null, 2))
    const downloadAnchor = document.createElement('a')
    downloadAnchor.setAttribute("href", dataStr)
    downloadAnchor.setAttribute("download", `scamshield_scan_${result.id || 'report'}.json`)
    document.body.appendChild(downloadAnchor)
    downloadAnchor.click()
    downloadAnchor.remove()
  }

  return (
    <div className="animate-fade-in-up" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* ── Top: score + summary ─────────────────────────────────────── */}
      <div className={`glass ${meta.glow}`} style={{
        borderRadius: 16,
        border: `1px solid ${meta.color}40`,
        padding: '28px 24px',
        display: 'flex', gap: 28,
        alignItems: 'center',
        flexWrap: 'wrap',
      }}>
        <ScoreRing score={result.risk_score} riskLevel={result.risk_level} size={130} />

        <div style={{ flex: 1, minWidth: 240 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className={`tag severity-${result.risk_level}`} style={{ fontSize: '0.8rem', padding: '5px 14px' }}>
                {meta.icon} {meta.label} Risk
              </span>
              <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.35)', textTransform: 'capitalize' }}>
                {result.scan_type === 'url' ? '🔗 URL Analysis' : '💬 Message Analysis'}
              </span>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn-ghost" onClick={handleCopy} style={{ fontSize: '0.75rem', padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 4 }}>
                {copied ? <Check size={13} style={{ color: '#10b981' }} /> : <Copy size={13} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
              <button className="btn-ghost" onClick={handleExport} style={{ fontSize: '0.75rem', padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 4 }}>
                <Download size={13} /> JSON
              </button>
            </div>
          </div>

          <p style={{ fontSize: '1rem', lineHeight: 1.65, color: 'rgba(255,255,255,0.8)', marginBottom: 16 }}>
            {result.summary}
          </p>

          {/* URL-specific meta */}
          {result.scan_type === 'url' && (
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              {result.domain && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.82rem', color: 'rgba(255,255,255,0.55)' }}>
                  <Globe size={13} />
                  <span className="mono">{result.domain}</span>
                </div>
              )}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.82rem' }}>
                {result.is_https
                  ? <><Lock size={13} style={{ color: '#10b981' }} /><span style={{ color: '#10b981' }}>HTTPS</span></>
                  : <><LockOpen size={13} style={{ color: '#ef4444' }} /><span style={{ color: '#ef4444' }}>HTTP only</span></>
                }
              </div>
            </div>
          )}

          {/* Message-specific: extracted URLs */}
          {result.extracted_urls && result.extracted_urls.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Links found in message:</span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 6 }}>
                {result.extracted_urls.map((u, i) => (
                  <span key={i} className="mono" style={{ fontSize: '0.78rem', color: '#f59e0b', wordBreak: 'break-all' }}>
                    {u}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Evidence ─────────────────────────────────────────────────── */}
      <Section title={`Evidence (${result.evidence.length} signals)`} icon={<Shield size={16} style={{ color: '#22d3ee' }} />}>
        {result.evidence.length === 0 ? (
          <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.9rem' }}>No suspicious signals detected.</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {result.evidence.map((ev, i) => (
              <EvidenceCard key={i} evidence={ev} index={i} />
            ))}
          </div>
        )}
      </Section>

      {/* ── Next steps ───────────────────────────────────────────────── */}
      <Section title="Recommended Next Steps" icon={<CheckCircle size={16} style={{ color: '#10b981' }} />}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {result.next_steps.map((step, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'flex-start', gap: 12,
              background: 'rgba(16,185,129,0.06)', borderRadius: 10,
              border: '1px solid rgba(16,185,129,0.15)',
              padding: '10px 14px',
            }}>
              <div style={{
                width: 22, height: 22, borderRadius: '50%',
                background: 'rgba(16,185,129,0.2)',
                border: '1px solid rgba(16,185,129,0.4)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: '0.7rem', fontWeight: 700, color: '#10b981', flexShrink: 0, marginTop: 1,
              }}>{i + 1}</div>
              <span style={{ fontSize: '0.88rem', color: 'rgba(255,255,255,0.75)', lineHeight: 1.55 }}>{step}</span>
            </div>
          ))}
        </div>
      </Section>

      {/* ── Limitations / disclaimer ─────────────────────────────────── */}
      <Section title="Limitations & Disclaimer" icon={<Info size={16} style={{ color: '#a855f7' }} />}>
        <div style={{ background: 'rgba(168,85,247,0.06)', borderRadius: 10, border: '1px solid rgba(168,85,247,0.2)', padding: '14px 16px' }}>
          <ul style={{ display: 'flex', flexDirection: 'column', gap: 6, paddingLeft: 0, listStyle: 'none' }}>
            {result.limitations.map((lim, i) => (
              <li key={i} style={{ display: 'flex', gap: 8, fontSize: '0.83rem', color: 'rgba(255,255,255,0.5)', lineHeight: 1.5 }}>
                <span style={{ color: '#a855f7', flexShrink: 0 }}>•</span>
                {lim}
              </li>
            ))}
          </ul>
        </div>
      </Section>
    </div>
  )
}

import React, { useState } from 'react'
import ScoreRing from './ScoreRing'
import EvidenceCard from './EvidenceCard'
import { getRiskMeta, getVerdictMeta } from '../utils'
import {
  Shield, CheckCircle, Info, ExternalLink, Globe, Lock, LockOpen,
  Download, Copy, Check, AlertTriangle, ShieldCheck, ShieldAlert,
  HelpCircle, Eye, CornerDownRight, X
} from 'lucide-react'

function Section({ title, icon, badge, children }) {
  return (
    <div style={{ marginBottom: 28 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {icon}
          <h3 style={{ fontSize: '0.88rem', fontWeight: 700, color: 'rgba(255,255,255,0.85)', letterSpacing: '0.05em', textTransform: 'uppercase' }}>
            {title}
          </h3>
        </div>
        {badge && (
          <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)', background: 'rgba(255,255,255,0.06)', padding: '2px 8px', borderRadius: 99 }}>
            {badge}
          </span>
        )}
      </div>
      {children}
    </div>
  )
}

/**
 * Full result panel rendered after analysis with Four Clear Verdicts,
 * explainable evidence groups, source attribution, and safe link confirmation.
 */
export default function ResultPanel({ result }) {
  const riskMeta = getRiskMeta(result.risk_level)
  const verdictMeta = getVerdictMeta(result.verdict, result.risk_level)
  const [copied, setCopied] = useState(false)
  const [showSafeNavModal, setShowSafeNavModal] = useState(false)
  const [acknowledgedRisk, setAcknowledgedRisk] = useState(false)

  const handleCopy = () => {
    const reportText = [
      `[ScamShield Security Audit Report]`,
      `Verdict: ${verdictMeta.label}`,
      `Risk Score: ${result.risk_score}/100 (${riskMeta.label})`,
      `Summary: ${result.summary}`,
      result.verdict_explanation ? `Verdict Rationale: ${result.verdict_explanation}` : null,
      `Sources Consulted: ${(result.sources_consulted || []).join(', ') || 'Rule Engine'}`,
      `Timestamp: ${result.created_at || new Date().toISOString()}`
    ].filter(Boolean).join('\n')

    navigator.clipboard.writeText(reportText)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleExport = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(result, null, 2))
    const downloadAnchor = document.createElement('a')
    downloadAnchor.setAttribute('href', dataStr)
    downloadAnchor.setAttribute('download', `scamshield_scan_${result.id || Date.now()}.json`)
    document.body.appendChild(downloadAnchor)
    downloadAnchor.click()
    downloadAnchor.remove()
  }

  const targetUrl = result.url || (result.extracted_urls && result.extracted_urls[0]) || (result.decoded_text?.startsWith('http') ? result.decoded_text : null)

  const positiveEvidence = result.positive_evidence || []
  const negativeEvidence = result.negative_evidence || result.evidence || []
  const sourcesConsulted = result.sources_consulted || ['Brand Registry', 'Domain Heuristics', 'URL Normalization Engine']
  const checksNotCompleted = result.checks_not_completed || []

  return (
    <div className="animate-fade-in-up" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* ── Top: Four Clear Verdicts & Score Ring ───────────────────────── */}
      <div className={`glass ${verdictMeta.glow}`} style={{
        borderRadius: 16,
        border: `1px solid ${verdictMeta.color}50`,
        padding: '28px 24px',
        display: 'flex', gap: 28,
        alignItems: 'center',
        flexWrap: 'wrap',
        position: 'relative',
        overflow: 'hidden',
      }}>
        {/* Ambient background wash */}
        <div style={{
          position: 'absolute', top: 0, left: 0, right: 0, height: 4,
          background: verdictMeta.color,
          boxShadow: `0 0 12px ${verdictMeta.color}`,
        }} />

        <ScoreRing score={result.risk_score} riskLevel={result.risk_level} size={130} />

        <div style={{ flex: 1, minWidth: 260 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              {/* Primary 4-State Verdict Badge */}
              <div style={{
                background: verdictMeta.bg,
                border: `1px solid ${verdictMeta.color}70`,
                color: verdictMeta.color,
                borderRadius: 8,
                padding: '6px 14px',
                fontSize: '0.85rem',
                fontWeight: 800,
                letterSpacing: '0.04em',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                boxShadow: `0 0 14px ${verdictMeta.color}25`
              }}>
                {verdictMeta.label === 'MALICIOUS' ? (
                  <ShieldAlert size={14} style={{ color: verdictMeta.color }} />
                ) : verdictMeta.label === 'SUSPICIOUS' ? (
                  <AlertTriangle size={14} style={{ color: verdictMeta.color }} />
                ) : verdictMeta.label === 'NO KNOWN THREAT FOUND' ? (
                  <ShieldCheck size={14} style={{ color: verdictMeta.color }} />
                ) : (
                  <HelpCircle size={14} style={{ color: verdictMeta.color }} />
                )}
                <span>VERDICT: {verdictMeta.label}</span>
              </div>

              <span style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.45)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                {result.scan_type === 'url' ? 'URL Forensics' : result.scan_type === 'qr' ? 'QR Code Payload' : result.scan_type === 'email' ? 'Email Forensics' : result.scan_type === 'file' ? 'File Analysis' : 'Text & Message Analysis'}
              </span>
            </div>

            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn-ghost" onClick={handleCopy} style={{ fontSize: '0.75rem', padding: '5px 12px', display: 'flex', alignItems: 'center', gap: 4 }}>
                {copied ? <Check size={13} style={{ color: '#10b981' }} /> : <Copy size={13} />}
                {copied ? 'Copied' : 'Copy Report'}
              </button>
              <button className="btn-ghost" onClick={handleExport} style={{ fontSize: '0.75rem', padding: '5px 12px', display: 'flex', alignItems: 'center', gap: 4 }}>
                <Download size={13} /> Export JSON
              </button>
            </div>
          </div>

          <p style={{ fontSize: '1rem', lineHeight: 1.6, color: 'rgba(255,255,255,0.88)', marginBottom: 12, fontWeight: 500 }}>
            {result.summary}
          </p>

          {/* Explainable verdict rationale */}
          {result.verdict_explanation && (
            <div style={{
              background: 'rgba(255,255,255,0.03)',
              borderLeft: `3px solid ${verdictMeta.color}`,
              padding: '8px 12px',
              borderRadius: '0 8px 8px 0',
              fontSize: '0.82rem',
              color: 'rgba(255,255,255,0.65)',
              marginBottom: 14,
              lineHeight: 1.5,
            }}>
              <strong style={{ color: verdictMeta.color }}>Analysis Rationale: </strong>
              {result.verdict_explanation}
            </div>
          )}

          {/* URL & Infrastructure details */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
            {result.domain && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.82rem', color: 'rgba(255,255,255,0.6)' }}>
                <Globe size={13} style={{ color: '#22d3ee' }} />
                <span className="mono">{result.domain}</span>
              </div>
            )}
            {result.scan_type === 'url' && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.82rem' }}>
                {result.is_https
                  ? <><Lock size={13} style={{ color: '#10b981' }} /><span style={{ color: '#10b981' }}>HTTPS (TLS Present)</span></>
                  : <><LockOpen size={13} style={{ color: '#ef4444' }} /><span style={{ color: '#ef4444' }}>HTTP Only (Insecure)</span></>
                }
              </div>
            )}
            {targetUrl && (
              <button
                onClick={() => setShowSafeNavModal(true)}
                style={{
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.15)',
                  borderRadius: 6,
                  color: 'rgba(255,255,255,0.7)',
                  fontSize: '0.78rem',
                  padding: '3px 10px',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 5,
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                }}
              >
                <ExternalLink size={12} /> Inspect / Visit Link Safely
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── Evidence Groups: Positive vs Negative Signals ──────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 18 }}>

        {/* Positive / Legitimate Evidence */}
        <div className="glass" style={{ borderRadius: 14, padding: 18, border: '1px solid rgba(16,185,129,0.2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <ShieldCheck size={16} style={{ color: '#10b981' }} />
            <h4 style={{ fontSize: '0.82rem', fontWeight: 700, color: '#10b981', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              Legitimacy Signals ({positiveEvidence.length})
            </h4>
          </div>
          {positiveEvidence.length === 0 ? (
            <p style={{ color: 'rgba(255,255,255,0.35)', fontSize: '0.8rem', fontStyle: 'italic' }}>
              No explicit trust anchors or verified domain proofs identified.
            </p>
          ) : (
            <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {positiveEvidence.map((pos, idx) => (
                <li key={idx} style={{
                  display: 'flex', alignItems: 'flex-start', gap: 8,
                  fontSize: '0.82rem', color: 'rgba(255,255,255,0.8)',
                  background: 'rgba(16,185,129,0.06)', borderRadius: 8, padding: '8px 10px',
                  border: '1px solid rgba(16,185,129,0.15)',
                }}>
                  <Check size={14} style={{ color: '#10b981', flexShrink: 0, marginTop: 2 }} />
                  <span>{pos}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Negative / Risk Evidence */}
        <div className="glass" style={{ borderRadius: 14, padding: 18, border: '1px solid rgba(255,45,85,0.2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <ShieldAlert size={16} style={{ color: '#ff2d55' }} />
            <h4 style={{ fontSize: '0.82rem', fontWeight: 700, color: '#ff2d55', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              Threat & Risk Findings ({negativeEvidence.length})
            </h4>
          </div>
          {negativeEvidence.length === 0 ? (
            <p style={{ color: 'rgba(255,255,255,0.35)', fontSize: '0.8rem', fontStyle: 'italic' }}>
              Zero suspicious heuristics or malicious feeds triggered.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {negativeEvidence.map((ev, i) => (
                <EvidenceCard key={i} evidence={ev} index={i} />
              ))}
            </div>
          )}
        </div>

      </div>

      {/* ── Threat Intelligence & Sources Attribution ──────────────────── */}
      <Section title="Threat Intelligence & Verification Sources" icon={<Globe size={16} style={{ color: '#22d3ee' }} />}>
        <div className="glass" style={{ borderRadius: 12, padding: '16px 20px' }}>
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
              Sources Consulted During Scan:
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {sourcesConsulted.map((source, i) => (
                <span key={i} style={{
                  background: 'rgba(34,211,238,0.08)',
                  border: '1px solid rgba(34,211,238,0.25)',
                  color: '#22d3ee',
                  fontSize: '0.76rem',
                  padding: '4px 10px',
                  borderRadius: 6,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 5,
                }}>
                  <Check size={11} /> {source}
                </span>
              ))}
            </div>
          </div>

          {checksNotCompleted.length > 0 && (
            <div style={{ marginTop: 14, paddingTop: 12, borderTop: '1px solid rgba(255,255,255,0.07)' }}>
              <div style={{ fontSize: '0.72rem', color: '#f59e0b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 5 }}>
                <HelpCircle size={12} /> Checks Not Completed / Optional Providers Offline:
              </div>
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
                {checksNotCompleted.map((check, i) => (
                  <li key={i} style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.5)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ color: '#f59e0b' }}>–</span> {check}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </Section>

      {/* ── Recommended Next Steps ─────────────────────────────────────── */}
      <Section title="Recommended Next Steps" icon={<CheckCircle size={16} style={{ color: '#10b981' }} />}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {(result.next_steps || []).map((step, i) => (
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

      {/* ── Limitations & Honest Security Boundary ─────────────────────── */}
      <Section title="Detection Limitations & Security Disclaimers" icon={<Info size={16} style={{ color: '#a855f7' }} />}>
        <div style={{ background: 'rgba(168,85,247,0.06)', borderRadius: 10, border: '1px solid rgba(168,85,247,0.2)', padding: '14px 16px' }}>
          <ul style={{ display: 'flex', flexDirection: 'column', gap: 6, paddingLeft: 0, listStyle: 'none', margin: 0 }}>
            {(result.limitations || []).map((lim, i) => (
              <li key={i} style={{ display: 'flex', gap: 8, fontSize: '0.82rem', color: 'rgba(255,255,255,0.55)', lineHeight: 1.5 }}>
                <span style={{ color: '#a855f7', flexShrink: 0 }}>•</span>
                {lim}
              </li>
            ))}
          </ul>
        </div>
      </Section>

      {/* ── Safe Navigation Confirmation Modal ─────────────────────────── */}
      {showSafeNavModal && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 9999,
          background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(8px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16,
        }}>
          <div className="glass" style={{
            maxWidth: 520, width: '100%', borderRadius: 16,
            border: '1px solid rgba(255,45,85,0.4)',
            padding: 24, boxShadow: '0 20px 50px rgba(0,0,0,0.8)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#ff2d55' }}>
                <AlertTriangle size={24} />
                <h3 style={{ fontSize: '1.1rem', fontWeight: 800, margin: 0 }}>External Navigation Warning</h3>
              </div>
              <button
                onClick={() => { setShowSafeNavModal(false); setAcknowledgedRisk(false) }}
                style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.4)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            <p style={{ fontSize: '0.88rem', color: 'rgba(255,255,255,0.75)', lineHeight: 1.55, marginBottom: 16 }}>
              You are requesting to navigate to an external web destination. ScamShield never automatically loads external sites to protect you from drive-by downloads, phishing, and IP tracking.
            </p>

            <div style={{
              background: 'rgba(0,0,0,0.4)', borderRadius: 8, padding: '12px 14px', marginBottom: 16,
              border: '1px solid rgba(255,255,255,0.1)',
            }}>
              <div style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', marginBottom: 4 }}>
                Target URL:
              </div>
              <div className="mono" style={{ fontSize: '0.82rem', color: '#f59e0b', wordBreak: 'break-all' }}>
                {targetUrl}
              </div>
              <div style={{ marginTop: 8, fontSize: '0.75rem', color: verdictMeta.color, fontWeight: 700 }}>
                Current Assessment: {verdictMeta.label} ({result.risk_score}/100)
              </div>
            </div>

            <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, cursor: 'pointer', marginBottom: 20 }}>
              <input
                type="checkbox"
                checked={acknowledgedRisk}
                onChange={e => setAcknowledgedRisk(e.target.checked)}
                style={{ marginTop: 3, accentColor: '#ff2d55' }}
              />
              <span style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.65)', lineHeight: 1.4 }}>
                I acknowledge the security risk and wish to open this external link in an isolated browser tab.
              </span>
            </label>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                className="btn-ghost"
                onClick={() => { setShowSafeNavModal(false); setAcknowledgedRisk(false) }}
                style={{ fontSize: '0.85rem' }}
              >
                Cancel / Stay Safe
              </button>
              <a
                href={targetUrl}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => {
                  if (!acknowledgedRisk) {
                    e.preventDefault()
                    return
                  }
                  setShowSafeNavModal(false)
                  setAcknowledgedRisk(false)
                }}
                className="btn-primary"
                style={{
                  textDecoration: 'none',
                  fontSize: '0.85rem',
                  opacity: acknowledgedRisk ? 1 : 0.4,
                  pointerEvents: acknowledgedRisk ? 'auto' : 'none',
                  background: 'linear-gradient(135deg, #ff2d55, #f59e0b)',
                  border: 'none',
                }}
              >
                Proceed to Site
              </a>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}

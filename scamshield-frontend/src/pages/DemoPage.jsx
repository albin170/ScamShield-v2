import React, { useState, useEffect } from 'react'
import { getDemoCases, runDemoCase } from '../api'
import { getRiskMeta } from '../utils'
import { FlaskConical, CheckCircle2, XCircle, Play, BarChart3 } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

function DemoCase({ c, onRun, result }) {
  const meta = result ? getRiskMeta(result.risk_level) : null
  const expectedMeta = getRiskMeta(c.expected_risk)

  return (
    <div className="glass" style={{ borderRadius: 14, padding: 18, display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <span style={{
              fontSize: '0.72rem', fontWeight: 700, padding: '3px 10px', borderRadius: 99,
              background: c.label === 'scam' ? 'rgba(255,45,85,0.15)' : 'rgba(16,185,129,0.12)',
              color: c.label === 'scam' ? '#ff2d55' : '#10b981',
              border: `1px solid ${c.label === 'scam' ? 'rgba(255,45,85,0.3)' : 'rgba(16,185,129,0.3)'}`,
              textTransform: 'uppercase',
            }}>
              {c.label === 'scam' ? '🚨 Scam' : '✓ Legit'}
            </span>
            <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase' }}>
              {c.type}
            </span>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'rgba(255,255,255,0.75)', lineHeight: 1.5 }}>{c.description}</p>
        </div>
        <button className="btn-ghost" onClick={() => onRun(c.id)} style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0, fontSize: '0.8rem', padding: '7px 14px' }}>
          <Play size={13} /> Run
        </button>
      </div>

      {/* Input preview */}
      <div style={{ background: 'rgba(0,0,0,0.3)', borderRadius: 8, padding: '10px 14px' }}>
        <p className="mono" style={{ fontSize: '0.78rem', color: '#94a3b8', wordBreak: 'break-all', lineHeight: 1.5 }}>
          {c.input}
        </p>
      </div>

      {/* Expected vs actual */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.4)' }}>
          Expected: <span style={{ color: expectedMeta.color, fontWeight: 700 }}>{expectedMeta.label}</span>
        </div>
        {result && (
          <>
            <div style={{ fontSize: '0.78rem' }}>
              Got: <span style={{ color: meta.color, fontWeight: 700 }}>{meta.label}</span>
              {' '}({result.risk_score}/100)
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              {result.matched_expected
                ? <><CheckCircle2 size={16} style={{ color: '#10b981' }} /><span style={{ fontSize: '0.78rem', color: '#10b981' }}>Correct</span></>
                : <><XCircle size={16} style={{ color: '#f97316' }} /><span style={{ fontSize: '0.78rem', color: '#f97316' }}>Mismatch</span></>
              }
            </div>
          </>
        )}
      </div>
    </div>
  )
}

export default function DemoPage() {
  const [cases, setCases] = useState([])
  const [results, setResults] = useState({})
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState({})
  const [error, setError] = useState('')

  useEffect(() => {
    getDemoCases()
      .then(r => setCases(r.data))
      .catch(() => setError('Could not load demo cases. Is the backend running?'))
      .finally(() => setLoading(false))
  }, [])

  async function handleRun(id) {
    setRunning(r => ({ ...r, [id]: true }))
    try {
      const res = await runDemoCase(id)
      setResults(r => ({ ...r, [id]: res.data }))
    } catch (e) {
      setError('Run failed: ' + (e?.response?.data?.detail || 'Backend error'))
    } finally {
      setRunning(r => ({ ...r, [id]: false }))
    }
  }

  async function handleRunAll() {
    for (const c of cases) {
      setRunning(r => ({ ...r, [c.id]: true }))
      try {
        const res = await runDemoCase(c.id)
        setResults(r => ({ ...r, [c.id]: res.data }))
      } catch {}
      finally { setRunning(r => ({ ...r, [c.id]: false })) }
    }
  }

  // Stats
  const ran = Object.values(results)
  const correct = ran.filter(r => r.matched_expected).length
  const total = ran.length
  const accuracy = total > 0 ? Math.round((correct / total) * 100) : null

  // Chart data
  const riskDist = ['safe', 'low', 'medium', 'high', 'critical'].map(r => ({
    name: r.charAt(0).toUpperCase() + r.slice(1),
    count: ran.filter(res => res.risk_level === r).length,
    color: getRiskMeta(r).color,
  })).filter(d => d.count > 0)

  return (
    <div style={{ maxWidth: 900, margin: '0 auto', padding: '0 16px 60px' }}>

      {/* ── Header ────────────────────────────────────────────────────── */}
      <div style={{ paddingTop: 20, marginBottom: 28 }}>
        <h1 style={{ fontSize: '1.6rem', fontWeight: 800, display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <FlaskConical size={22} style={{ color: '#a855f7' }} />
          <span className="shimmer-text">Demo & Evaluation</span>
        </h1>
        <p style={{ color: 'rgba(255,255,255,0.45)', fontSize: '0.88rem' }}>
          Run labeled test cases and measure ScamShield's detection performance.
        </p>
      </div>

      {/* ── Stats bar ─────────────────────────────────────────────────── */}
      {total > 0 && (
        <div className="glass" style={{ borderRadius: 14, padding: '16px 24px', marginBottom: 24, display: 'flex', gap: 32, flexWrap: 'wrap', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '2rem', fontWeight: 900, color: accuracy >= 75 ? '#10b981' : '#f97316' }}>{accuracy}%</div>
            <div style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Accuracy</div>
          </div>
          <div>
            <div style={{ fontSize: '2rem', fontWeight: 900, color: '#22d3ee' }}>{correct}/{total}</div>
            <div style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Correct</div>
          </div>
          <div style={{ flex: 1, minWidth: 200, height: 80 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskDist} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'rgba(255,255,255,0.4)' }} />
                <YAxis tick={{ fontSize: 11, fill: 'rgba(255,255,255,0.4)' }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: '#0d1321', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: 'rgba(255,255,255,0.7)' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {riskDist.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* ── Controls ──────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}>
        <button className="btn-primary" onClick={handleRunAll} disabled={cases.length === 0}
          style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <BarChart3 size={16} /> Run All Cases
        </button>
      </div>

      {error && (
        <div style={{ background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)', borderRadius: 12, padding: '12px 16px', marginBottom: 16, color: 'rgba(255,255,255,0.7)', fontSize: '0.88rem' }}>
          {error}
        </div>
      )}

      {/* ── Cases grid ────────────────────────────────────────────────── */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: 60 }}>
          <div className="radar" style={{ margin: '0 auto 20px' }} />
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(400px, 1fr))', gap: 14 }}>
          {cases.map(c => (
            <DemoCase
              key={c.id}
              c={c}
              onRun={handleRun}
              result={results[c.id]}
            />
          ))}
        </div>
      )}
    </div>
  )
}

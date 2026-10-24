import React, { useState, useRef } from 'react'
import { analyzeFile } from '../api'
import ResultPanel from '../components/ResultPanel'
import { FileText, Upload, X, AlertTriangle, Scan, Shield, Database, Copy, Check } from 'lucide-react'

const MAX_SIZE_MB = 25

export default function FilePage() {
  const [file, setFile]       = useState(null)
  const [dragging, setDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult]   = useState(null)
  const [error, setError]     = useState('')
  const [copied, setCopied]   = useState(false)
  const inputRef = useRef(null)

  function handleFileSelect(f) {
    if (!f) return
    if (f.size > MAX_SIZE_MB * 1024 * 1024) {
      setError(`File too large. Maximum is ${MAX_SIZE_MB} MB.`)
      return
    }
    setError('')
    setResult(null)
    setFile(f)
  }

  function handleDrop(e) {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files?.[0]
    if (f) handleFileSelect(f)
  }

  function clearFile() {
    setFile(null)
    setResult(null)
    setError('')
    if (inputRef.current) inputRef.current.value = ''
  }

  async function handleScan() {
    if (!file) return
    setError('')
    setResult(null)
    setLoading(true)
    try {
      const fd = new FormData()
      fd.append('file', file)
      const res = await analyzeFile(fd)
      setResult(res.data)
    } catch (err) {
      setError(err?.response?.data?.detail || 'Analysis failed. Is the server running?')
    } finally {
      setLoading(false)
    }
  }

  function copyHash() {
    if (result?.file_sha256) {
      navigator.clipboard.writeText(result.file_sha256)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const sizeStr = file
    ? file.size < 1024
      ? `${file.size} B`
      : file.size < 1024 * 1024
      ? `${(file.size / 1024).toFixed(1)} KB`
      : `${(file.size / (1024 * 1024)).toFixed(2)} MB`
    : ''

  return (
    <div style={{ maxWidth: 820, margin: '0 auto', padding: '0 16px 60px' }}>

      {/* Header */}
      <div style={{ textAlign: 'center', marginBottom: 32, paddingTop: 20 }}>
        <div style={{
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: 64, height: 64, borderRadius: 18,
          background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.3)',
          marginBottom: 14,
        }}>
          <FileText size={28} style={{ color: '#f59e0b' }} />
        </div>
        <h1 style={{ fontSize: 'clamp(1.5rem, 3.5vw, 2rem)', fontWeight: 900, marginBottom: 8 }}>
          <span className="shimmer-text">What's Inside That File?</span>
        </h1>
        <p style={{ color: 'rgba(255,255,255,0.45)', fontSize: '0.92rem', maxWidth: 540, margin: '0 auto' }}>
          Got a suspicious attachment? Drop it here — we’ll dissect it and tell you if it’s dangerous, without ever running it.
        </p>
      </div>

      {/* Safety notice */}
      <div style={{
        background: 'rgba(16,185,129,0.07)', border: '1px solid rgba(16,185,129,0.2)',
        borderRadius: 12, padding: '12px 16px', marginBottom: 20,
        display: 'flex', gap: 10, alignItems: 'flex-start',
      }}>
        <Shield size={15} style={{ color: '#10b981', flexShrink: 0, marginTop: 2 }} />
        <p style={{ fontSize: '0.82rem', color: 'rgba(255,255,255,0.55)', lineHeight: 1.55 }}>
          <strong style={{ color: 'rgba(255,255,255,0.75)' }}>Static analysis only:</strong>{' '}
          Uploaded files are <strong style={{ color: '#10b981' }}>never executed, opened, or run</strong> in any environment.
          Analysis covers file type verification, hash generation, and metadata checks.
          ScamShield does not perform virus scanning — use dedicated antivirus software for that.
        </p>
      </div>

      {/* Drop zone */}
      <div
        className="glass"
        onDragEnter={() => setDragging(true)}
        onDragLeave={() => setDragging(false)}
        onDragOver={e => e.preventDefault()}
        onDrop={handleDrop}
        onClick={() => !file && inputRef.current?.click()}
        style={{
          borderRadius: 16, padding: file ? 20 : 48,
          textAlign: 'center', cursor: file ? 'default' : 'pointer',
          border: dragging ? '2px dashed #f59e0b' : '2px dashed rgba(245,158,11,0.2)',
          transition: 'all 0.2s',
          background: dragging ? 'rgba(245,158,11,0.04)' : undefined,
          marginBottom: 16,
        }}
      >
        <input
          ref={inputRef}
          type="file"
          style={{ display: 'none' }}
          onChange={e => handleFileSelect(e.target.files?.[0])}
        />

        {file ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <div style={{
                width: 48, height: 48, borderRadius: 12,
                background: 'rgba(245,158,11,0.12)', border: '1px solid rgba(245,158,11,0.3)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <FileText size={22} style={{ color: '#f59e0b' }} />
              </div>
              <div style={{ textAlign: 'left' }}>
                <div style={{ fontWeight: 600, fontSize: '0.92rem', marginBottom: 3 }}>{file.name}</div>
                <div style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.4)' }}>{sizeStr} · {file.type || 'unknown type'}</div>
              </div>
            </div>
            <button onClick={e => { e.stopPropagation(); clearFile() }} style={{
              background: 'rgba(255,45,85,0.15)', border: '1px solid rgba(255,45,85,0.3)',
              borderRadius: 8, cursor: 'pointer', color: '#ff2d55',
              padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.82rem',
            }}>
              <X size={14} /> Remove
            </button>
          </div>
        ) : (
          <div>
            <div style={{
              width: 72, height: 72, borderRadius: 20,
              background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              margin: '0 auto 16px',
            }}>
              <Upload size={30} style={{ color: '#f59e0b' }} />
            </div>
            <p style={{ fontSize: '1rem', fontWeight: 600, marginBottom: 6 }}>
              Drop a suspicious file here
            </p>
            <p style={{ fontSize: '0.82rem', color: 'rgba(255,255,255,0.35)' }}>
              or click to browse — any file type, max {MAX_SIZE_MB} MB
            </p>
          </div>
        )}
      </div>

      {/* Scan button */}
      {file && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}>
          <button
            className="btn-primary"
            onClick={handleScan}
            disabled={loading}
            style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'linear-gradient(135deg, #d97706, #f59e0b)' }}
          >
            {loading ? (
              <>
                <span style={{ width: 16, height: 16, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'radar-spin 0.7s linear infinite', display: 'inline-block' }} />
                Analysing…
              </>
            ) : (
              <><Scan size={16} /> Analyse File</>
            )}
          </button>
        </div>
      )}

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
          <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.9rem' }}>Performing static metadata analysis…</p>
        </div>
      )}

      {/* File metadata summary */}
      {result && !loading && (
        <div className="glass" style={{ borderRadius: 14, padding: '16px 20px', marginBottom: 20, borderColor: 'rgba(245,158,11,0.2)' }}>
          <div style={{ fontSize: '0.72rem', color: '#f59e0b', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 12 }}>
            File Metadata
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 10, marginBottom: 12 }}>
            {[
              { label: 'Filename', value: result.filename },
              { label: 'Detected Type', value: result.detected_type },
              { label: 'Extension', value: result.claimed_extension || 'none' },
              { label: 'Size', value: result.file_size_bytes != null ? `${(result.file_size_bytes / 1024).toFixed(1)} KB` : '—' },
              { label: 'Type Mismatch', value: result.type_mismatch ? 'FLAGGED' : 'Clean', alert: result.type_mismatch },
              { label: 'Macros Detected', value: result.macro_detected ? 'DETECTED' : 'None', alert: result.macro_detected },
            ].map(({ label, value, alert: isAlert }) => (
              <div key={label} style={{ background: 'rgba(0,0,0,0.25)', borderRadius: 8, padding: '8px 12px' }}>
                <div style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.35)', marginBottom: 3, textTransform: 'uppercase' }}>{label}</div>
                <div style={{ fontSize: '0.82rem', fontWeight: 600, color: isAlert ? '#f59e0b' : 'rgba(255,255,255,0.8)', wordBreak: 'break-all' }}>{value}</div>
              </div>
            ))}
          </div>
          {/* SHA-256 */}
          {result.file_sha256 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'rgba(0,0,0,0.25)', borderRadius: 8, padding: '8px 12px' }}>
              <Database size={13} style={{ color: 'rgba(255,255,255,0.35)', flexShrink: 0 }} />
              <span className="mono" style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.5)', wordBreak: 'break-all', flex: 1 }}>
                SHA-256: {result.file_sha256}
              </span>
              <button onClick={copyHash} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.4)', flexShrink: 0 }}>
                {copied ? <Check size={14} style={{ color: '#10b981' }} /> : <Copy size={14} />}
              </button>
            </div>
          )}
          {result.archive_contents?.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.35)', marginBottom: 6, textTransform: 'uppercase' }}>Archive Contents ({result.archive_contents.length} files)</div>
              <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: 8, padding: '8px 12px', maxHeight: 120, overflowY: 'auto' }}>
                {result.archive_contents.map((name, i) => (
                  <div key={i} className="mono" style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.5)', lineHeight: 1.7 }}>{name}</div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Result */}
      {result && !loading && <ResultPanel result={result} />}
    </div>
  )
}

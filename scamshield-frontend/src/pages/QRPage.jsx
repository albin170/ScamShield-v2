import React, { useState, useRef } from 'react'
import { analyzeQR } from '../api'
import ResultPanel from '../components/ResultPanel'
import { QrCode, Upload, X, AlertTriangle, Scan, Info, Shield } from 'lucide-react'

const ACCEPTED_TYPES = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/bmp', 'image/gif']

export default function QRPage() {
  const [file, setFile] = useState(null)
  const [preview, setPreview] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const inputRef = useRef(null)

  function handleFileSelect(f) {
    if (!f) return
    if (!ACCEPTED_TYPES.includes(f.type)) {
      setError(`Unsupported file type: ${f.type}. Please upload a PNG, JPEG, WEBP, BMP, or GIF image.`)
      return
    }
    if (f.size > 10 * 1024 * 1024) {
      setError('File too large. Maximum is 10 MB.')
      return
    }
    setError('')
    setResult(null)
    setFile(f)
    const reader = new FileReader()
    reader.onload = e => setPreview(e.target.result)
    reader.readAsDataURL(f)
  }

  function handleDrop(e) {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files?.[0]
    if (f) handleFileSelect(f)
  }

  function clearFile() {
    setFile(null)
    setPreview(null)
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
      const res = await analyzeQR(fd)
      setResult(res.data)
    } catch (err) {
      if (err?.response?.status === 503 || err?.response?.status === 500) {
        setError('QR decoding library not available. Install pillow and pyzbar on the server, or the backend may be offline.')
      } else {
        setError(err?.response?.data?.detail || 'Analysis failed. Is the server running?')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: 820, margin: '0 auto', padding: '0 16px 60px' }}>

      {/* Header */}
      <div style={{ textAlign: 'center', marginBottom: 32, paddingTop: 20 }}>
        <div style={{
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: 64, height: 64, borderRadius: 18,
          background: 'rgba(34,211,238,0.1)', border: '1px solid rgba(34,211,238,0.3)',
          marginBottom: 14,
        }}>
          <QrCode size={28} style={{ color: '#22d3ee' }} />
        </div>
        <h1 style={{ fontSize: 'clamp(1.5rem, 3.5vw, 2rem)', fontWeight: 900, marginBottom: 8 }}>
          <span className="shimmer-text">QR Code Scanner</span>
        </h1>
        <p style={{ color: 'rgba(255,255,255,0.45)', fontSize: '0.92rem', maxWidth: 520, margin: '0 auto' }}>
          Upload a QR code image. The decoded URL or content will be analysed for scam indicators.
          Your device will never navigate to the decoded link.
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
          <strong style={{ color: 'rgba(255,255,255,0.75)' }}>Safe analysis:</strong>{' '}
          ScamShield decodes the QR code and analyses the content statically.
          The decoded URL is <strong style={{ color: '#10b981' }}>never opened</strong> or fetched by the server.
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
          borderRadius: 16, padding: preview ? 16 : 48,
          textAlign: 'center', cursor: file ? 'default' : 'pointer',
          border: dragging ? '2px dashed #22d3ee' : '2px dashed rgba(34,211,238,0.2)',
          transition: 'all 0.2s',
          background: dragging ? 'rgba(34,211,238,0.04)' : undefined,
          marginBottom: 16,
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept="image/png,image/jpeg,image/jpg,image/webp,image/bmp,image/gif"
          style={{ display: 'none' }}
          onChange={e => handleFileSelect(e.target.files?.[0])}
        />

        {preview ? (
          <div>
            <div style={{ position: 'relative', display: 'inline-block' }}>
              <img
                src={preview}
                alt="QR code preview"
                style={{ maxWidth: 280, maxHeight: 280, borderRadius: 12, border: '1px solid rgba(255,255,255,0.1)' }}
              />
              <button
                onClick={e => { e.stopPropagation(); clearFile() }}
                style={{
                  position: 'absolute', top: -10, right: -10,
                  width: 28, height: 28, borderRadius: '50%',
                  background: 'rgba(255,45,85,0.8)', border: 'none', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff',
                }}
              >
                <X size={14} />
              </button>
            </div>
            <div style={{ marginTop: 12, fontSize: '0.82rem', color: 'rgba(255,255,255,0.4)' }}>
              {file.name} — {(file.size / 1024).toFixed(1)} KB
            </div>
          </div>
        ) : (
          <div>
            <div style={{
              width: 72, height: 72, borderRadius: 20,
              background: 'rgba(34,211,238,0.08)', border: '1px solid rgba(34,211,238,0.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              margin: '0 auto 16px',
            }}>
              <Upload size={30} style={{ color: '#22d3ee' }} />
            </div>
            <p style={{ fontSize: '1rem', fontWeight: 600, marginBottom: 6 }}>
              Drop a QR code image here
            </p>
            <p style={{ fontSize: '0.82rem', color: 'rgba(255,255,255,0.35)' }}>
              or click to browse — PNG, JPEG, WEBP, BMP, GIF (max 10 MB)
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
            style={{ display: 'flex', alignItems: 'center', gap: 8 }}
          >
            {loading ? (
              <>
                <span style={{ width: 16, height: 16, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'radar-spin 0.7s linear infinite', display: 'inline-block' }} />
                Decoding QR…
              </>
            ) : (
              <><Scan size={16} /> Decode & Analyse</>
            )}
          </button>
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{
          background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)',
          borderRadius: 12, padding: '14px 18px', marginBottom: 20,
          display: 'flex', alignItems: 'flex-start', gap: 10,
        }}>
          <AlertTriangle size={18} style={{ color: '#ff2d55', flexShrink: 0, marginTop: 2 }} />
          <span style={{ fontSize: '0.9rem', color: 'rgba(255,255,255,0.75)', lineHeight: 1.5 }}>{error}</span>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '60px 0', gap: 20 }}>
          <div className="radar" />
          <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.9rem' }}>Decoding QR code and analysing content…</p>
        </div>
      )}

      {/* Decoded text preview */}
      {result && !loading && result.decoded_text && (
        <div className="glass" style={{ borderRadius: 14, padding: '16px 20px', marginBottom: 20, borderColor: 'rgba(34,211,238,0.2)' }}>
          <div style={{ fontSize: '0.72rem', color: '#22d3ee', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
            Decoded QR Content ({result.qr_type})
          </div>
          <div className="mono" style={{ fontSize: '0.85rem', color: 'rgba(255,255,255,0.8)', wordBreak: 'break-all', lineHeight: 1.6, background: 'rgba(0,0,0,0.3)', borderRadius: 8, padding: '10px 14px' }}>
            {result.decoded_text}
          </div>
          <p style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.3)', marginTop: 8 }}>
            ⚠️ Do not manually navigate to this URL. Use the analysis below to assess risk first.
          </p>
        </div>
      )}

      {/* Result */}
      {result && !loading && <ResultPanel result={result} />}
    </div>
  )
}

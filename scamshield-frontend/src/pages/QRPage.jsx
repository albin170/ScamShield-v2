import React, { useState, useRef, useEffect } from 'react'
import { analyzeQR } from '../api'
import ResultPanel from '../components/ResultPanel'
import {
  QrCode, Upload, X, AlertTriangle, Scan, Shield, Camera,
  CameraOff, RefreshCw, Smartphone, Wifi, UserCheck, CreditCard,
  FileText, ExternalLink
} from 'lucide-react'

const ACCEPTED_TYPES = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/bmp', 'image/gif']

export default function QRPage() {
  const [mode, setMode] = useState('upload') // 'upload' | 'camera'
  const [file, setFile] = useState(null)
  const [preview, setPreview] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const inputRef = useRef(null)

  // Camera state
  const [cameraActive, setCameraActive] = useState(false)
  const [cameraError, setCameraError] = useState('')
  const videoRef = useRef(null)
  const streamRef = useRef(null)

  // Clean up camera on unmount or mode switch
  useEffect(() => {
    return () => {
      stopCamera()
    }
  }, [])

  function stopCamera() {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(track => track.stop())
      streamRef.current = null
    }
    setCameraActive(false)
  }

  async function startCamera() {
    setError('')
    setCameraError('')
    try {
      if (!navigator.mediaDevices?.getUserMedia) {
        setCameraError('Camera access is not supported by your browser or environment.')
        return
      }
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } }
      })
      streamRef.current = stream
      if (videoRef.current) {
        videoRef.current.srcObject = stream
        await videoRef.current.play()
      }
      setCameraActive(true)
    } catch (err) {
      if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
        setCameraError('Camera permission was denied. Please allow camera access in your browser settings, or switch to Image Upload.')
      } else if (err.name === 'NotFoundError' || err.name === 'DevicesNotFoundError') {
        setCameraError('No camera found on this device. Please use Image Upload.')
      } else {
        setCameraError(`Camera error: ${err.message || 'Unable to start camera stream'}`)
      }
      setCameraActive(false)
    }
  }

  function handleFileSelect(f) {
    if (!f) return
    if (!ACCEPTED_TYPES.includes(f.type)) {
      setError(`Unsupported file type: ${f.type}. Please upload a PNG, JPEG, WEBP, BMP, or GIF image.`)
      return
    }
    if (f.size > 10 * 1024 * 1024) {
      setError('File too large. Maximum size is 10 MB.')
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

  async function handleScanFile(uploadFile) {
    const targetFile = uploadFile || file
    if (!targetFile) return
    setError('')
    setResult(null)
    setLoading(true)
    try {
      const fd = new FormData()
      fd.append('file', targetFile)
      const res = await analyzeQR(fd)
      setResult(res.data)
    } catch (err) {
      if (err?.response?.status === 503) {
        setError('QR decoding engine unavailable on server. Please ensure pyzbar and pillow are installed.')
      } else {
        setError(err?.response?.data?.detail || 'Analysis failed. Is the server running?')
      }
    } finally {
      setLoading(false)
    }
  }

  async function captureCameraFrame() {
    if (!videoRef.current || !cameraActive) return
    const video = videoRef.current
    const canvas = document.createElement('canvas')
    canvas.width = video.videoWidth || 640
    canvas.height = video.videoHeight || 480
    const ctx = canvas.getContext('2d')
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height)

    canvas.toBlob(blob => {
      if (!blob) {
        setError('Failed to capture frame from camera.')
        return
      }
      const capturedFile = new File([blob], 'camera-qr-frame.png', { type: 'image/png' })
      handleScanFile(capturedFile)
    }, 'image/png')
  }

  function getPayloadBadge(qrType) {
    switch (qrType) {
      case 'url':
        return { label: 'Web URL', icon: <ExternalLink size={13} />, color: '#22d3ee', bg: 'rgba(34,211,238,0.1)' }
      case 'social_deeplink':
        return { label: 'Social Media Deep Link', icon: <Smartphone size={13} />, color: '#a855f7', bg: 'rgba(168,85,247,0.1)' }
      case 'wifi':
        return { label: 'Wi-Fi Network Configuration', icon: <Wifi size={13} />, color: '#10b981', bg: 'rgba(16,185,129,0.1)' }
      case 'vcard':
        return { label: 'Contact Card (vCard)', icon: <UserCheck size={13} />, color: '#38bdf8', bg: 'rgba(56,189,248,0.1)' }
      case 'upi':
        return { label: 'UPI Payment Request', icon: <CreditCard size={13} />, color: '#f59e0b', bg: 'rgba(245,158,11,0.1)' }
      default:
        return { label: 'Plain Text Payload', icon: <FileText size={13} />, color: '#94a3b8', bg: 'rgba(148,163,184,0.1)' }
    }
  }

  return (
    <div style={{ maxWidth: 840, margin: '0 auto', padding: '0 16px 60px' }}>

      {/* Header */}
      <div style={{ textAlign: 'center', marginBottom: 28, paddingTop: 20 }}>
        <div style={{
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: 64, height: 64, borderRadius: 18,
          background: 'rgba(34,211,238,0.1)', border: '1px solid rgba(34,211,238,0.3)',
          marginBottom: 14,
        }}>
          <QrCode size={28} style={{ color: '#22d3ee' }} />
        </div>
        <h1 style={{ fontSize: 'clamp(1.5rem, 3.5vw, 2rem)', fontWeight: 900, marginBottom: 8 }}>
          <span className="shimmer-text">Scan That QR Code First</span>
        </h1>
        <p style={{ color: 'rgba(255,255,255,0.45)', fontSize: '0.92rem', maxWidth: 540, margin: '0 auto' }}>
          Before you scan that QR code with your phone — let us check it first. We decode it safely and reveal exactly what it’s hiding.
        </p>
      </div>

      {/* Mode switcher tabs */}
      <div className="tab-bar" style={{ marginBottom: 20 }}>
        <button
          className={`tab-item ${mode === 'upload' ? 'active' : ''}`}
          onClick={() => {
            stopCamera()
            setMode('upload')
            setError('')
          }}
        >
          <Upload size={16} /> Image File Upload
        </button>
        <button
          className={`tab-item ${mode === 'camera' ? 'active' : ''}`}
          onClick={() => {
            setMode('camera')
            setError('')
            startCamera()
          }}
        >
          <Camera size={16} /> Live Camera Scan
        </button>
      </div>

      {/* Safety notice */}
      <div style={{
        background: 'rgba(16,185,129,0.07)', border: '1px solid rgba(16,185,129,0.2)',
        borderRadius: 12, padding: '12px 16px', marginBottom: 20,
        display: 'flex', gap: 10, alignItems: 'flex-start',
      }}>
        <Shield size={16} style={{ color: '#10b981', flexShrink: 0, marginTop: 2 }} />
        <p style={{ fontSize: '0.82rem', color: 'rgba(255,255,255,0.65)', lineHeight: 1.55, margin: 0 }}>
          <strong style={{ color: '#10b981' }}>Safe Sandbox:</strong> QR payloads are decoded and evaluated through the explainable threat pipeline. The decoded content is <strong style={{ color: '#fff' }}>never automatically opened or executed</strong> by your browser.
        </p>
      </div>

      {/* Mode 1: Image File Upload */}
      {mode === 'upload' && (
        <div
          className="glass"
          onDragEnter={() => setDragging(true)}
          onDragLeave={() => setDragging(false)}
          onDragOver={e => e.preventDefault()}
          onDrop={handleDrop}
          onClick={() => !file && inputRef.current?.click()}
          style={{
            borderRadius: 16, padding: preview ? 20 : 48,
            textAlign: 'center', cursor: file ? 'default' : 'pointer',
            border: dragging ? '2px dashed #22d3ee' : '2px dashed rgba(34,211,238,0.25)',
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
                    background: 'rgba(255,45,85,0.85)', border: 'none', cursor: 'pointer',
                    display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff',
                  }}
                  title="Remove image"
                >
                  <X size={14} />
                </button>
              </div>
              <div style={{ marginTop: 12, fontSize: '0.82rem', color: 'rgba(255,255,255,0.5)' }}>
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
              <p style={{ fontSize: '0.82rem', color: 'rgba(255,255,255,0.4)' }}>
                Supports PNG, JPEG, WEBP, BMP, GIF (max 10 MB)
              </p>
            </div>
          )}
        </div>
      )}

      {/* Mode 2: Live Camera Viewfinder */}
      {mode === 'camera' && (
        <div className="glass" style={{ borderRadius: 16, padding: 20, marginBottom: 16, textAlign: 'center' }}>
          {cameraError ? (
            <div style={{ padding: '30px 16px' }}>
              <div style={{
                width: 60, height: 60, borderRadius: '50%', background: 'rgba(255,45,85,0.1)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 14px'
              }}>
                <CameraOff size={28} style={{ color: '#ff2d55' }} />
              </div>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: 8, color: '#ff2d55' }}>
                Camera Unavailable
              </h3>
              <p style={{ fontSize: '0.85rem', color: 'rgba(255,255,255,0.6)', maxWidth: 460, margin: '0 auto 16px', lineHeight: 1.5 }}>
                {cameraError}
              </p>
              <div style={{ display: 'flex', gap: 10, justifyContent: 'center' }}>
                <button className="btn-primary" onClick={startCamera} style={{ fontSize: '0.82rem', padding: '8px 16px' }}>
                  <RefreshCw size={14} /> Retry Camera
                </button>
                <button className="btn-ghost" onClick={() => setMode('upload')} style={{ fontSize: '0.82rem', padding: '8px 16px' }}>
                  Switch to Upload
                </button>
              </div>
            </div>
          ) : (
            <div>
              {/* Viewfinder frame */}
              <div style={{
                position: 'relative', width: '100%', maxWidth: 420, height: 320,
                margin: '0 auto', borderRadius: 14, overflow: 'hidden',
                background: '#000', border: '2px solid rgba(34,211,238,0.3)',
              }}>
                <video
                  ref={videoRef}
                  playsInline
                  muted
                  style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                />

                {/* Viewfinder corner brackets & scanning laser */}
                <div style={{
                  position: 'absolute', inset: '15%',
                  border: '2px dashed rgba(34,211,238,0.7)',
                  borderRadius: 12,
                  pointerEvents: 'none',
                }}>
                  {/* Laser line */}
                  <div style={{
                    position: 'absolute', left: 0, right: 0, height: 2,
                    background: '#22d3ee',
                    boxShadow: '0 0 8px #22d3ee',
                    animation: 'scanline 2s ease-in-out infinite alternate',
                  }} />
                </div>
              </div>

              {/* Camera controls */}
              <div style={{ display: 'flex', justifyContent: 'center', gap: 12, marginTop: 16 }}>
                <button
                  className="btn-primary"
                  onClick={captureCameraFrame}
                  disabled={loading || !cameraActive}
                  style={{ display: 'flex', alignItems: 'center', gap: 8 }}
                >
                  <Scan size={16} /> Capture & Decode QR
                </button>
                <button
                  className="btn-ghost"
                  onClick={stopCamera}
                  style={{ fontSize: '0.82rem', padding: '8px 14px' }}
                >
                  <CameraOff size={14} /> Stop Camera
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Upload mode scan button */}
      {mode === 'upload' && file && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}>
          <button
            className="btn-primary"
            onClick={() => handleScanFile()}
            disabled={loading}
            style={{ display: 'flex', alignItems: 'center', gap: 8 }}
          >
            {loading ? (
              <>
                <span style={{ width: 16, height: 16, border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'radar-spin 0.7s linear infinite', display: 'inline-block' }} />
                Decoding QR…
              </>
            ) : (
              <><Scan size={16} /> Decode & Analyse QR</>
            )}
          </button>
        </div>
      )}

      {/* Error alert */}
      {error && (
        <div style={{
          background: 'rgba(255,45,85,0.1)', border: '1px solid rgba(255,45,85,0.3)',
          borderRadius: 12, padding: '14px 18px', marginBottom: 20,
          display: 'flex', alignItems: 'flex-start', gap: 10,
        }}>
          <AlertTriangle size={18} style={{ color: '#ff2d55', flexShrink: 0, marginTop: 2 }} />
          <span style={{ fontSize: '0.9rem', color: 'rgba(255,255,255,0.85)', lineHeight: 1.5 }}>{error}</span>
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '50px 0', gap: 16 }}>
          <div className="radar" />
          <p style={{ color: 'rgba(255,255,255,0.5)', fontSize: '0.9rem' }}>
            Extracting QR matrix & evaluating security indicators…
          </p>
        </div>
      )}

      {/* Decoded content and payload breakdown */}
      {result && !loading && (
        <div style={{ marginBottom: 24 }}>
          {result.decoded_text ? (
            <div className="glass" style={{ borderRadius: 14, padding: '18px 20px', borderColor: 'rgba(34,211,238,0.3)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <QrCode size={16} style={{ color: '#22d3ee' }} />
                  <span style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.6)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Decoded QR Payload
                  </span>
                </div>

                {/* Payload Type Badge */}
                {(() => {
                  const badge = getPayloadBadge(result.qr_type)
                  return (
                    <span style={{
                      background: badge.bg,
                      border: `1px solid ${badge.color}50`,
                      color: badge.color,
                      borderRadius: 6,
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      padding: '3px 10px',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 5,
                    }}>
                      {badge.icon} {badge.label}
                    </span>
                  )
                })()}
              </div>

              <div className="mono" style={{
                fontSize: '0.85rem', color: '#e2e8f0', wordBreak: 'break-all',
                lineHeight: 1.6, background: 'rgba(0,0,0,0.4)', borderRadius: 8, padding: '12px 14px',
                border: '1px solid rgba(255,255,255,0.08)'
              }}>
                {result.decoded_text}
              </div>

              <p style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.45)', marginTop: 8, marginBottom: 0, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Shield size={12} style={{ color: '#22d3ee', flexShrink: 0 }} /> Isolated Payload: ScamShield never opens decoded URLs without explicit user confirmation.
              </p>
            </div>
          ) : (
            <div className="glass" style={{ borderRadius: 14, padding: '18px 20px', borderColor: 'rgba(255,45,85,0.3)' }}>
              <p style={{ color: '#ff2d55', fontSize: '0.9rem', margin: 0 }}>
                Could not detect or decode a valid QR matrix in this image. Please ensure the QR code is clear, well-lit, and uncropped.
              </p>
            </div>
          )}
        </div>
      )}

      {/* Analysis Result */}
      {result && !loading && <ResultPanel result={result} />}
    </div>
  )
}

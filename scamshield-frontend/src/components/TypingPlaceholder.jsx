import React, { useEffect, useRef, useState } from 'react'

/**
 * Horror Cyber Typing Placeholder
 * Animated typing with glitch effects, eerie humanized cyber-horror wording,
 * and a pulsing blood-red cursor. Cycles per scan type.
 *
 * Props:
 *   scanType: 'url' | 'message' | 'email' | 'qr' | 'file'
 *   value: current input value (hides animation if non-empty)
 *   multiline: positions for textarea
 */

const EXAMPLES = {
  url: [
    '▸ Inspect suspicious URL destination...',
    '▸ https://totally-not-a-scam.ru/clickme',
    '▸ Paste link to inspect brand impersonation & redirects',
    '▸ http://paypa1-verify-account.tk/urgent',
    '▸ Cross-reference known threat intelligence feeds...',
    '▸ Inspecting homoglyphs, typosquatting & IDN punycode...',
    '▸ https://amazon-delivery-update.xyz/track',
  ],
  message: [
    '▸ Paste suspicious message text for fraud inspection...',
    '▸ "URGENT: Your account has been COMPROMISED"',
    '▸ Inspect SMS, WhatsApp, and social engineering bait...',
    '▸ "Congratulations! You have won lottery prize..."',
    '▸ Inspect task scams, bank impersonations & seed phrase drains',
    '▸ "Your OTP is... reply immediately to retain access"',
    '▸ Deterministic analysis with explainable evidence',
  ],
  email: [
    '▸ Paste raw email headers or body content...',
    '▸ From: "security@paypa1-support.com"',
    '▸ Received: from authentication-mismatch.tk...',
    '▸ Subject: Urgent account limitation notification',
    '▸ Full MIME, SPF, DKIM, and DMARC forensic audit',
  ],
  qr: [
    '▸ Upload QR code image for payload inspection...',
    '▸ Decodes matrix locally before executing navigation',
    '▸ Supports PNG, JPEG, WEBP, BMP — inspects URLs and UPI requests',
  ],
  file: [
    '▸ Upload suspicious file for safe static metadata inspection...',
    '▸ Non-executing archive, macro, and double extension audit',
    '▸ Inspects Office macros, ZIP payloads, and PE signatures',
  ],
}

const GLITCH_CHARS = '!@#$%^░▒▓█▄▀■□▪◈0101'

function glitchChar() {
  return GLITCH_CHARS[Math.floor(Math.random() * GLITCH_CHARS.length)]
}

export default function TypingPlaceholder({ scanType = 'url', value = '', multiline = false, inputRef }) {
  const [displayed, setDisplayed] = useState('')
  const [exIdx, setExIdx] = useState(0)
  const [phase, setPhase] = useState('typing') // 'typing' | 'pause' | 'glitch' | 'deleting'
  const [charIdx, setCharIdx] = useState(0)
  const [glitched, setGlitched] = useState('')
  const intervalRef = useRef(null)
  const glitchTimerRef = useRef(null)

  const examples = EXAMPLES[scanType] || EXAMPLES.url
  const hidden = value.length > 0

  useEffect(() => {
    setDisplayed('')
    setExIdx(0)
    setPhase('typing')
    setCharIdx(0)
    setGlitched('')
  }, [scanType])

  // Random ambient glitch flicker on displayed text
  useEffect(() => {
    if (hidden || displayed.length < 4) return
    glitchTimerRef.current = setInterval(() => {
      if (Math.random() < 0.15) {
        const arr = displayed.split('')
        const pos = Math.floor(Math.random() * arr.length)
        arr[pos] = glitchChar()
        setGlitched(arr.join(''))
        setTimeout(() => setGlitched(''), 90)
      }
    }, 300)
    return () => clearInterval(glitchTimerRef.current)
  }, [displayed, hidden])

  useEffect(() => {
    if (hidden) return
    clearInterval(intervalRef.current)

    const target = examples[exIdx % examples.length]

    if (phase === 'typing') {
      intervalRef.current = setInterval(() => {
        setCharIdx(i => {
          const next = i + 1
          setDisplayed(target.slice(0, next))
          if (next >= target.length) {
            clearInterval(intervalRef.current)
            setTimeout(() => setPhase('glitch'), 1400)
          }
          return next
        })
      }, 50)
    } else if (phase === 'glitch') {
      // Rapid glitch burst before deleting
      let ticks = 0
      intervalRef.current = setInterval(() => {
        ticks++
        const base = displayed
        const arr = base.split('')
        for (let i = 0; i < 4; i++) {
          const pos = Math.floor(Math.random() * arr.length)
          arr[pos] = glitchChar()
        }
        setGlitched(arr.join(''))
        if (ticks > 7) {
          clearInterval(intervalRef.current)
          setGlitched('')
          setTimeout(() => setPhase('deleting'), 180)
        }
      }, 75)
    } else if (phase === 'pause') {
      intervalRef.current = setInterval(() => {
        clearInterval(intervalRef.current)
        setPhase('glitch')
      }, 1200)
    } else if (phase === 'deleting') {
      intervalRef.current = setInterval(() => {
        setCharIdx(i => {
          const next = i - 1
          setDisplayed(target.slice(0, next))
          if (next <= 0) {
            clearInterval(intervalRef.current)
            setExIdx(x => x + 1)
            setCharIdx(0)
            setTimeout(() => setPhase('typing'), 480)
          }
          return next
        })
      }, 24)
    }

    return () => clearInterval(intervalRef.current)
  }, [phase, exIdx, hidden, examples])

  if (hidden) return null

  const renderText = glitched || displayed

  return (
    <span
      className={`typing-placeholder horror-typing ${multiline ? 'typing-placeholder--textarea' : ''}`}
      aria-hidden="true"
    >
      <span className="horror-typing-text">{renderText}</span>
      <span className="typing-cursor horror-cursor" />
    </span>
  )
}

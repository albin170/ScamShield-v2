import React, { useEffect, useState } from 'react'

/**
 * FuturisticCursor
 * Polished, high-tech animated neon cursor for desktop.
 * - Glowing core dot + smoothly lerping outer energy ring
 * - Reactive expand & glow on hovering interactive elements
 * - Automatically disabled on mobile/touch screens and when prefers-reduced-motion is active
 */
export default function FuturisticCursor() {
  const [pos, setPos] = useState({ x: -100, y: -100 })
  const [ringPos, setRingPos] = useState({ x: -100, y: -100 })
  const [isHovering, setIsHovering] = useState(false)
  const [isVisible, setIsVisible] = useState(false)

  useEffect(() => {
    // Only run on non-touch devices with fine pointers and no reduced motion preference
    if (typeof window === 'undefined') return
    const isTouch = window.matchMedia('(pointer: coarse)').matches
    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (isTouch || prefersReduced) return

    let rafId
    let mouseX = -100, mouseY = -100
    let ringX = -100, ringY = -100

    const onMouseMove = (e) => {
      mouseX = e.clientX
      mouseY = e.clientY
      setPos({ x: mouseX, y: mouseY })
      if (!isVisible) setIsVisible(true)

      // Check if target is interactive
      const target = e.target
      if (
        target.closest('button') ||
        target.closest('a') ||
        target.closest('input') ||
        target.closest('textarea') ||
        target.closest('[role="button"]') ||
        target.closest('.interactive')
      ) {
        setIsHovering(true)
      } else {
        setIsHovering(false)
      }
    }

    const onMouseLeave = () => setIsVisible(false)
    const onMouseEnter = () => setIsVisible(true)

    const loop = () => {
      // Smooth lerp for outer ring
      ringX += (mouseX - ringX) * 0.22
      ringY += (mouseY - ringY) * 0.22
      setRingPos({ x: ringX, y: ringY })
      rafId = requestAnimationFrame(loop)
    }

    window.addEventListener('mousemove', onMouseMove, { passive: true })
    document.addEventListener('mouseleave', onMouseLeave)
    document.addEventListener('mouseenter', onMouseEnter)
    rafId = requestAnimationFrame(loop)

    return () => {
      window.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseleave', onMouseLeave)
      document.removeEventListener('mouseenter', onMouseEnter)
      cancelAnimationFrame(rafId)
    }
  }, [isVisible])

  if (!isVisible) return null

  return (
    <>
      {/* Outer Lerping Ring */}
      <div
        style={{
          position: 'fixed',
          top: ringPos.y,
          left: ringPos.x,
          width: isHovering ? 46 : 28,
          height: isHovering ? 46 : 28,
          transform: 'translate(-50%, -50%)',
          borderRadius: '50%',
          border: `1.5px solid ${isHovering ? '#22d3ee' : 'rgba(34,211,238,0.5)'}`,
          boxShadow: isHovering ? '0 0 20px rgba(34,211,238,0.5), inset 0 0 10px rgba(34,211,238,0.3)' : '0 0 10px rgba(34,211,238,0.2)',
          pointerEvents: 'none',
          zIndex: 9999,
          transition: 'width 0.2s cubic-bezier(0.16, 1, 0.3, 1), height 0.2s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.2s',
        }}
      />
      {/* Core Center Dot */}
      <div
        style={{
          position: 'fixed',
          top: pos.y,
          left: pos.x,
          width: isHovering ? 8 : 5,
          height: isHovering ? 8 : 5,
          transform: 'translate(-50%, -50%)',
          borderRadius: '50%',
          background: isHovering ? '#22d3ee' : '#ffffff',
          boxShadow: '0 0 8px #22d3ee',
          pointerEvents: 'none',
          zIndex: 10000,
          transition: 'width 0.15s, height 0.15s, background-color 0.15s',
        }}
      />
    </>
  )
}

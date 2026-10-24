import React, { useRef, useEffect } from 'react'

/**
 * MatrixRain — Horror Cyber Background
 * Full-screen canvas rendering falling matrix characters in blood-red and matrix-green.
 * Uses Katakana, binary digits, hex, and ASCII glyphs for maximum eerie vibes.
 * Responds to mouse position for trail depth effect.
 * Respects prefers-reduced-motion.
 */

const MATRIX_CHARS =
  'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン' +
  '0123456789ABCDEF!@#$%^&*<>/?░▒▓■□01'

export default function MatrixRain({ opacity = 0.16 }) {
  const canvasRef = useRef(null)
  const animRef   = useRef(null)
  const mouseRef  = useRef({ x: -999, y: -999 })

  const prefersReducedMotion =
    typeof window !== 'undefined' &&
    window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

  useEffect(() => {
    if (prefersReducedMotion) return

    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')

    const FONT_SIZE = 14
    let W = window.innerWidth
    let H = window.innerHeight

    canvas.width  = W
    canvas.height = H

    const cols = Math.floor(W / FONT_SIZE)

    // Each column: y position (in rows), speed, color mode
    const drops = Array.from({ length: cols }, () => ({
      y:     Math.random() * -50,
      speed: 0.3 + Math.random() * 0.7,
      // color mode: 0 = blood-red, 1 = matrix-green, 2 = dim white
      mode:  Math.random() < 0.6 ? 0 : Math.random() < 0.7 ? 1 : 2,
      chars: Array.from({ length: 20 }, () =>
        MATRIX_CHARS[Math.floor(Math.random() * MATRIX_CHARS.length)]
      ),
      charTimer: 0,
    }))

    const chars = MATRIX_CHARS

    function getColor(mode, alpha, isHead = false) {
      if (isHead) return `rgba(255,255,255,${Math.min(alpha * 1.6, 1).toFixed(2)})`
      if (mode === 0) return `rgba(255,0,60,${alpha.toFixed(2)})`    // blood red
      if (mode === 1) return `rgba(0,255,65,${alpha.toFixed(2)})`    // matrix green
      return `rgba(180,180,255,${(alpha * 0.5).toFixed(2)})`         // dim blue-white
    }

    let frame = 0

    function animate() {
      frame++
      // Dark semi-transparent overlay — creates the trail fade
      ctx.fillStyle = 'rgba(7, 1, 3, 0.08)'
      ctx.fillRect(0, 0, W, H)

      ctx.font = `${FONT_SIZE}px "JetBrains Mono", monospace`

      const mx = mouseRef.current.x
      const my = mouseRef.current.y

      for (let i = 0; i < drops.length; i++) {
        const drop = drops[i]
        const x = i * FONT_SIZE

        // Mouse proximity brightens columns
        const distToMouse = Math.abs(x - mx)
        const mouseBrightness = distToMouse < 120 ? 1 - distToMouse / 120 : 0

        // Randomly mutate characters
        drop.charTimer++
        if (drop.charTimer > 4 + Math.floor(Math.random() * 8)) {
          const idx = Math.floor(Math.random() * drop.chars.length)
          drop.chars[idx] = chars[Math.floor(Math.random() * chars.length)]
          drop.charTimer = 0
        }

        const yPx = Math.floor(drop.y) * FONT_SIZE
        const trailLen = 18 + Math.floor(Math.random() * 6)

        for (let j = 0; j < trailLen; j++) {
          const rowY = yPx - j * FONT_SIZE
          if (rowY < 0 || rowY > H) continue

          const alpha = j === 0
            ? 0.95 + mouseBrightness * 0.05          // head
            : Math.max(0, (1 - j / trailLen) * 0.55 + mouseBrightness * 0.2)

          const ch = drop.chars[j % drop.chars.length]
          ctx.fillStyle = getColor(drop.mode, alpha, j === 0)
          ctx.fillText(ch, x, rowY)
        }

        drop.y += drop.speed

        // Reset when column exits screen, occasionally change color mode
        if (drop.y * FONT_SIZE > H + trailLen * FONT_SIZE) {
          drop.y = Math.random() * -30
          drop.speed = 0.3 + Math.random() * 0.7
          drop.mode = Math.random() < 0.6 ? 0 : Math.random() < 0.7 ? 1 : 2
        }
      }

      animRef.current = requestAnimationFrame(animate)
    }

    animRef.current = requestAnimationFrame(animate)

    function onResize() {
      W = window.innerWidth
      H = window.innerHeight
      canvas.width  = W
      canvas.height = H
    }

    function onMouseMove(e) {
      mouseRef.current = { x: e.clientX, y: e.clientY }
    }

    window.addEventListener('resize', onResize, { passive: true })
    window.addEventListener('mousemove', onMouseMove, { passive: true })

    return () => {
      cancelAnimationFrame(animRef.current)
      window.removeEventListener('resize', onResize)
      window.removeEventListener('mousemove', onMouseMove)
    }
  }, [prefersReducedMotion])

  if (prefersReducedMotion) return null

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        top:    0,
        left:   0,
        width:  '100%',
        height: '100%',
        pointerEvents: 'none',
        zIndex: 0,
        opacity,
        mixBlendMode: 'screen',
      }}
      aria-hidden="true"
    />
  )
}

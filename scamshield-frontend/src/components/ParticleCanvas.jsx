import React, { useRef, useEffect } from 'react'

/**
 * Full-screen Canvas particle system for ScamShield's futuristic background.
 * Renders floating particles in cyan, orange, and purple with connection lines.
 * Responds to mouse movement for parallax effect.
 * Respects prefers-reduced-motion.
 */
export default function ParticleCanvas({ theme = 'cyan' }) {
  const canvasRef = useRef(null)
  const animRef = useRef(null)
  const mouseRef = useRef({ x: 0, y: 0 })

  const prefersReducedMotion =
    typeof window !== 'undefined' &&
    window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

  useEffect(() => {
    if (prefersReducedMotion) return

    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')

    // Theme colors
    const COLORS = {
      cyan:   ['rgba(34,211,238,', 'rgba(59,130,246,'],
      orange: ['rgba(249,115,22,', 'rgba(239,68,68,'],
      purple: ['rgba(168,85,247,', 'rgba(236,72,153,'],
    }
    const palette = COLORS[theme] || COLORS.cyan

    let W = window.innerWidth
    let H = window.innerHeight
    canvas.width = W
    canvas.height = H

    // Particle count scales with screen size, capped for performance
    const COUNT = Math.min(Math.floor((W * H) / 12000), 80)

    class Particle {
      constructor() { this.reset(true) }
      reset(init = false) {
        this.x = Math.random() * W
        this.y = init ? Math.random() * H : H + 10
        this.vx = (Math.random() - 0.5) * 0.4
        this.vy = -(Math.random() * 0.6 + 0.2)
        this.radius = Math.random() * 2 + 0.5
        this.alpha = Math.random() * 0.5 + 0.1
        this.color = palette[Math.floor(Math.random() * palette.length)]
        this.pulse = Math.random() * Math.PI * 2
        this.pulseSpeed = 0.02 + Math.random() * 0.02
      }
      update(mx, my) {
        // Subtle mouse attraction
        const dx = mx - this.x
        const dy = my - this.y
        const dist = Math.sqrt(dx * dx + dy * dy)
        if (dist < 200) {
          this.vx += (dx / dist) * 0.003
          this.vy += (dy / dist) * 0.003
        }
        this.x += this.vx
        this.y += this.vy
        this.pulse += this.pulseSpeed
        this.vx *= 0.99
        this.vy *= 0.99
        if (this.y < -10 || this.x < -50 || this.x > W + 50) this.reset()
      }
      draw() {
        const a = this.alpha * (0.7 + 0.3 * Math.sin(this.pulse))
        ctx.beginPath()
        ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2)
        ctx.fillStyle = `${this.color}${a.toFixed(2)})`
        ctx.fill()
        // Glow
        ctx.beginPath()
        ctx.arc(this.x, this.y, this.radius * 3, 0, Math.PI * 2)
        ctx.fillStyle = `${this.color}${(a * 0.15).toFixed(2)})`
        ctx.fill()
      }
    }

    const particles = Array.from({ length: COUNT }, () => new Particle())

    function drawConnections() {
      const maxDist = 120
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x
          const dy = particles[i].y - particles[j].y
          const dist = Math.sqrt(dx * dx + dy * dy)
          if (dist < maxDist) {
            const a = (1 - dist / maxDist) * 0.12
            ctx.beginPath()
            ctx.moveTo(particles[i].x, particles[i].y)
            ctx.lineTo(particles[j].x, particles[j].y)
            ctx.strokeStyle = `${palette[0]}${a.toFixed(2)})`
            ctx.lineWidth = 0.5
            ctx.stroke()
          }
        }
      }
    }

    function animate() {
      ctx.clearRect(0, 0, W, H)
      const mx = mouseRef.current.x
      const my = mouseRef.current.y
      drawConnections()
      particles.forEach(p => { p.update(mx, my); p.draw() })
      animRef.current = requestAnimationFrame(animate)
    }

    animRef.current = requestAnimationFrame(animate)

    function onResize() {
      W = window.innerWidth
      H = window.innerHeight
      canvas.width = W
      canvas.height = H
    }

    function onMouseMove(e) {
      mouseRef.current = { x: e.clientX, y: e.clientY }
    }

    window.addEventListener('resize', onResize)
    window.addEventListener('mousemove', onMouseMove)

    return () => {
      cancelAnimationFrame(animRef.current)
      window.removeEventListener('resize', onResize)
      window.removeEventListener('mousemove', onMouseMove)
    }
  }, [theme, prefersReducedMotion])

  if (prefersReducedMotion) return null

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        zIndex: 0,
        opacity: 0.7,
      }}
    />
  )
}

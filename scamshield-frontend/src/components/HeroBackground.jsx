import React, { useEffect, useRef } from 'react'
import { useLocation } from 'react-router-dom'
import ThreeMultiverseScene from './ThreeMultiverseScene'

/**
 * HeroBackground — Cyber Security Multiverse Experience
 *
 * Rules:
 *  - Dashboard ('/dashboard') exclusively uses Pic 1 ('/assets/dashboard-art.jpg')
 *    with dynamic cyberpunk animations (cosmic drift, energy vortex pulse, scan sweep, 3D tilt).
 *  - All other routes use the original guardians artwork ('/assets/codeverse-art.webp')
 *    rendered significantly more visible with reduced dark overlays and vivid contrast.
 *  - Respects prefers-reduced-motion.
 */
export default function HeroBackground({ className = '' }) {
  const location = useLocation()
  const isDashboard = location.pathname === '/dashboard'
  const containerRef = useRef(null)
  const imageRef = useRef(null)

  useEffect(() => {
    const prefersReduced =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

    if (prefersReduced) return

    let rafId
    let targetX = 0, targetY = 0
    let currentX = 0, currentY = 0

    const onMouseMove = (e) => {
      targetX = (e.clientX / window.innerWidth - 0.5) * 2
      targetY = (e.clientY / window.innerHeight - 0.5) * 2
    }

    const updateTilt = () => {
      currentX += (targetX - currentX) * 0.05
      currentY += (targetY - currentY) * 0.05

      if (imageRef.current) {
        imageRef.current.style.transform = `
          perspective(1200px)
          rotateY(${currentX * 2.4}deg)
          rotateX(${-currentY * 1.8}deg)
          translateX(${currentX * -10}px)
          translateY(${currentY * -6}px)
          scale(${isDashboard ? 1.05 : 1.04})
        `
      }
      rafId = requestAnimationFrame(updateTilt)
    }

    window.addEventListener('mousemove', onMouseMove, { passive: true })
    rafId = requestAnimationFrame(updateTilt)

    return () => {
      window.removeEventListener('mousemove', onMouseMove)
      cancelAnimationFrame(rafId)
    }
  }, [isDashboard])

  return (
    <div
      ref={containerRef}
      className={`hero-bg-container ${className} ${isDashboard ? 'dashboard-bg-active' : 'standard-bg-active'}`}
      aria-hidden="true"
      style={{
        position: 'fixed',
        inset: 0,
        pointerEvents: 'none',
        zIndex: 0,
        overflow: 'hidden',
        background: '#060913',
      }}
    >
      {/* 1. Main Background Image Container */}
      <div
        style={{
          position: 'absolute',
          inset: '-25px',
          overflow: 'hidden',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <img
          key={isDashboard ? 'dashboard-bg' : 'standard-bg'}
          ref={imageRef}
          src={isDashboard ? '/assets/dashboard-art.jpg' : '/assets/codeverse-art.webp'}
          alt={isDashboard ? 'ScamShield Cyber Dashboard Artwork' : 'ScamShield Multiverse Sentinel Guardians'}
          loading="eager"
          className={isDashboard ? 'animate-dashboard-drift' : ''}
          style={{
            width: '100%',
            height: '100%',
            objectFit: 'cover',
            objectPosition: isDashboard ? 'center 35%' : 'center 20%',
            willChange: 'transform',
            filter: isDashboard
              ? 'brightness(1.04) contrast(1.14) saturate(1.2)'
              : 'brightness(1.02) contrast(1.16) saturate(1.22)',
            transition: 'opacity 0.5s ease-in-out, transform 0.08s ease-out',
          }}
        />
      </div>

      {/* 2. WebGL 3D Particles & Energy Dust */}
      <ThreeMultiverseScene />

      {/* 3. Glowing Cyber Energy Orbs */}
      {isDashboard ? (
        <>
          {/* Glowing Shield Energy Vortex Pulse (Right side where hero shield is) */}
          <div
            style={{
              position: 'absolute',
              right: '12%',
              top: '25%',
              width: '42vw',
              height: '42vw',
              maxWidth: 550,
              maxHeight: 550,
              borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(0,240,255,0.22) 0%, rgba(34,211,238,0.08) 45%, transparent 70%)',
              filter: 'blur(55px)',
              animation: 'dashboard-glow-pulse 5s ease-in-out infinite',
              zIndex: 2,
            }}
          />
          {/* Cosmic Portal Center Glow */}
          <div
            style={{
              position: 'absolute',
              left: '38%',
              top: '12%',
              width: '35vw',
              height: '35vw',
              maxWidth: 450,
              maxHeight: 450,
              borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(168,85,247,0.18) 0%, rgba(99,102,241,0.05) 50%, transparent 70%)',
              filter: 'blur(60px)',
              animation: 'dashboard-glow-pulse 7s ease-in-out infinite 1.5s',
              zIndex: 2,
            }}
          />
        </>
      ) : (
        <>
          {/* Guardian Orbs for standard pages */}
          <div
            style={{
              position: 'absolute',
              left: '4%',
              top: '25%',
              width: '30vw',
              height: '30vw',
              maxWidth: 420,
              maxHeight: 420,
              borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(249,115,22,0.24) 0%, rgba(249,115,22,0.06) 45%, transparent 70%)',
              filter: 'blur(45px)',
              animation: 'energy-pulse 6s ease-in-out infinite',
              zIndex: 2,
            }}
          />
          <div
            style={{
              position: 'absolute',
              left: '50%',
              top: '20%',
              transform: 'translateX(-50%)',
              width: '32vw',
              height: '32vw',
              maxWidth: 480,
              maxHeight: 480,
              borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(34,211,238,0.22) 0%, rgba(59,130,246,0.08) 45%, transparent 70%)',
              filter: 'blur(50px)',
              animation: 'energy-pulse 7s ease-in-out infinite 1s',
              zIndex: 2,
            }}
          />
          <div
            style={{
              position: 'absolute',
              right: '4%',
              top: '25%',
              width: '30vw',
              height: '30vw',
              maxWidth: 420,
              maxHeight: 420,
              borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(168,85,247,0.24) 0%, rgba(236,72,153,0.06) 45%, transparent 70%)',
              filter: 'blur(45px)',
              animation: 'energy-pulse 6.5s ease-in-out infinite 2s',
              zIndex: 2,
            }}
          />
        </>
      )}

      {/* 4. Subtle Cyber Hologram Grid */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          backgroundImage: `
            linear-gradient(rgba(34,211,238,0.035) 1px, transparent 1px),
            linear-gradient(90deg, rgba(34,211,238,0.035) 1px, transparent 1px)
          `,
          backgroundSize: '56px 56px',
          opacity: 0.7,
          zIndex: 3,
        }}
      />

      {/* 5. Animated Laser Scanline Sweep */}
      <div
        className="hero-scanline"
        style={{
          position: 'absolute',
          left: 0,
          right: 0,
          height: 2,
          background: 'linear-gradient(90deg, transparent 5%, rgba(0,240,255,0.45) 50%, transparent 95%)',
          boxShadow: '0 0 12px rgba(0,240,255,0.4)',
          zIndex: 4,
        }}
      />

      {/* 6. High-Contrast Overlay — Lightened so artwork is vividly visible */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background: isDashboard
            ? `
              radial-gradient(circle at 65% 35%, rgba(8,11,20,0.18) 0%, rgba(8,11,20,0.52) 75%),
              linear-gradient(180deg, rgba(8,11,20,0.45) 0%, rgba(8,11,20,0.38) 40%, rgba(8,11,20,0.85) 100%)
            `
            : `
              radial-gradient(circle at 50% 30%, rgba(8,11,20,0.22) 0%, rgba(8,11,20,0.42) 70%),
              linear-gradient(180deg, rgba(8,11,20,0.45) 0%, rgba(8,11,20,0.38) 45%, rgba(8,11,20,0.85) 100%)
            `,
          zIndex: 5,
        }}
      />

      {/* 7. Bottom Gradient Fade for page footer readability */}
      <div
        style={{
          position: 'absolute',
          bottom: 0,
          left: 0,
          right: 0,
          height: '24vh',
          background: 'linear-gradient(to top, rgba(8,11,20,0.95) 0%, rgba(8,11,20,0.6) 50%, transparent 100%)',
          zIndex: 6,
        }}
      />
    </div>
  )
}

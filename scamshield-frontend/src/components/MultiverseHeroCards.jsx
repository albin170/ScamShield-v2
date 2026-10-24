import React, { useState } from 'react'
import { NavLink } from 'react-router-dom'
import { Shield, Zap, Sparkles, ArrowRight, Activity, Terminal, CheckCircle2 } from 'lucide-react'

/**
 * MultiverseHeroCards
 * Displays the 3 individual character artworks as themed 3D interactive cards:
 *   - hero-01.webp: Orange-themed Volt Runner (Message / Social Defense)
 *   - hero-02.webp: Cyan-themed Neon Sentinel (URL / Network Defense)
 *   - hero-03.webp: Purple-themed Void Architect (Email / File Forensics)
 * Plus an animated telemetry monitor with codeverse-hero.gif.
 */
export default function MultiverseHeroCards() {
  const [hoveredCard, setHoveredCard] = useState(null)

  const CARDS = [
    {
      id: 'orange',
      heroImage: '/assets/hero-01.webp',
      badge: 'CORE 01 // VOLT RUNNER',
      title: 'Rapid Message Defense',
      desc: 'High-speed NLP heuristics scanning SMS, WhatsApp, telegram recruitment schemes, and banking urgency alerts.',
      accent: '#f97316',
      accentGlow: 'rgba(249,115,22,0.3)',
      borderClass: 'neon-border-orange',
      link: '/scan',
      btnText: 'Open Message Scanner',
      stats: 'Engine: Multi-Vector NLP Heuristics',
      icon: Zap,
    },
    {
      id: 'cyan',
      heroImage: '/assets/hero-02.webp',
      badge: 'CORE 02 // NEON SENTINEL',
      title: 'Perimeter URL Security',
      desc: 'Active link inspection analyzing Cyrillic homographs, punycode spoofing, suspicious TLDs, and cloaked redirects.',
      accent: '#22d3ee',
      accentGlow: 'rgba(34,211,238,0.3)',
      borderClass: 'neon-border-cyan',
      link: '/',
      btnText: 'Open URL Scanner',
      stats: 'Engine: Verified Brand Domain Registry',
      icon: Shield,
    },
    {
      id: 'purple',
      heroImage: '/assets/hero-03.webp',
      badge: 'CORE 03 // VOID ARCHITECT',
      title: 'Deep Email & File Forensics',
      desc: 'Multi-layer RFC 5322 header verification, DKIM/SPF/DMARC authentication parsing, and static file metadata checks.',
      accent: '#a855f7',
      accentGlow: 'rgba(168,85,247,0.3)',
      borderClass: 'neon-border-purple',
      link: '/email',
      btnText: 'Open Email Forensics',
      stats: 'Engine: RFC 5322 Header Forensics',
      icon: Sparkles,
    },
  ]

  return (
    <section style={{ marginBottom: 44 }}>
      {/* Section Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20, flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{
              display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
              background: '#22d3ee', boxShadow: '0 0 10px #22d3ee',
            }} />
            <span style={{ fontSize: '0.72rem', color: '#22d3ee', fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase' }}>
              Multiverse Sentinel Matrix
            </span>
          </div>
          <h2 style={{ fontSize: '1.3rem', fontWeight: 900, letterSpacing: '-0.01em' }}>
            Tri-Core Cyber Defense Architecture
          </h2>
        </div>

        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          background: 'rgba(8,11,20,0.8)', border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: 99, padding: '5px 14px', fontSize: '0.76rem', color: 'rgba(255,255,255,0.5)',
        }}>
          <span style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: 4 }}>
            <CheckCircle2 size={13} /> Tri-Core Detection Initialized
          </span>
        </div>
      </div>

      {/* 3 Themed Character Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(290px, 1fr))',
        gap: 20,
      }}>
        {CARDS.map((card) => {
          const Icon = card.icon
          const isHovered = hoveredCard === card.id

          return (
            <div
              key={card.id}
              className={`multiverse-card ${card.borderClass}`}
              onMouseEnter={() => setHoveredCard(card.id)}
              onMouseLeave={() => setHoveredCard(null)}
              style={{
                position: 'relative',
                borderRadius: 20,
                background: 'rgba(10, 14, 26, 0.85)',
                backdropFilter: 'blur(16px)',
                border: `1px solid ${isHovered ? card.accent : `${card.accent}33`}`,
                boxShadow: isHovered
                  ? `0 16px 40px rgba(0,0,0,0.6), 0 0 30px ${card.accentGlow}`
                  : '0 10px 30px rgba(0,0,0,0.4)',
                overflow: 'hidden',
                display: 'flex',
                flexDirection: 'column',
                transition: 'all 0.32s cubic-bezier(0.16, 1, 0.3, 1)',
                transform: isHovered ? 'translateY(-6px) scale(1.015)' : 'none',
              }}
            >
              {/* Image Container with Consistent Aspect Ratio & Neon Tint */}
              <div style={{
                position: 'relative',
                width: '100%',
                height: 230,
                overflow: 'hidden',
                background: '#060913',
              }}>
                <img
                  src={card.heroImage}
                  alt={card.title}
                  loading="lazy"
                  style={{
                    width: '100%',
                    height: '100%',
                    objectFit: 'cover',
                    objectPosition: 'center 20%',
                    transition: 'transform 0.5s cubic-bezier(0.16, 1, 0.3, 1)',
                    transform: isHovered ? 'scale(1.08)' : 'scale(1)',
                    filter: `brightness(0.95) contrast(1.08) drop-shadow(0 0 16px ${card.accentGlow})`,
                  }}
                />
                {/* Gradient Overlays for Cinematic Contrast */}
                <div style={{
                  position: 'absolute',
                  inset: 0,
                  background: `linear-gradient(to top, rgba(10,14,26,1) 0%, rgba(10,14,26,0.2) 60%, transparent 100%)`,
                }} />

                {/* Top Badge */}
                <div style={{
                  position: 'absolute',
                  top: 14,
                  left: 14,
                  background: 'rgba(8,11,20,0.85)',
                  border: `1px solid ${card.accent}66`,
                  borderRadius: 8,
                  padding: '4px 10px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  backdropFilter: 'blur(8px)',
                }}>
                  <Icon size={12} style={{ color: card.accent }} />
                  <span style={{ fontSize: '0.66rem', fontWeight: 800, color: card.accent, letterSpacing: '0.08em' }}>
                    {card.badge}
                  </span>
                </div>
              </div>

              {/* Card Body */}
              <div style={{ padding: '18px 20px 22px', flex: 1, display: 'flex', flexDirection: 'column' }}>
                <h3 style={{ fontSize: '1.15rem', fontWeight: 800, marginBottom: 8, color: '#f1f5f9' }}>
                  {card.title}
                </h3>
                <p style={{ fontSize: '0.82rem', color: 'rgba(255,255,255,0.6)', lineHeight: 1.55, marginBottom: 16, flex: 1 }}>
                  {card.desc}
                </p>

                {/* Telemetry info */}
                <div style={{
                  fontSize: '0.72rem',
                  color: 'rgba(255,255,255,0.4)',
                  borderTop: '1px solid rgba(255,255,255,0.06)',
                  paddingTop: 10,
                  marginBottom: 14,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}>
                  <span>{card.stats}</span>
                  <span style={{ color: card.accent }}>● Ready</span>
                </div>

                {/* Action Link */}
                <NavLink to={card.link} style={{ textDecoration: 'none' }}>
                  <button
                    style={{
                      width: '100%',
                      background: isHovered ? card.accent : 'rgba(255,255,255,0.05)',
                      color: isHovered ? '#000' : '#fff',
                      border: `1px solid ${isHovered ? card.accent : `${card.accent}55`}`,
                      borderRadius: 12,
                      padding: '10px 16px',
                      fontSize: '0.84rem',
                      fontWeight: 700,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: 8,
                      transition: 'all 0.22s ease',
                      boxShadow: isHovered ? `0 0 20px ${card.accentGlow}` : 'none',
                    }}
                  >
                    <span>{card.btnText}</span>
                    <ArrowRight size={14} />
                  </button>
                </NavLink>
              </div>
            </div>
          )
        })}
      </div>

      {/* Animated Live Shield Monitor with codeverse-hero.gif */}
      <div
        className="glass"
        style={{
          marginTop: 20,
          borderRadius: 18,
          padding: '16px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 16,
          border: '1px solid rgba(34,211,238,0.22)',
          background: 'linear-gradient(90deg, rgba(8,145,178,0.08) 0%, rgba(168,85,247,0.08) 100%)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          {/* Hero GIF Thumbnail */}
          <div style={{
            width: 52,
            height: 52,
            borderRadius: 12,
            overflow: 'hidden',
            border: '1px solid rgba(34,211,238,0.4)',
            boxShadow: '0 0 16px rgba(34,211,238,0.25)',
            flexShrink: 0,
            background: '#090e1a',
          }}>
            <img
              src="/assets/codeverse-hero.gif"
              alt="Active Threat Shield"
              style={{ width: '100%', height: '100%', objectFit: 'cover' }}
            />
          </div>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: '0.92rem', fontWeight: 800 }}>Continuous Shield Protocol</span>
              <span className="tag" style={{ background: 'rgba(16,185,129,0.15)', color: '#10b981', border: '1px solid rgba(16,185,129,0.3)', fontSize: '0.68rem', padding: '2px 8px' }}>
                HEURISTICS ACTIVE
              </span>
            </div>
            <p style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.45)', marginTop: 2 }}>
              Real-time multi-vector threat heuristics active across all network inputs.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <NavLink to="/demo" style={{ textDecoration: 'none' }}>
            <button className="btn-ghost" style={{ fontSize: '0.8rem', padding: '7px 14px' }}>
              Run Benchmark
            </button>
          </NavLink>
          <NavLink to="/admin/login" style={{ textDecoration: 'none' }}>
            <button style={{
              background: 'linear-gradient(135deg, rgba(8,145,178,0.6), rgba(168,85,247,0.5))',
              border: '1px solid rgba(34,211,238,0.4)',
              color: '#fff',
              borderRadius: 10,
              padding: '7px 16px',
              fontSize: '0.8rem',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}>
              <Terminal size={13} />
              <span>Admin Console</span>
            </button>
          </NavLink>
        </div>
      </div>
    </section>
  )
}

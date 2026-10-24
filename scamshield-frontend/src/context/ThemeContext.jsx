import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { getThemeSettings } from '../api'

const ThemeContext = createContext(null)

const THEME_PRESETS = {
  cyan_sentinel: {
    id: 'cyan_sentinel',
    name: 'Cyan Sentinel',
    primary: '#22d3ee',
    secondary: '#3b82f6',
    accent: '#0891b2',
    glowIntensity: 0.35,
    overlayStrength: 0.72,
    animationIntensity: 1.0,
  },
  orange_volt: {
    id: 'orange_volt',
    name: 'Orange Volt',
    primary: '#f97316',
    secondary: '#ef4444',
    accent: '#fb923c',
    glowIntensity: 0.45,
    overlayStrength: 0.68,
    animationIntensity: 1.2,
  },
  purple_void: {
    id: 'purple_void',
    name: 'Purple Void',
    primary: '#a855f7',
    secondary: '#ec4899',
    accent: '#7c3aed',
    glowIntensity: 0.4,
    overlayStrength: 0.75,
    animationIntensity: 0.95,
  },
}

export function ThemeProvider({ children }) {
  const [activeThemeId, setActiveThemeId] = useState('cyan_sentinel')
  const [glowIntensity, setGlowIntensity] = useState(0.35)
  const [overlayStrength, setOverlayStrength] = useState(0.72)
  const [animationIntensity, setAnimationIntensity] = useState(1.0)
  const [loading, setLoading] = useState(true)

  const applyThemeVariables = useCallback((themeId, glow, overlay, anim) => {
    const preset = THEME_PRESETS[themeId] || THEME_PRESETS.cyan_sentinel
    const root = document.documentElement

    // Safe sanitized CSS custom properties
    root.style.setProperty('--theme-primary', preset.primary)
    root.style.setProperty('--theme-secondary', preset.secondary)
    root.style.setProperty('--theme-accent', preset.accent)
    root.style.setProperty('--neon-glow-intensity', String(glow))
    root.style.setProperty('--bg-overlay-strength', String(overlay))
    root.style.setProperty('--animation-intensity', String(anim))
  }, [])

  const fetchTheme = useCallback(async () => {
    try {
      const res = await getThemeSettings()
      const data = res.data
      if (data.active_theme && THEME_PRESETS[data.active_theme]) {
        setActiveThemeId(data.active_theme)
      }
      const glow = parseFloat(data.neon_glow_intensity) || 0.35
      const overlay = parseFloat(data.bg_overlay_strength) || 0.72
      const anim = parseFloat(data.animation_intensity) || 1.0

      setGlowIntensity(glow)
      setOverlayStrength(overlay)
      setAnimationIntensity(anim)

      applyThemeVariables(data.active_theme || 'cyan_sentinel', glow, overlay, anim)
    } catch {
      // Fallback to Cyan Sentinel
      applyThemeVariables('cyan_sentinel', 0.35, 0.72, 1.0)
    } finally {
      setLoading(false)
    }
  }, [applyThemeVariables])

  useEffect(() => {
    fetchTheme()
  }, [fetchTheme])

  const setTheme = (themeId, customGlow, customOverlay, customAnim) => {
    setActiveThemeId(themeId)
    const g = customGlow !== undefined ? customGlow : glowIntensity
    const o = customOverlay !== undefined ? customOverlay : overlayStrength
    const a = customAnim !== undefined ? customAnim : animationIntensity
    if (customGlow !== undefined) setGlowIntensity(g)
    if (customOverlay !== undefined) setOverlayStrength(o)
    if (customAnim !== undefined) setAnimationIntensity(a)
    applyThemeVariables(themeId, g, o, a)
  }

  return (
    <ThemeContext.Provider
      value={{
        activeThemeId,
        theme: THEME_PRESETS[activeThemeId] || THEME_PRESETS.cyan_sentinel,
        presets: THEME_PRESETS,
        glowIntensity,
        overlayStrength,
        animationIntensity,
        setTheme,
        refreshTheme: fetchTheme,
        loading,
      }}
    >
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider')
  return ctx
}

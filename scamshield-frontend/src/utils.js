// Risk level helpers shared across components

export const RISK_META = {
  safe:     { label: 'Safe',     color: '#10b981', bg: 'bg-risk-safe',     glow: 'glow-green',  icon: '✓', score_class: 'risk-safe' },
  low:      { label: 'Low Risk', color: '#22d3ee', bg: 'bg-risk-low',      glow: 'glow-cyan',   icon: '↓', score_class: 'risk-low' },
  medium:   { label: 'Medium',   color: '#f59e0b', bg: 'bg-risk-medium',   glow: 'glow-yellow', icon: '!', score_class: 'risk-medium' },
  high:     { label: 'High',     color: '#f97316', bg: 'bg-risk-high',     glow: 'glow-orange', icon: '⚠', score_class: 'risk-high' },
  critical: { label: 'Critical', color: '#ff2d55', bg: 'bg-risk-critical', glow: 'glow-red',    icon: '✕', score_class: 'risk-critical' },
}

export const SEVERITY_META = {
  safe:     { label: 'Safe',     cls: 'severity-safe' },
  low:      { label: 'Low',      cls: 'severity-low' },
  medium:   { label: 'Medium',   cls: 'severity-medium' },
  high:     { label: 'High',     cls: 'severity-high' },
  critical: { label: 'Critical', cls: 'severity-critical' },
}

export function getRiskMeta(level) {
  return RISK_META[level] ?? RISK_META.medium
}

export function getSeverityMeta(severity) {
  return SEVERITY_META[severity] ?? SEVERITY_META.medium
}

export function formatDate(iso) {
  return new Date(iso).toLocaleString('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

export function truncate(str, len = 60) {
  return str && str.length > len ? str.slice(0, len) + '…' : str
}

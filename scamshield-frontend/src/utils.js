// Risk level helpers shared across components

export const RISK_META = {
  safe:     { label: 'Safe',     color: '#10b981', bg: 'bg-risk-safe',     glow: 'glow-green',  icon: 'CLEAN', score_class: 'risk-safe' },
  low:      { label: 'Low Risk', color: '#22d3ee', bg: 'bg-risk-low',      glow: 'glow-cyan',   icon: 'LOW',   score_class: 'risk-low' },
  medium:   { label: 'Medium',   color: '#f59e0b', bg: 'bg-risk-medium',   glow: 'glow-yellow', icon: 'WARN',  score_class: 'risk-medium' },
  high:     { label: 'High',     color: '#f97316', bg: 'bg-risk-high',     glow: 'glow-orange', icon: 'RISK',  score_class: 'risk-high' },
  critical: { label: 'Critical', color: '#ff2d55', bg: 'bg-risk-critical', glow: 'glow-red',    icon: 'ALERT', score_class: 'risk-critical' },
}

export const SEVERITY_META = {
  safe:     { label: 'Safe',     cls: 'severity-safe' },
  info:     { label: 'Info',     cls: 'severity-low' },
  low:      { label: 'Low',      cls: 'severity-low' },
  medium:   { label: 'Medium',   cls: 'severity-medium' },
  high:     { label: 'High',     cls: 'severity-high' },
  critical: { label: 'Critical', cls: 'severity-critical' },
}

export const VERDICT_META = {
  'MALICIOUS': { label: 'MALICIOUS', color: '#ff2d55', bg: 'rgba(255,45,85,0.15)', glow: 'glow-red', icon: 'THREAT', desc: 'Credible threat indicators identified' },
  'SUSPICIOUS': { label: 'SUSPICIOUS', color: '#f59e0b', bg: 'rgba(245,158,11,0.15)', glow: 'glow-yellow', icon: 'REVIEW', desc: 'Meaningful risk indicators present' },
  'NO KNOWN THREAT FOUND': { label: 'NO KNOWN THREAT FOUND', color: '#10b981', bg: 'rgba(16,185,129,0.15)', glow: 'glow-green', icon: 'VERIFIED', desc: 'Checks did not find a known threat' },
  'UNKNOWN / UNABLE TO VERIFY': { label: 'UNKNOWN / UNABLE TO VERIFY', color: '#38bdf8', bg: 'rgba(56,189,248,0.15)', glow: 'glow-cyan', icon: 'UNKNOWN', desc: 'Insufficient evidence or input' },
}

export function getRiskMeta(level) {
  return RISK_META[level] ?? RISK_META.medium
}

export function getVerdictMeta(verdict, fallbackLevel) {
  if (verdict && VERDICT_META[verdict]) return VERDICT_META[verdict]
  if (fallbackLevel === 'critical' || fallbackLevel === 'high') return VERDICT_META['MALICIOUS']
  if (fallbackLevel === 'medium') return VERDICT_META['SUSPICIOUS']
  if (fallbackLevel === 'safe' || fallbackLevel === 'low') return VERDICT_META['NO KNOWN THREAT FOUND']
  return VERDICT_META['UNKNOWN / UNABLE TO VERIFY']
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

// All available permissions in the system
export const ALL_PERMISSIONS = [
  'view_stats',
  'view_history',
  'clear_history',
  'manage_users',
  'view_audit_log',
  'manage_settings',
  'view_errors',
  'view_analytics',
  'manage_integrations',
]

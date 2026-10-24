import React, { useState, useEffect, useRef } from 'react'
import { Bell, X, Check, AlertTriangle, Info, CheckCircle } from 'lucide-react'
import { adminNotifications, adminMarkRead } from '../api'
import { useAuth, useIsAdmin } from '../context/AuthContext'

const TYPE_ICON = {
  info:    Info,
  warning: AlertTriangle,
  success: CheckCircle,
  error:   AlertTriangle,
}

const TYPE_COLOR = {
  info:    '#22d3ee',
  warning: '#f59e0b',
  success: '#10b981',
  error:   '#ff2d55',
}

export default function NotificationBell() {
  const { user } = useAuth()
  const isAdmin = useIsAdmin()
  const [notifications, setNotifications] = useState([])
  const [open, setOpen] = useState(false)
  const panelRef = useRef(null)

  const unread = notifications.filter(n => !n.is_read).length

  const fetchNotifications = async () => {
    if (!isAdmin) return
    try {
      const res = await adminNotifications()
      setNotifications(res.data)
    } catch { /* silent */ }
  }

  useEffect(() => {
    if (isAdmin) {
      fetchNotifications()
      const interval = setInterval(fetchNotifications, 60000) // refresh every minute
      return () => clearInterval(interval)
    }
  }, [isAdmin])

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const markRead = async (id) => {
    try {
      await adminMarkRead(id)
      setNotifications(prev =>
        prev.map(n => n.id === id ? { ...n, is_read: 1 } : n)
      )
    } catch { /* silent */ }
  }

  if (!isAdmin) return null

  return (
    <div ref={panelRef} style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          position: 'relative',
          background: 'none',
          border: '1px solid rgba(99,179,237,0.15)',
          borderRadius: 10,
          padding: '6px 10px',
          cursor: 'pointer',
          color: unread > 0 ? '#22d3ee' : 'rgba(255,255,255,0.4)',
          display: 'flex',
          alignItems: 'center',
          gap: 4,
          transition: 'all 0.2s',
        }}
        title="Notifications"
      >
        <Bell size={16} style={{ animation: unread > 0 ? 'bell-ring 2s ease infinite' : 'none' }} />
        {unread > 0 && (
          <span style={{
            position: 'absolute',
            top: 4,
            right: 4,
            width: 8,
            height: 8,
            borderRadius: '50%',
            background: '#ff2d55',
            border: '1.5px solid #080b14',
          }} />
        )}
      </button>

      {open && (
        <div style={{
          position: 'absolute',
          top: 'calc(100% + 8px)',
          right: 0,
          width: 320,
          maxHeight: 400,
          overflowY: 'auto',
          background: 'rgba(13,19,33,0.98)',
          border: '1px solid rgba(34,211,238,0.2)',
          borderRadius: 14,
          boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
          zIndex: 200,
        }}>
          <div style={{
            padding: '14px 16px 10px',
            borderBottom: '1px solid rgba(255,255,255,0.06)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}>
            <span style={{ fontWeight: 700, fontSize: '0.88rem' }}>
              Notifications {unread > 0 && <span style={{ color: '#22d3ee' }}>({unread})</span>}
            </span>
            <button onClick={() => setOpen(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.3)' }}>
              <X size={14} />
            </button>
          </div>

          {notifications.length === 0 ? (
            <div style={{ padding: '24px 16px', textAlign: 'center', color: 'rgba(255,255,255,0.3)', fontSize: '0.85rem' }}>
              No notifications
            </div>
          ) : (
            notifications.map(n => {
              const Icon = TYPE_ICON[n.type] || Info
              const color = TYPE_COLOR[n.type] || '#22d3ee'
              return (
                <div
                  key={n.id}
                  style={{
                    padding: '12px 16px',
                    borderBottom: '1px solid rgba(255,255,255,0.04)',
                    background: n.is_read ? 'transparent' : 'rgba(34,211,238,0.04)',
                    display: 'flex',
                    gap: 10,
                    alignItems: 'flex-start',
                  }}
                >
                  <Icon size={14} style={{ color, flexShrink: 0, marginTop: 2 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: '0.82rem', marginBottom: 2 }}>{n.title}</div>
                    <div style={{ fontSize: '0.76rem', color: 'rgba(255,255,255,0.5)', lineHeight: 1.4 }}>{n.message}</div>
                    <div style={{ fontSize: '0.68rem', color: 'rgba(255,255,255,0.25)', marginTop: 4 }}>
                      {new Date(n.created_at).toLocaleString()}
                    </div>
                  </div>
                  {!n.is_read && (
                    <button
                      onClick={() => markRead(n.id)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.3)', flexShrink: 0 }}
                      title="Mark as read"
                    >
                      <Check size={13} />
                    </button>
                  )}
                </div>
              )
            })
          )}
        </div>
      )}
    </div>
  )
}

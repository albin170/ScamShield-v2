import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { authMe, authLogin, authLogout } from '../api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [checked, setChecked] = useState(false)

  const checkAuth = useCallback(async () => {
    try {
      const res = await authMe()
      setUser(res.data)
    } catch {
      setUser(null)
    } finally {
      setLoading(false)
      setChecked(true)
    }
  }, [])

  useEffect(() => {
    checkAuth()
  }, [checkAuth])

  const login = async (username, password) => {
    const res = await authLogin(username, password)
    // Refresh user state from server
    await checkAuth()
    return res.data
  }

  const logout = async () => {
    try { await authLogout() } catch { /* ignore */ }
    setUser(null)
  }

  const refreshUser = checkAuth

  return (
    <AuthContext.Provider value={{ user, loading, checked, login, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}

export function useIsAdmin() {
  const { user } = useAuth()
  return user?.role === 'admin' || user?.role === 'superadmin'
}

export function useIsSuperAdmin() {
  const { user } = useAuth()
  return user?.role === 'superadmin'
}

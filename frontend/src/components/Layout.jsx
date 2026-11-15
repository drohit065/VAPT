import { useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { api, setToken } from '../api.js'

const RANK = { viewer: 0, analyst: 1, admin: 2 }
export const can = (user, role) => !!user && RANK[user.role] >= RANK[role]

const ICONS = {
  dashboard: 'M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z',
  projects: 'M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6z',
  scan: 'M12 5v14M5 12h14',
  users: 'M16 11a4 4 0 1 0-8 0M4 20a8 8 0 0 1 16 0',
  audit: 'M9 5h10M9 12h10M9 19h10M4 5h.01M4 12h.01M4 19h.01',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM4 12h2M18 12h2M12 4v2M12 18v2M6.3 6.3l1.4 1.4M16.3 16.3l1.4 1.4M6.3 17.7l1.4-1.4M16.3 7.7l1.4-1.4',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
}

export function Icon({ name, size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"
         strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={ICONS[name]} />
    </svg>
  )
}

function Item({ to, icon, children, end }) {
  return (
    <NavLink to={to} end={end}>
      <Icon name={icon} /><span>{children}</span>
    </NavLink>
  )
}

export default function Layout() {
  const [open, setOpen] = useState(false)
  const [user, setUser] = useState(null)
  const navigate = useNavigate()
  const location = useLocation()

  useEffect(() => { setOpen(false) }, [location.pathname])
  useEffect(() => { api('/api/auth/me').then(setUser).catch(() => {}) }, [])

  async function logout() {
    try { await api('/api/auth/logout', { method: 'POST' }) } catch { /* already signed out */ }
    setToken(null)
    navigate('/login', { replace: true })
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">VAPT <span>Scanner</span></div>
        <button onClick={() => setOpen(o => !o)} aria-expanded={open} aria-label="Menu">
          {open ? 'Close' : 'Menu'}
        </button>
      </header>
      <aside className={`sidebar${open ? ' open' : ''}`}>
        <div className="brand">VAPT <span>Scanner</span></div>
        <nav className="nav">
          <div className="nav-section">Security</div>
          <Item to="/" icon="dashboard" end>Dashboard</Item>
          <Item to="/projects" icon="projects">Projects</Item>
          {can(user, 'analyst') && <Item to="/scans/new" icon="scan">New scan</Item>}
          {can(user, 'admin') && (
            <>
              <div className="nav-section">Administration</div>
              <Item to="/users" icon="users">Users</Item>
              <Item to="/audit" icon="audit">Audit log</Item>
              <Item to="/settings" icon="settings">Settings</Item>
            </>
          )}
        </nav>
        <div className="spacer" />
        {user && (
          <div className="user-card">
            <div className="avatar" aria-hidden>{user.username.slice(0, 1).toUpperCase()}</div>
            <div className="user-meta">
              <div className="user-name">{user.username}</div>
              <div className="user-role">{user.role}{user.builtin ? ' · built-in' : ''}</div>
            </div>
          </div>
        )}
        <button className="linkbtn signout" onClick={logout}><Icon name="logout" size={16} /> Sign out</button>
      </aside>
      <main className="main">
        <Outlet context={{ user }} />
      </main>
    </div>
  )
}

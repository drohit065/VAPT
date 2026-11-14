import { useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { api, setToken } from '../api.js'

const RANK = { viewer: 0, analyst: 1, admin: 2 }
export const can = (user, role) => !!user && RANK[user.role] >= RANK[role]

export default function Layout() {
  const [open, setOpen] = useState(false)
  const [user, setUser] = useState(null)
  const navigate = useNavigate()
  const location = useLocation()

  useEffect(() => { setOpen(false) }, [location.pathname])
  useEffect(() => { api('/api/auth/me').then(setUser).catch(() => {}) }, [])

  function logout() {
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
          <NavLink to="/projects">Projects</NavLink>
          {can(user, 'analyst') && <NavLink to="/scans/new">New scan</NavLink>}
          {can(user, 'admin') && <NavLink to="/users">Users</NavLink>}
          {can(user, 'admin') && <NavLink to="/audit">Audit log</NavLink>}
        </nav>
        <div className="spacer" />
        {user && (
          <div className="user">
            Signed in as {user.username}
            <div className="small" style={{ opacity: 0.7 }}>{user.role}{user.builtin ? ' (built-in)' : ''}</div>
          </div>
        )}
        <button className="linkbtn" onClick={logout}>Sign out</button>
      </aside>
      <main className="main">
        <Outlet context={{ user }} />
      </main>
    </div>
  )
}

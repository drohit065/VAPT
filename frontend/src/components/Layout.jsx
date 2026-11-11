import { useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { api, setToken } from '../api.js'

export default function Layout() {
  const [open, setOpen] = useState(false)
  const [user, setUser] = useState('')
  const navigate = useNavigate()
  const location = useLocation()

  useEffect(() => { setOpen(false) }, [location.pathname])
  useEffect(() => { api('/api/auth/me').then(d => setUser(d.username)).catch(() => {}) }, [])

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
          <NavLink to="/scans/new">New scan</NavLink>
        </nav>
        <div className="spacer" />
        {user && <div className="user">Signed in as {user}</div>}
        <button className="linkbtn" onClick={logout}>Sign out</button>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}

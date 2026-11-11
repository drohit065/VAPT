import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, setToken } from '../api.js'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const data = await api('/api/auth/login', { method: 'POST', body: { username, password } })
      setToken(data.access_token)
      navigate('/projects', { replace: true })
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="card login-card" onSubmit={submit}>
        <div className="brand">VAPT <span>Scanner</span></div>
        <p className="muted small" style={{ marginTop: 0 }}>Source code security scanning. Read-only.</p>
        {error && <div className="error">{error}</div>}
        <div className="field">
          <label htmlFor="u">Username</label>
          <input id="u" type="text" autoComplete="username" value={username}
                 onChange={e => setUsername(e.target.value)} required />
        </div>
        <div className="field">
          <label htmlFor="p">Password</label>
          <input id="p" type="password" autoComplete="current-password" value={password}
                 onChange={e => setPassword(e.target.value)} required />
        </div>
        <button className="btn" style={{ width: '100%' }} disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}

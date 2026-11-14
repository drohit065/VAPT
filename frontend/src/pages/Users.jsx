import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { fmtTime } from '../components/Severity.jsx'

const ROLE_HELP = {
  viewer: 'Read projects, reports and exports',
  analyst: 'Viewer + start scans, triage findings, schedules',
  admin: 'Analyst + manage users and read the audit log',
}

export default function Users() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [form, setForm] = useState({ username: '', password: '', role: 'viewer' })
  const [busy, setBusy] = useState(false)

  const load = () => api('/api/users').then(setData).catch(e => setError(e.message))
  useEffect(() => { load() }, [])

  async function create(e) {
    e.preventDefault()
    setBusy(true); setError(''); setMsg('')
    try {
      await api('/api/users', { method: 'POST', body: form })
      setMsg(`User ${form.username} created.`)
      setForm({ username: '', password: '', role: 'viewer' })
      load()
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  async function patch(u, body, done) {
    setError(''); setMsg('')
    try {
      await api(`/api/users/${u.id}`, { method: 'PATCH', body })
      setMsg(done)
      load()
    } catch (err) { setError(err.message) }
  }

  async function resetPassword(u) {
    const pw = window.prompt(`New password for ${u.username} (at least 12 characters):`)
    if (pw) patch(u, { password: pw }, `Password for ${u.username} changed; their sessions were ended.`)
  }

  async function remove(u) {
    if (!window.confirm(`Delete user ${u.username}? This cannot be undone.`)) return
    setError(''); setMsg('')
    try {
      await api(`/api/users/${u.id}`, { method: 'DELETE' })
      setMsg(`User ${u.username} deleted.`)
      load()
    } catch (err) { setError(err.message) }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Users</h1>
          <div className="muted">Changing a role, password or deactivating a user ends their open sessions.</div>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      {msg && <div className="info">{msg}</div>}

      <form className="card" onSubmit={create}>
        <h2>Add user</h2>
        <div className="grid3">
          <div className="field">
            <label htmlFor="nu">Username</label>
            <input id="nu" value={form.username} autoComplete="off" required
                   onChange={e => setForm({ ...form, username: e.target.value })} />
          </div>
          <div className="field">
            <label htmlFor="np">Password <span className="muted small">(12+ characters)</span></label>
            <input id="np" type="password" value={form.password} autoComplete="new-password" required minLength={12}
                   onChange={e => setForm({ ...form, password: e.target.value })} />
          </div>
          <div className="field">
            <label htmlFor="nr">Role</label>
            <select id="nr" value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}>
              {Object.keys(ROLE_HELP).map(r => <option key={r} value={r}>{r}</option>)}
            </select>
            <div className="small muted" style={{ marginTop: 4 }}>{ROLE_HELP[form.role]}</div>
          </div>
        </div>
        <button className="btn" disabled={busy}>{busy ? 'Adding…' : 'Add user'}</button>
      </form>

      <div className="card" style={{ padding: 8 }}>
        {!data && !error && <div className="empty">Loading…</div>}
        {data && (
          <table className="list responsive">
            <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last login</th><th></th></tr></thead>
            <tbody>
              <tr>
                <td data-label="User"><strong>{data.builtin_admin}</strong></td>
                <td data-label="Role">admin</td>
                <td data-label="Status"><span className="muted">built-in (from .env)</span></td>
                <td data-label="Last login">—</td>
                <td />
              </tr>
              {data.users.map(u => (
                <tr key={u.id}>
                  <td data-label="User"><strong>{u.username}</strong></td>
                  <td data-label="Role">
                    <select value={u.role} aria-label={`Role of ${u.username}`}
                            onChange={e => patch(u, { role: e.target.value }, `${u.username} is now ${e.target.value}.`)}>
                      {data.roles.map(r => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </td>
                  <td data-label="Status">{u.active ? 'Active' : <span className="muted">Deactivated</span>}</td>
                  <td data-label="Last login">{fmtTime(u.last_login_at)}</td>
                  <td data-label="" className="row-actions">
                    <button type="button" className="linkbtn"
                            onClick={() => patch(u, { active: !u.active }, `${u.username} ${u.active ? 'deactivated' : 'activated'}.`)}>
                      {u.active ? 'Deactivate' : 'Activate'}
                    </button>
                    <button type="button" className="linkbtn" onClick={() => resetPassword(u)}>Reset password</button>
                    <button type="button" className="linkbtn danger" onClick={() => remove(u)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}

import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { fmtTime } from '../components/Severity.jsx'

const ACTIONS = ['', 'login', 'login_failed', 'scan_created', 'finding_status', 'schedule_changed',
  'export_pdf', 'export_csv', 'export_sarif', 'user_created', 'user_updated', 'user_deleted']

function detailText(d) {
  if (!d || !Object.keys(d).length) return ''
  return Object.entries(d).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(' → ') : String(v)}`).join(' · ')
}

export default function Audit() {
  const [rows, setRows] = useState(null)
  const [error, setError] = useState('')
  const [action, setAction] = useState('')
  const [username, setUsername] = useState('')

  useEffect(() => {
    const q = new URLSearchParams({ limit: '300' })
    if (action) q.set('action', action)
    if (username.trim()) q.set('username', username.trim())
    setRows(null)
    api(`/api/audit?${q}`).then(setRows).catch(e => setError(e.message))
  }, [action, username])

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Audit log</h1>
          <div className="muted">Who did what and when: logins, scans, triage decisions, exports and user changes.</div>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      <div className="card">
        <div className="report-filters">
          <select value={action} onChange={e => setAction(e.target.value)} aria-label="Filter by action">
            {ACTIONS.map(a => <option key={a} value={a}>{a || 'All actions'}</option>)}
          </select>
          <input className="filter-input" placeholder="Filter by user" value={username}
                 onChange={e => setUsername(e.target.value)} />
        </div>
        {!rows && !error && <div className="empty">Loading…</div>}
        {rows && rows.length === 0 && <div className="empty">No entries.</div>}
        {rows && rows.length > 0 && (
          <table className="list responsive">
            <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr></thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.id}>
                  <td data-label="Time" className="nowrap">{fmtTime(r.at)}</td>
                  <td data-label="User">{r.username}</td>
                  <td data-label="Action"><span className={`tag act-${r.action}`}>{r.action}</span></td>
                  <td data-label="Target">{r.target || '—'}</td>
                  <td data-label="Details" className="small">{detailText(r.detail)}</td>
                  <td data-label="IP" className="mono small">{r.ip || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}

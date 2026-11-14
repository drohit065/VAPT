import { useEffect, useState } from 'react'
import { Link, useNavigate, useOutletContext } from 'react-router-dom'
import { api } from '../api.js'
import { can } from '../components/Layout.jsx'
import { CountChips, SevBadge, fmtTime } from '../components/Severity.jsx'

export default function Projects() {
  const [items, setItems] = useState(null)
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const { user } = useOutletContext() || {}

  useEffect(() => {
    api('/api/projects').then(setItems).catch(e => setError(e.message))
  }, [])

  function open(p) {
    const s = p.latest_completed_scan || p.latest_scan
    if (!s) return
    navigate(s.status === 'completed' ? `/scans/${s.id}/report` : `/scans/${s.id}`)
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Projects</h1>
          <div className="muted">Every scanned repository or upload, with its latest results.</div>
        </div>
        {can(user, 'analyst') && <Link className="btn" to="/scans/new">New scan</Link>}
      </div>
      {error && <div className="error">{error}</div>}
      <div className="card" style={{ padding: 8 }}>
        {items === null && !error && <div className="empty">Loading…</div>}
        {items && items.length === 0 && (
          <div className="empty">
            No projects yet. <Link to="/scans/new">Start your first scan</Link>.
          </div>
        )}
        {items && items.length > 0 && (
          <table className="list responsive">
            <thead>
              <tr>
                <th>Project</th>
                <th>Last scan</th>
                <th>Findings</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {items.map(p => {
                const done = p.latest_completed_scan
                const last = p.latest_scan
                return (
                  <tr key={p.id} className="clickable" onClick={() => open(p)}>
                    <td data-label="Project" className="cell-main">
                      <div style={{ fontWeight: 600 }}>
                        {p.name}
                        {p.schedule && p.schedule !== 'none' && <span className="sched-badge">⟳ {p.schedule}</span>}
                      </div>
                      <div className="mono muted" style={{ wordBreak: 'break-all' }}>{p.source}</div>
                    </td>
                    <td data-label="Last scan">
                      {fmtTime(last?.created_at)}
                      {last && last.status !== 'completed' && (
                        <div className="small muted">{last.status}</div>
                      )}
                    </td>
                    <td data-label="Findings">
                      {done ? <CountChips counts={done.counts} /> : <span className="muted">—</span>}
                    </td>
                    <td data-label="Risk">
                      {done ? <SevBadge level={done.risk} /> : <span className="muted">—</span>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}

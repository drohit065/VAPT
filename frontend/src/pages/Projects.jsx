import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useOutletContext } from 'react-router-dom'
import { api } from '../api.js'
import { can } from '../components/Layout.jsx'
import { CountChips, SEVERITIES, SevBadge, fmtTime } from '../components/Severity.jsx'

const TYPES = { git: 'Git', zip: 'Zip', url: 'Website / API', image: 'Image' }
const RISK_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, None: 4 }

export default function Projects() {
  const [items, setItems] = useState(null)
  const [error, setError] = useState('')
  const [q, setQ] = useState('')
  const [type, setType] = useState('all')
  const [sort, setSort] = useState('recent')
  const navigate = useNavigate()
  const { user } = useOutletContext() || {}

  const load = () => api('/api/projects').then(setItems).catch(e => setError(e.message))
  useEffect(() => { load() }, [])

  function open(p) {
    const s = p.latest_completed_scan || p.latest_scan
    if (!s) return
    navigate(s.status === 'completed' ? `/scans/${s.id}/report` : `/scans/${s.id}`)
  }

  async function remove(e, p) {
    e.stopPropagation()
    if (!window.confirm(`Delete project "${p.name}" and all ${p.scan_count} scan(s) and findings? This cannot be undone.`)) return
    try { await api(`/api/projects/${p.id}`, { method: 'DELETE' }); load() } catch (err) { setError(err.message) }
  }

  const shown = useMemo(() => {
    const term = q.trim().toLowerCase()
    const list = (items || []).filter(p => (type === 'all' || p.source_type === type)
      && (!term || p.name.toLowerCase().includes(term) || p.source.toLowerCase().includes(term)))
    const open_ = p => SEVERITIES.reduce((n, s) => n + (p.latest_completed_scan?.counts?.[s] || 0), 0)
    if (sort === 'risk') {
      list.sort((a, b) => (RISK_ORDER[a.latest_completed_scan?.risk || 'None'] - RISK_ORDER[b.latest_completed_scan?.risk || 'None'])
        || open_(b) - open_(a))
    } else if (sort === 'name') {
      list.sort((a, b) => a.name.localeCompare(b.name))
    }
    return list
  }, [items, q, type, sort])

  const typeCounts = useMemo(() => (items || []).reduce((c, p) => ({ ...c, [p.source_type]: (c[p.source_type] || 0) + 1 }), {}), [items])

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Projects</h1>
          <div className="muted">Every scanned repository, upload, website and image, with its latest results.</div>
        </div>
        {can(user, 'analyst') && <Link className="btn" to="/scans/new">New scan</Link>}
      </div>
      {error && <div className="error">{error}</div>}

      {items && items.length > 0 && (
        <div className="toolbar">
          <input className="search" type="search" placeholder="Search projects…" value={q}
                 onChange={e => setQ(e.target.value)} aria-label="Search projects" />
          <div className="segmented">
            <button type="button" className={type === 'all' ? 'on' : ''} onClick={() => setType('all')}>All ({items.length})</button>
            {Object.entries(TYPES).filter(([k]) => typeCounts[k]).map(([k, l]) => (
              <button key={k} type="button" className={type === k ? 'on' : ''} onClick={() => setType(k)}>{l} ({typeCounts[k]})</button>
            ))}
          </div>
          <select value={sort} onChange={e => setSort(e.target.value)} aria-label="Sort">
            <option value="recent">Most recent</option>
            <option value="risk">Highest risk</option>
            <option value="name">Name</option>
          </select>
        </div>
      )}

      <div className="card" style={{ padding: 8 }}>
        {items === null && !error && <div className="empty">Loading…</div>}
        {items && items.length === 0 && (
          <div className="empty">
            No projects yet. {can(user, 'analyst') && <Link to="/scans/new">Start your first scan</Link>}
          </div>
        )}
        {items && items.length > 0 && shown.length === 0 && <div className="empty">No projects match.</div>}
        {shown.length > 0 && (
          <table className="list responsive">
            <thead>
              <tr>
                <th>Project</th>
                <th>Last scan</th>
                <th>Open findings</th>
                <th>Risk</th>
                {can(user, 'admin') && <th aria-label="Actions" />}
              </tr>
            </thead>
            <tbody>
              {shown.map(p => {
                const done = p.latest_completed_scan
                const last = p.latest_scan
                return (
                  <tr key={p.id} className="clickable" onClick={() => open(p)}>
                    <td data-label="Project" className="cell-main">
                      <div className="proj-name">
                        <span className={`type-badge t-${p.source_type}`}>{TYPES[p.source_type] || p.source_type}</span>
                        <strong>{p.name}</strong>
                        {p.schedule && p.schedule !== 'none' && <span className="sched-badge">⟳ {p.schedule}</span>}
                      </div>
                      <div className="mono muted small proj-source">{p.source.split('\n').join(' · ')}</div>
                    </td>
                    <td data-label="Last scan">
                      {fmtTime(last?.created_at)}
                      {last && last.status !== 'completed' && (
                        <div className={`small status-text st-${last.status}`}>{last.status}</div>
                      )}
                    </td>
                    <td data-label="Open findings">
                      {done ? <CountChips counts={done.counts} /> : <span className="muted">—</span>}
                    </td>
                    <td data-label="Risk">
                      {done ? <SevBadge level={done.risk} /> : <span className="muted">—</span>}
                    </td>
                    {can(user, 'admin') && (
                      <td data-label="">
                        <button type="button" className="linkbtn danger" onClick={e => remove(e, p)}
                                disabled={last?.status === 'running'} title="Delete project">Delete</button>
                      </td>
                    )}
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

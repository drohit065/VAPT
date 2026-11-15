import { useEffect, useState } from 'react'
import { Link, useNavigate, useOutletContext } from 'react-router-dom'
import { api } from '../api.js'
import { can } from '../components/Layout.jsx'
import { CountChips, SEVERITIES, SEV_COLORS, SevBadge, fmtTime } from '../components/Severity.jsx'
import { CategoryBars, CategoryTable, ChartCard, MiniBar, TrendChart, TrendTable } from '../components/Charts.jsx'

function Stat({ label, value, sub, tone, to }) {
  const body = (
    <>
      <div className="stat-label">{label}</div>
      <div className={`stat-value${tone ? ` tone-${tone}` : ''}`}>{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </>
  )
  return to ? <Link className="card stat" to={to}>{body}</Link> : <div className="card stat">{body}</div>
}

export default function Dashboard() {
  const [d, setD] = useState(null)
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const { user } = useOutletContext() || {}

  useEffect(() => { api('/api/dashboard').then(setD).catch(e => setError(e.message)) }, [])

  if (error) return <div className="error">{error}</div>
  if (!d) return <div className="muted">Loading…</div>

  const k = d.kpis
  const openTotal = SEVERITIES.reduce((n, s) => n + d.totals[s], 0)
  const maxTop = Math.max(1, ...d.top_projects.map(p => SEVERITIES.reduce((n, s) => n + p.counts[s], 0)))

  if (k.projects === 0) {
    return (
      <>
        <div className="page-head"><div><h1>Dashboard</h1></div></div>
        <div className="card empty-hero">
          <h2>No scans yet</h2>
          <p className="muted">Scan a Git repository, a zip, a live website or API, or a container image to see your security posture here.</p>
          {can(user, 'analyst') && <Link className="btn" to="/scans/new">Start your first scan</Link>}
        </div>
      </>
    )
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Dashboard</h1>
          <div className="muted">Open findings across the latest completed scan of every project (triaged findings excluded).</div>
        </div>
        {can(user, 'analyst') && <Link className="btn" to="/scans/new">New scan</Link>}
      </div>

      <div className="stats">
        <Stat label="Open findings" value={openTotal}
              sub={<span className="sev-inline">{SEVERITIES.map(s => (
                <span key={s}><i style={{ background: SEV_COLORS[s].bg }} />{d.totals[s]} {s}</span>))}</span>} />
        <Stat label="Critical + High" value={d.totals.Critical + d.totals.High}
              tone={d.totals.Critical ? 'crit' : d.totals.High ? 'high' : 'ok'} sub="fix these first" />
        <Stat label="Fixed in 30 days" value={k.fixed_30d} tone="ok" sub={`${k.new_30d} new in 30 days`} />
        <Stat label="Projects" value={k.projects} to="/projects"
              sub={`${k.scans_30d} scan(s) in 30 days${k.scheduled ? ` · ${k.scheduled} scheduled` : ''}`} />
      </div>
      {(k.active_scans > 0 || k.failed_30d > 0) && (
        <div className="info small">
          {k.active_scans > 0 && <>{k.active_scans} scan(s) queued or running. </>}
          {k.failed_30d > 0 && <>{k.failed_30d} scan(s) failed in the last 30 days.</>}
        </div>
      )}

      <div className="dash-grid">
        <ChartCard title="Open findings over time" subtitle="Per week, latest completed scan of each project"
                   table={<TrendTable data={d.trend} />}>
          <TrendChart data={d.trend} />
        </ChartCard>
        <ChartCard title="Open findings by category" subtitle="Which kind of check found them"
                   table={d.categories.length ? <CategoryTable rows={d.categories} /> : null}>
          {d.categories.length ? <CategoryBars rows={d.categories} />
            : <div className="empty">No open findings.</div>}
        </ChartCard>
      </div>

      <div className="dash-grid">
        <div className="card" style={{ padding: 8 }}>
          <h2 style={{ padding: '8px 8px 0' }}>Riskiest projects</h2>
          {d.top_projects.length === 0 && <div className="empty">No open findings in any project.</div>}
          {d.top_projects.length > 0 && (
            <table className="list responsive">
              <thead><tr><th>Project</th><th>Open findings</th><th>Risk</th></tr></thead>
              <tbody>
                {d.top_projects.map(p => (
                  <tr key={p.id} className="clickable" onClick={() => navigate(`/scans/${p.scan_id}/report`)}>
                    <td data-label="Project" className="cell-main">
                      <div style={{ fontWeight: 600 }}>{p.name}</div>
                      <div className="small muted">{p.source_type} · {p.new} new · {p.fixed} fixed</div>
                    </td>
                    <td data-label="Open findings" style={{ minWidth: 160 }}>
                      <MiniBar counts={p.counts} max={maxTop} />
                      <div className="small muted" style={{ marginTop: 4 }}><CountChips counts={p.counts} /></div>
                    </td>
                    <td data-label="Risk"><SevBadge level={p.risk} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card" style={{ padding: 8 }}>
          <h2 style={{ padding: '8px 8px 0' }}>Recent scans</h2>
          <ul className="activity">
            {d.recent.map(s => (
              <li key={s.id}>
                <Link to={s.status === 'completed' ? `/scans/${s.id}/report` : `/scans/${s.id}`}>
                  <span className={`dot st-${s.status}`} aria-hidden />
                  <span className="act-main">
                    <span className="act-title">{s.project}</span>
                    <span className="small muted">#{s.id} · {s.status} · {fmtTime(s.finished_at || s.created_at)}</span>
                  </span>
                  {s.status === 'completed' && <CountChips counts={s.counts} />}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </>
  )
}

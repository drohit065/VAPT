import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import { CountChips, fmtTime } from '../components/Severity.jsx'

const ICON = { pending: '○', running: '◐', done: '✓', failed: '✕', skipped: '–' }

function duration(s) {
  if (!s.started_at) return ''
  const end = s.finished_at ? new Date(s.finished_at) : new Date()
  const secs = Math.max(0, Math.round((end - new Date(s.started_at)) / 1000))
  return secs >= 60 ? `${Math.floor(secs / 60)}m ${secs % 60}s` : `${secs}s`
}

export default function ScanProgress() {
  const { id } = useParams()
  const [scan, setScan] = useState(null)
  const [error, setError] = useState('')
  const timer = useRef(null)

  useEffect(() => {
    let alive = true
    async function poll() {
      try {
        const s = await api(`/api/scans/${id}`)
        if (!alive) return
        setScan(s)
        if (s.status === 'queued' || s.status === 'running') timer.current = setTimeout(poll, 1500)
      } catch (e) {
        if (alive) setError(e.message)
      }
    }
    poll()
    return () => { alive = false; clearTimeout(timer.current) }
  }, [id])

  if (error) return <div className="error">{error}</div>
  if (!scan) return <div className="muted">Loading…</div>

  const active = scan.status === 'queued' || scan.status === 'running'
  return (
    <>
      <div className="page-head">
        <div>
          <h1>{scan.project.name}</h1>
          <div className="mono muted" style={{ wordBreak: 'break-all' }}>{scan.project.source}</div>
        </div>
        <span className={`status status-${scan.status}`}>{scan.status}</span>
      </div>

      <div className="card">
        <h2>Scan progress</h2>
        {scan.status === 'queued' && <div className="info">Waiting for the worker to pick up this scan…</div>}
        <ol className="steps">
          {scan.steps.map(s => (
            <li key={s.key} className={`step step-${s.status}`}>
              <span className="step-icon" aria-hidden>{ICON[s.status]}</span>
              <div className="step-body">
                <div className="step-label">{s.label}</div>
                {s.detail && <div className="step-detail">{s.detail}</div>}
              </div>
              <span className="step-time">{s.status === 'running' ? 'running…' : duration(s)}</span>
            </li>
          ))}
        </ol>
        {scan.notes?.length > 0 && (
          <div className="info" style={{ marginTop: 14, marginBottom: 0 }}>
            {scan.notes.map((n, i) => <div key={i}>{n}</div>)}
          </div>
        )}
      </div>

      {scan.status === 'failed' && (
        <div className="card">
          <div className="error" style={{ marginBottom: 12 }}>Scan failed: {scan.error}</div>
          <Link className="btn secondary" to="/scans/new">Start another scan</Link>
        </div>
      )}

      {scan.status === 'completed' && (
        <div className="card done-card">
          <div>
            <div className="small muted">Finished {fmtTime(scan.finished_at)}</div>
            <div style={{ marginTop: 6 }}><CountChips counts={scan.counts} /></div>
          </div>
          <Link className="btn" to={`/scans/${scan.id}/report`}>View report</Link>
        </div>
      )}
      {active && <p className="muted small">This page updates automatically. You can leave it; the scan keeps running.</p>}
    </>
  )
}

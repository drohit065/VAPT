import { useEffect, useMemo, useState } from 'react'
import { Link, useOutletContext, useParams } from 'react-router-dom'
import { api } from '../api.js'
import { can } from '../components/Layout.jsx'
import { CountChips, SEVERITIES, SevBadge, SeverityBar, fmtTime } from '../components/Severity.jsx'

const CHECK_LABELS = {
  code: 'Code flaws',
  deps: 'Dependencies',
  secrets: 'Secrets',
  iac: 'Docker / Terraform',
  web: 'Web checks',
  nuclei: 'Nuclei',
  authz: 'Access control',
  zap: 'OWASP ZAP',
  tls: 'TLS',
  ports: 'Open ports',
}
const STATUS_LABELS = {
  open: 'Open',
  false_positive: 'False positive',
  accepted_risk: 'Accepted risk',
  fixed: 'Fixed',
}
const SUPPRESSED = ['false_positive', 'accepted_risk', 'fixed']
const VIEWS = [
  { key: 'open', label: 'Open' },
  { key: 'new', label: 'New' },
  { key: 'suppressed', label: 'Triaged' },
  { key: 'all', label: 'All' },
]

async function download(path, fallbackName) {
  const res = await api(path, { raw: true })
  const blob = await res.blob()
  const cd = res.headers.get('Content-Disposition') || ''
  const name = (cd.match(/filename="([^"]+)"/) || [])[1] || fallbackName
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = name
  document.body.appendChild(a); a.click(); a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function StatusEditor({ f, onSaved }) {
  const [status, setStatus] = useState(f.status || 'open')
  const [note, setNote] = useState(f.status_note || '')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const dirty = status !== (f.status || 'open') || note !== (f.status_note || '')

  async function save() {
    setBusy(true); setErr('')
    try {
      const res = await api(`/api/findings/${f.id}`, { method: 'PATCH', body: { status, note } })
      onSaved(res)
    } catch (e) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="triage">
      <h3>Triage</h3>
      <div className="triage-row">
        <select value={status} onChange={e => setStatus(e.target.value)} aria-label="Finding status">
          {Object.entries(STATUS_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <input type="text" placeholder="Reason / note (optional)" maxLength={2000}
               value={note} onChange={e => setNote(e.target.value)} />
        <button type="button" className="btn small-btn" onClick={save} disabled={busy || !dirty}>
          {busy ? 'Saving…' : 'Save'}
        </button>
      </div>
      {err && <div className="error small" style={{ marginTop: 8 }}>{err}</div>}
      <div className="small muted" style={{ marginTop: 6 }}>
        False positive and Accepted risk carry over to future scans of this project.
        {f.status_updated_at && <> Last changed {fmtTime(f.status_updated_at)}.</>}
      </div>
    </section>
  )
}

function Finding({ f, open, onToggle, onSaved, canEdit }) {
  const triaged = f.status && f.status !== 'open'
  return (
    <div className={`finding${open ? ' open' : ''}${triaged ? ' triaged' : ''}`}>
      <button type="button" className="finding-head" onClick={onToggle} aria-expanded={open}>
        <SevBadge level={f.severity} />
        {f.cvss_score != null && (
          <span className={`cvss${f.cvss_source === 'estimated' ? ' est' : ''}`}
                title={f.cvss_source === 'estimated' ? 'Estimated from severity' : (f.cvss_vector || 'CVSS v3')}>
            {f.cvss_score.toFixed(1)}
          </span>
        )}
        <span className="finding-title">
          {f.title}
          {f.is_new && <span className="badge-new">New</span>}
          {triaged && <span className={`badge-status st-${f.status}`}>{STATUS_LABELS[f.status]}</span>}
        </span>
        <span className="finding-loc mono">
          {f.file_path}{f.line ? `:${f.line}` : ''}
        </span>
      </button>
      {open && (
        <div className="finding-body">
          <div className="finding-meta small">
            <span className="tag">{CHECK_LABELS[f.check] || f.check}</span>
            {f.scanners?.map(s => <span key={s} className="tag">{s}</span>)}
            {f.cwe && <span className="tag">{f.cwe}</span>}
            {f.owasp && <span className="tag">{f.owasp}</span>}
            {f.cvss_score != null && (
              <span className="tag">
                CVSS {f.cvss_score.toFixed(1)}{f.cvss_source === 'estimated' ? ' (estimated)' : ''}
              </span>
            )}
          </div>
          {f.cvss_vector && <div className="small muted mono" style={{ marginTop: 6 }}>{f.cvss_vector}</div>}
          {f.snippet && <pre className="snippet">{f.snippet}</pre>}
          {f.description && (
            <section>
              <h3>What is wrong</h3>
              <p className="pre-wrap">{f.description}</p>
            </section>
          )}
          {f.exploitation && (
            <section>
              <h3>How it could be exploited</h3>
              <p className="pre-wrap">{f.exploitation}</p>
            </section>
          )}
          {f.recommendation && (
            <section>
              <h3>Recommended fix</h3>
              <p className="pre-wrap">{f.recommendation}</p>
            </section>
          )}
          {f.rule_id && <div className="small muted mono" style={{ marginTop: 10 }}>Rule: {f.rule_id}</div>}
          {canEdit
            ? <StatusEditor key={`${f.id}-${f.status}-${f.status_note}`} f={f} onSaved={onSaved} />
            : f.status_note && <section><h3>Triage note</h3><p className="pre-wrap">{f.status_note}</p></section>}
        </div>
      )}
    </div>
  )
}

function DiffCard({ diff }) {
  const [showFixed, setShowFixed] = useState(false)
  if (!diff?.previous_scan_id) {
    return <div className="card small muted">First completed scan of this project: every finding is marked New.</div>
  }
  return (
    <div className="card diff-card">
      <div className="diff-head">
        <span>Since <Link to={`/scans/${diff.previous_scan_id}/report`}>scan #{diff.previous_scan_id}</Link>:</span>
        <span className="diff-num new">{diff.new} new</span>
        <span className="diff-num fixed">{diff.fixed} fixed</span>
        <span className="diff-num">{diff.recurring} still present</span>
        {diff.fixed > 0 && (
          <button type="button" className="linkbtn" onClick={() => setShowFixed(s => !s)}>
            {showFixed ? 'Hide fixed' : 'Show fixed'}
          </button>
        )}
      </div>
      {showFixed && (
        <ul className="fixed-list">
          {diff.fixed_items.map((it, i) => (
            <li key={i}>
              <SevBadge level={it.severity} /> <span>{it.title}</span>
              <span className="mono muted small"> {it.file_path}{it.line ? `:${it.line}` : ''}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export default function ScanReport() {
  const { id } = useParams()
  const { user } = useOutletContext() || {}
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState(null)
  const [error, setError] = useState('')
  const [sev, setSev] = useState('all')
  const [check, setCheck] = useState('all')
  const [view, setView] = useState('open')
  const [open, setOpen] = useState({})
  const [history, setHistory] = useState([])
  const [busy, setBusy] = useState('')
  const [dlError, setDlError] = useState('')

  useEffect(() => {
    setScan(null); setFindings(null); setOpen({}); setSev('all'); setCheck('all'); setView('open')
    Promise.all([api(`/api/scans/${id}`), api(`/api/scans/${id}/findings`)])
      .then(([s, f]) => {
        setScan(s); setFindings(f)
        return api(`/api/projects/${s.project.id}`).then(p => setHistory(p.scans || []))
      })
      .catch(e => setError(e.message))
  }, [id])

  async function exportAs(kind) {
    setBusy(kind); setDlError('')
    try {
      const path = kind === 'pdf' ? `/api/scans/${id}/report.pdf` : `/api/scans/${id}/export.${kind}`
      await download(path, `vapt-scan${id}.${kind}`)
    } catch (e) {
      setDlError(e.message)
    } finally {
      setBusy('')
    }
  }

  function onSaved(updated) {
    setFindings(fs => fs.map(x => (x.id === updated.id ? { ...x, ...updated } : x)))
    if (updated.scan_counts) setScan(s => ({ ...s, counts: updated.scan_counts }))
  }

  const inView = useMemo(() => (findings || []).filter(f => {
    const st = f.status || 'open'
    if (view === 'open') return !SUPPRESSED.includes(st)
    if (view === 'new') return f.is_new && !SUPPRESSED.includes(st)
    if (view === 'suppressed') return SUPPRESSED.includes(st)
    return true
  }), [findings, view])

  const viewCounts = useMemo(() => {
    const c = {}
    inView.forEach(f => { c[f.severity] = (c[f.severity] || 0) + 1 })
    return c
  }, [inView])

  const checksPresent = useMemo(() => [...new Set((findings || []).map(f => f.check))], [findings])
  const shown = useMemo(
    () => inView.filter(f => (sev === 'all' || f.severity === sev) && (check === 'all' || f.check === check)),
    [inView, sev, check]
  )

  if (error) return <div className="error">{error}</div>
  if (!scan || !findings) return <div className="muted">Loading…</div>

  const allOpen = shown.length > 0 && shown.every(f => open[f.id])
  function toggleAll() {
    const next = { ...open }
    shown.forEach(f => { next[f.id] = !allOpen })
    setOpen(next)
  }
  const triagedCount = findings.filter(f => SUPPRESSED.includes(f.status)).length
  const newCount = findings.filter(f => f.is_new && !SUPPRESSED.includes(f.status)).length
  const viewTotals = { open: findings.length - triagedCount, new: newCount, suppressed: triagedCount, all: findings.length }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{scan.project.name}</h1>
          <div className="mono muted" style={{ wordBreak: 'break-all' }}>{scan.project.source}</div>
          <div className="small muted" style={{ marginTop: 4 }}>
            Scan #{scan.id} · finished {fmtTime(scan.finished_at)}
            {scan.branch && <> · {scan.branch}</>}
            {scan.commit_sha && <> @ <span className="mono">{scan.commit_sha.slice(0, 12)}</span></>}
          </div>
        </div>
        <div className="head-actions">
          <Link className="btn secondary" to={`/scans/${scan.id}`}>Scan details</Link>
          {scan.status === 'completed' && (
            <>
              <button type="button" className="btn secondary" onClick={() => exportAs('csv')} disabled={!!busy}>
                {busy === 'csv' ? 'Exporting…' : 'CSV'}
              </button>
              <button type="button" className="btn secondary" onClick={() => exportAs('sarif')} disabled={!!busy}
                      title="SARIF 2.1.0 for GitHub code scanning, Azure DevOps, IDEs">
                {busy === 'sarif' ? 'Exporting…' : 'SARIF'}
              </button>
              <button type="button" className="btn" onClick={() => exportAs('pdf')} disabled={!!busy}>
                {busy === 'pdf' ? 'Preparing PDF…' : 'Download PDF'}
              </button>
            </>
          )}
        </div>
      </div>
      {dlError && <div className="error">Download failed: {dlError}</div>}
      {scan.status !== 'completed' && (
        <div className="info">This scan is {scan.status}. <Link to={`/scans/${scan.id}`}>See progress</Link>.</div>
      )}

      <div className="card">
        <SeverityBar counts={scan.counts || {}} />
        {triagedCount > 0 && (
          <div className="small muted" style={{ marginTop: 6 }}>
            Counts exclude {triagedCount} triaged finding(s) (false positive, accepted risk or fixed).
          </div>
        )}
      </div>

      <DiffCard diff={scan.diff} />

      <div className="card report-summary">
        <div>
          <div className="small muted">Overall risk</div>
          <SevBadge level={scan.risk || 'None'} />
        </div>
        <div>
          <div className="small muted">Scan time</div>
          <div>{fmtTime(scan.started_at || scan.created_at)}</div>
        </div>
        <div>
          <div className="small muted">Branch / commit</div>
          <div>
            {scan.branch || '—'}
            {scan.commit_sha && <> @ <span className="mono">{scan.commit_sha.slice(0, 12)}</span></>}
          </div>
        </div>
        {scan.languages?.length > 0 && (
          <div>
            <div className="small muted">Languages</div>
            <div>{scan.languages.map(l => l.name).join(', ')}</div>
          </div>
        )}
        {scan.frameworks?.length > 0 && (
          <div>
            <div className="small muted">{scan.project.source_type === 'url' ? 'Technologies' : 'Frameworks'}</div>
            <div>{scan.frameworks.join(', ')}</div>
          </div>
        )}
      </div>

      {scan.notes?.length > 0 && (
        <div className="info">{scan.notes.map((n, i) => <div key={i}>{n}</div>)}</div>
      )}

      <div className="card">
        <div className="report-filters">
          <div className="segmented">
            {VIEWS.map(v => (
              <button key={v.key} type="button" className={view === v.key ? 'on' : ''}
                      onClick={() => { setView(v.key); setSev('all') }}>
                {v.label} ({viewTotals[v.key]})
              </button>
            ))}
          </div>
        </div>
        <div className="report-filters">
          <div className="segmented">
            {['all', ...SEVERITIES].map(s => (
              <button key={s} type="button" className={sev === s ? 'on' : ''} onClick={() => setSev(s)}>
                {s === 'all' ? 'All severities' : `${s} (${viewCounts[s] || 0})`}
              </button>
            ))}
          </div>
          {checksPresent.length > 1 && (
            <select value={check} onChange={e => setCheck(e.target.value)} aria-label="Filter by check">
              <option value="all">All checks</option>
              {checksPresent.map(c => <option key={c} value={c}>{CHECK_LABELS[c] || c}</option>)}
            </select>
          )}
          {shown.length > 0 && (
            <button type="button" className="linkbtn" onClick={toggleAll}>
              {allOpen ? 'Collapse all' : 'Expand all'}
            </button>
          )}
        </div>

        {findings.length === 0 && <div className="empty">No findings. 🎉</div>}
        {findings.length > 0 && shown.length === 0 && <div className="empty">No findings match this filter.</div>}
        {shown.map(f => (
          <Finding key={f.id} f={f} open={!!open[f.id]} onSaved={onSaved} canEdit={can(user, 'analyst')}
                   onToggle={() => setOpen(o => ({ ...o, [f.id]: !o[f.id] }))} />
        ))}
      </div>

      {history.length > 0 && (
        <div className="card" style={{ padding: 8 }}>
          <h2 style={{ padding: '8px 8px 0' }}>Scan history</h2>
          <table className="list responsive">
            <thead>
              <tr><th>Scan</th><th>Date</th><th>Branch</th><th>Status</th><th>Open findings</th></tr>
            </thead>
            <tbody>
              {history.map(h => {
                const to = h.status === 'completed' ? `/scans/${h.id}/report` : `/scans/${h.id}`
                return (
                  <tr key={h.id} className={h.id === scan.id ? 'current' : ''}>
                    <td data-label="Scan">
                      {h.id === scan.id ? <strong>#{h.id} (this report)</strong> : <Link to={to}>#{h.id}</Link>}
                    </td>
                    <td data-label="Date">{fmtTime(h.created_at)}</td>
                    <td data-label="Branch">
                      {h.branch || '—'}
                      {h.commit_sha && <span className="mono muted"> @{h.commit_sha.slice(0, 7)}</span>}
                    </td>
                    <td data-label="Status">{h.status}</td>
                    <td data-label="Open findings">
                      {h.status === 'completed' ? <CountChips counts={h.counts} /> : <span className="muted">—</span>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

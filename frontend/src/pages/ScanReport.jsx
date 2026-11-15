import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useOutletContext, useParams } from 'react-router-dom'
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
  image: 'Container image',
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

const PROVIDER_LABEL = { jira: 'Jira issue', github: 'GitHub issue' }

function TicketButton({ f, provider, canEdit, onSaved }) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  if (f.ticket_url) {
    return <a className="ticket-link" href={f.ticket_url} target="_blank" rel="noopener noreferrer">↗ {f.ticket_key}</a>
  }
  if (!canEdit || !provider || provider === 'none') return null
  async function create() {
    setBusy(true); setErr('')
    try { onSaved(await api(`/api/findings/${f.id}/ticket`, { method: 'POST' })) }
    catch (e) { setErr(e.message) } finally { setBusy(false) }
  }
  return (
    <span>
      <button type="button" className="btn secondary small-btn" onClick={create} disabled={busy}>
        {busy ? 'Creating…' : `Create ${PROVIDER_LABEL[provider]}`}
      </button>
      {err && <span className="error small inline-error">{err}</span>}
    </span>
  )
}

function Finding({ f, open, onToggle, onSaved, canEdit, provider }) {
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
          <div style={{ marginTop: 10 }}>
            <TicketButton f={f} provider={provider} canEdit={canEdit} onSaved={onSaved} />
          </div>
          {canEdit
            ? <StatusEditor key={`${f.id}-${f.status}-${f.status_note}`} f={f} onSaved={onSaved} />
            : f.status_note && <section><h3>Triage note</h3><p className="pre-wrap">{f.status_note}</p></section>}
        </div>
      )}
    </div>
  )
}

function ScheduleCard({ project, canEdit, onSaved }) {
  const [schedule, setSchedule] = useState(project.schedule || 'none')
  const [hour, setHour] = useState(project.schedule_hour ?? 2)
  const [showCreds, setShowCreds] = useState(false)
  const [creds, setCreds] = useState({ git_token: '', auth_a: '', auth_b: '', registry_user: '', registry_password: '' })
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const credsEntered = Object.values(creds).some(v => v.trim())
  const dirty = schedule !== (project.schedule || 'none') || Number(hour) !== (project.schedule_hour ?? 2) || credsEntered

  if (project.source_type === 'zip') return null
  const type = project.source_type
  const setC = (k, v) => setCreds({ ...creds, [k]: v })

  async function save(extra = {}) {
    setBusy(true); setErr(''); setMsg('')
    try {
      const p = await api(`/api/projects/${project.id}/schedule`, {
        method: 'PUT', body: { schedule, hour_utc: Number(hour), ...creds, ...extra },
      })
      onSaved({ ...project, ...p })
      setCreds({ git_token: '', auth_a: '', auth_b: '', registry_user: '', registry_password: '' })
      setShowCreds(false)
      setMsg('Schedule saved.')
    } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  const credLabel = { git: 'access token', url: 'login headers', image: 'registry login' }[type]

  return (
    <div className="card schedule-card">
      <div className="schedule-row">
        <strong>Scheduled re-scan</strong>
        {canEdit ? (
          <>
            <select value={schedule} onChange={e => setSchedule(e.target.value)} aria-label="Schedule">
              <option value="none">Off</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
            </select>
            {schedule !== 'none' && (
              <label className="small">at{' '}
                <select value={hour} onChange={e => setHour(e.target.value)} aria-label="Hour (UTC)">
                  {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{String(h).padStart(2, '0')}:00</option>)}
                </select>{' '}UTC
              </label>
            )}
            <button type="button" className="btn small-btn" onClick={() => save()} disabled={busy || !dirty}>
              {busy ? 'Saving…' : 'Save'}
            </button>
          </>
        ) : (
          <span>{project.schedule === 'none' ? 'Off' : `${project.schedule} at ${String(project.schedule_hour).padStart(2, '0')}:00 UTC`}</span>
        )}
        {project.next_run_at && project.schedule !== 'none' && (
          <span className="small muted">Next run: {fmtTime(project.next_run_at)}</span>
        )}
        {project.schedule !== 'none' && (
          <span className={`pill ${project.schedule_has_credentials ? 'ok' : ''}`}>
            {project.schedule_has_credentials ? `${credLabel} saved` : `no ${credLabel}`}
          </span>
        )}
      </div>
      {err && <div className="error small" style={{ marginTop: 8 }}>{err}</div>}
      {msg && <div className="small" style={{ marginTop: 8, color: 'var(--ok)' }}>{msg}</div>}

      {canEdit && schedule !== 'none' && (
        <div style={{ marginTop: 10 }}>
          <button type="button" className="linkbtn auth-toggle" onClick={() => setShowCreds(s => !s)}>
            {showCreds ? '▾' : '▸'} {project.schedule_has_credentials ? `Replace or remove the saved ${credLabel}` : `Save ${credLabel} for scheduled runs (optional)`}
          </button>
          {showCreds && (
            <div className="creds-box">
              {type === 'git' && (
                <div className="field"><label htmlFor="sgt">Read-only access token</label>
                  <input id="sgt" type="password" autoComplete="off" value={creds.git_token} onChange={e => setC('git_token', e.target.value)} /></div>
              )}
              {type === 'url' && (
                <div className="grid2">
                  <div className="field"><label htmlFor="sa">User A headers</label>
                    <textarea id="sa" className="mono" rows={2} spellCheck={false} placeholder="Authorization: Bearer …"
                              value={creds.auth_a} onChange={e => setC('auth_a', e.target.value)} /></div>
                  <div className="field"><label htmlFor="sb">User B headers <span className="muted small">(optional)</span></label>
                    <textarea id="sb" className="mono" rows={2} spellCheck={false} placeholder="Authorization: Bearer …"
                              value={creds.auth_b} onChange={e => setC('auth_b', e.target.value)} /></div>
                </div>
              )}
              {type === 'image' && (
                <div className="grid2">
                  <div className="field"><label htmlFor="sru">Registry username</label>
                    <input id="sru" autoComplete="off" value={creds.registry_user} onChange={e => setC('registry_user', e.target.value)} /></div>
                  <div className="field"><label htmlFor="srp">Registry password / token</label>
                    <input id="srp" type="password" autoComplete="off" value={creds.registry_password} onChange={e => setC('registry_password', e.target.value)} /></div>
                </div>
              )}
              <p className="small muted" style={{ margin: '4px 0 0' }}>
                Stored encrypted and used only by scheduled runs; never shown again. Use read-only test credentials that you can rotate.
                {project.schedule_has_credentials && (
                  <> <button type="button" className="linkbtn danger" disabled={busy}
                             onClick={() => save({ clear_credentials: true })}>Remove saved {credLabel}</button></>
                )}
              </p>
            </div>
          )}
        </div>
      )}
      {!project.schedule_has_credentials && project.schedule !== 'none' && (
        <div className="small muted" style={{ marginTop: 6 }}>
          Scheduled runs repeat this project's latest scan settings without credentials unless you save them here.
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
  const navigate = useNavigate()
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState(null)
  const [error, setError] = useState('')
  const [sev, setSev] = useState('all')
  const [check, setCheck] = useState('all')
  const [view, setView] = useState('open')
  const [open, setOpen] = useState({})
  const [history, setHistory] = useState([])
  const [project, setProject] = useState(null)
  const [busy, setBusy] = useState('')
  const [dlError, setDlError] = useState('')
  const [provider, setProvider] = useState('none')
  const [bulkMsg, setBulkMsg] = useState('')
  useEffect(() => { api('/api/meta').then(m => setProvider(m.ticketing || 'none')).catch(() => {}) }, [])

  useEffect(() => {
    setScan(null); setFindings(null); setOpen({}); setSev('all'); setCheck('all'); setView('open')
    Promise.all([api(`/api/scans/${id}`), api(`/api/scans/${id}/findings`)])
      .then(([s, f]) => {
        setScan(s); setFindings(f)
        return api(`/api/projects/${s.project.id}`).then(p => { setHistory(p.scans || []); setProject(p) })
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

  async function deleteScan(h) {
    if (!window.confirm(`Delete scan #${h.id} and its findings? This cannot be undone.`)) return
    try {
      await api(`/api/scans/${h.id}`, { method: 'DELETE' })
      if (h.id === scan.id) {
        const rest = history.filter(x => x.id !== h.id && x.status === 'completed')
        navigate(rest.length ? `/scans/${rest[0].id}/report` : '/projects')
      } else {
        setHistory(hs => hs.filter(x => x.id !== h.id))
      }
    } catch (e) { setDlError(e.message) }
  }

  async function bulkTickets() {
    setBusy('tickets'); setBulkMsg(''); setDlError('')
    try {
      const r = await api(`/api/scans/${id}/tickets`, { method: 'POST', body: { min_severity: 'High' } })
      setFindings(await api(`/api/scans/${id}/findings`))
      setBulkMsg(r.errors.length ? `Created ${r.created.length} ticket(s); stopped: ${r.errors[0]}`
        : r.created.length ? `Created ${r.created.length} ticket(s): ${r.created.join(', ')}` : 'Every open Critical/High finding already has a ticket.')
    } catch (e) { setDlError(e.message) } finally { setBusy('') }
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
              {can(user, 'analyst') && provider !== 'none' && (
                <button type="button" className="btn secondary" onClick={bulkTickets} disabled={!!busy}
                        title="Create a ticket for every open Critical and High finding that has none yet">
                  {busy === 'tickets' ? 'Creating tickets…' : 'Tickets for Critical/High'}
                </button>
              )}
            </>
          )}
        </div>
      </div>
      {dlError && <div className="error">Download failed: {dlError}</div>}
      {bulkMsg && <div className="info">{bulkMsg}</div>}
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
      {project && <ScheduleCard project={project} canEdit={can(user, 'analyst')} onSaved={setProject} />}

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
          <Finding key={f.id} f={f} open={!!open[f.id]} onSaved={onSaved} canEdit={can(user, 'analyst')} provider={provider}
                   onToggle={() => setOpen(o => ({ ...o, [f.id]: !o[f.id] }))} />
        ))}
      </div>

      {history.length > 0 && (
        <div className="card" style={{ padding: 8 }}>
          <h2 style={{ padding: '8px 8px 0' }}>Scan history</h2>
          <table className="list responsive">
            <thead>
              <tr><th>Scan</th><th>Date</th><th>Branch</th><th>Status</th><th>Open findings</th>{can(user, 'admin') && <th aria-label="Actions" />}</tr>
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
                    {can(user, 'admin') && (
                      <td data-label="">
                        {h.status !== 'running' && (
                          <button type="button" className="linkbtn danger" onClick={() => deleteScan(h)}>Delete</button>
                        )}
                      </td>
                    )}
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

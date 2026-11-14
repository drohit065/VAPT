import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import { CountChips, SEVERITIES, SevBadge, SeverityBar, fmtTime } from '../components/Severity.jsx'

const CHECK_LABELS = {
  code: 'Code flaws',
  deps: 'Dependencies',
  secrets: 'Secrets',
  iac: 'Docker / Terraform',
  web: 'Web checks',
  nuclei: 'Nuclei',
}

function Finding({ f, open, onToggle }) {
  return (
    <div className={`finding${open ? ' open' : ''}`}>
      <button type="button" className="finding-head" onClick={onToggle} aria-expanded={open}>
        <SevBadge level={f.severity} />
        <span className="finding-title">{f.title}</span>
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
          </div>
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
          {f.rule_id && <div className="small muted mono">Rule: {f.rule_id}</div>}
        </div>
      )}
    </div>
  )
}

export default function ScanReport() {
  const { id } = useParams()
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState(null)
  const [error, setError] = useState('')
  const [sev, setSev] = useState('all')
  const [check, setCheck] = useState('all')
  const [open, setOpen] = useState({})
  const [history, setHistory] = useState([])
  const [pdfBusy, setPdfBusy] = useState(false)
  const [pdfError, setPdfError] = useState('')

  useEffect(() => {
    setScan(null); setFindings(null); setOpen({}); setSev('all'); setCheck('all')
    Promise.all([api(`/api/scans/${id}`), api(`/api/scans/${id}/findings`)])
      .then(([s, f]) => {
        setScan(s); setFindings(f)
        return api(`/api/projects/${s.project.id}`).then(p => setHistory(p.scans || []))
      })
      .catch(e => setError(e.message))
  }, [id])

  async function downloadPdf() {
    setPdfBusy(true); setPdfError('')
    try {
      const res = await api(`/api/scans/${id}/report.pdf`, { raw: true })
      const blob = await res.blob()
      const cd = res.headers.get('Content-Disposition') || ''
      const name = (cd.match(/filename="([^"]+)"/) || [])[1] || `vapt-report-scan${id}.pdf`
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = name
      document.body.appendChild(a); a.click(); a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (e) {
      setPdfError(e.message)
    } finally {
      setPdfBusy(false)
    }
  }

  const checksPresent = useMemo(
    () => [...new Set((findings || []).map(f => f.check))],
    [findings]
  )
  const shown = useMemo(
    () => (findings || []).filter(f =>
      (sev === 'all' || f.severity === sev) && (check === 'all' || f.check === check)),
    [findings, sev, check]
  )

  if (error) return <div className="error">{error}</div>
  if (!scan || !findings) return <div className="muted">Loading…</div>

  const allOpen = shown.length > 0 && shown.every(f => open[f.id])
  function toggleAll() {
    const next = { ...open }
    shown.forEach(f => { next[f.id] = !allOpen })
    setOpen(next)
  }

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
            <button type="button" className="btn" onClick={downloadPdf} disabled={pdfBusy}>
              {pdfBusy ? 'Preparing PDF…' : 'Download PDF'}
            </button>
          )}
        </div>
      </div>
      {pdfError && <div className="error">PDF download failed: {pdfError}</div>}
      {scan.status !== 'completed' && (
        <div className="info">This scan is {scan.status}. <Link to={`/scans/${scan.id}`}>See progress</Link>.</div>
      )}

      <div className="card">
        <SeverityBar counts={scan.counts || {}} />
      </div>

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
            <div className="small muted">Frameworks</div>
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
            {['all', ...SEVERITIES].map(s => (
              <button key={s} type="button" className={sev === s ? 'on' : ''} onClick={() => setSev(s)}>
                {s === 'all' ? 'All' : s}
                {s !== 'all' && ` (${scan.counts?.[s] || 0})`}
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
          <Finding key={f.id} f={f} open={!!open[f.id]}
                   onToggle={() => setOpen(o => ({ ...o, [f.id]: !o[f.id] }))} />
        ))}
      </div>

      {history.length > 0 && (
        <div className="card" style={{ padding: 8 }}>
          <h2 style={{ padding: '8px 8px 0' }}>Scan history</h2>
          <table className="list responsive">
            <thead>
              <tr><th>Scan</th><th>Date</th><th>Branch</th><th>Status</th><th>Findings</th></tr>
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
                    <td data-label="Findings">
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

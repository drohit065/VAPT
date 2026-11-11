import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api.js'

export default function NewScan() {
  const [meta, setMeta] = useState(null)
  const [mode, setMode] = useState('git')
  const [url, setUrl] = useState('')
  const [branch, setBranch] = useState('')
  const [token, setToken] = useState('')
  const [file, setFile] = useState(null)
  const [checks, setChecks] = useState({})
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    api('/api/meta').then(m => {
      setMeta(m)
      setChecks(Object.fromEntries(m.checks.map(c => [c.key, c.default])))
    }).catch(e => setError(e.message))
  }, [])

  async function submit(e) {
    e.preventDefault()
    setError('')
    if (mode === 'git' && !url.trim().toLowerCase().startsWith('https://')) {
      setError('Enter an https:// Git repository URL.'); return
    }
    if (mode === 'zip' && !file) { setError('Choose a .zip file.'); return }
    if (mode === 'zip' && meta && file.size > meta.max_upload_mb * 1024 * 1024) {
      setError(`The zip is larger than ${meta.max_upload_mb} MB.`); return
    }
    const form = new FormData()
    form.append('source_type', mode)
    form.append('checks', JSON.stringify(checks))
    if (mode === 'git') {
      form.append('repo_url', url.trim())
      if (branch.trim()) form.append('branch', branch.trim())
      if (token.trim()) form.append('token', token.trim())
    } else {
      form.append('file', file)
    }
    setBusy(true)
    try {
      const res = await api('/api/scans', { method: 'POST', form })
      setToken('')
      navigate(`/scans/${res.id}`)
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>New scan</h1>
          <div className="muted">Code is cloned or unzipped into a temporary folder, read by the scanners, then deleted. It is never built, run or changed.</div>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      <form onSubmit={submit} className="newscan">
        <div className="card">
          <h2>Source</h2>
          <div className="segmented" role="tablist">
            <button type="button" role="tab" aria-selected={mode === 'git'} className={mode === 'git' ? 'on' : ''} onClick={() => setMode('git')}>Git repository</button>
            <button type="button" role="tab" aria-selected={mode === 'zip'} className={mode === 'zip' ? 'on' : ''} onClick={() => setMode('zip')}>Zip upload</button>
          </div>

          {mode === 'git' ? (
            <>
              <div className="field">
                <label htmlFor="url">Repository URL</label>
                <input id="url" type="url" className="mono" placeholder="https://github.com/org/repo"
                       value={url} onChange={e => setUrl(e.target.value)} required />
              </div>
              <div className="grid2">
                <div className="field">
                  <label htmlFor="branch">Branch <span className="muted small">(optional, default branch if empty)</span></label>
                  <input id="branch" type="text" className="mono" placeholder="main"
                         value={branch} onChange={e => setBranch(e.target.value)} />
                </div>
                <div className="field">
                  <label htmlFor="token">Access token <span className="muted small">(private repos only)</span></label>
                  <input id="token" type="password" autoComplete="off" placeholder="Read-only token"
                         value={token} onChange={e => setToken(e.target.value)} />
                </div>
              </div>
              <p className="muted small" style={{ margin: 0 }}>
                The token is encrypted while the scan waits in the queue, used once to clone, then deleted. It is never shown again or written to logs.
              </p>
            </>
          ) : (
            <div className="field">
              <label htmlFor="zip">Zip archive</label>
              <input id="zip" type="file" accept=".zip,application/zip" onChange={e => setFile(e.target.files[0] || null)} />
              <p className="muted small">Up to {meta?.max_upload_mb ?? '…'} MB. Zip uploads have no Git history, so secrets are checked in current files only.</p>
            </div>
          )}
        </div>

        <div className="card">
          <h2>Checks</h2>
          {!meta && <div className="muted">Loading…</div>}
          {meta?.checks.map(c => {
            const disabled = c.key === 'ai' && !meta.ai_available
            return (
              <label key={c.key} className={`switch-row${disabled ? ' disabled' : ''}`}>
                <span>
                  <span className="switch-label">{c.label}</span>
                  {disabled && <span className="small muted switch-help">Unavailable: {meta.ai_unavailable_reason}</span>}
                  {c.key === 'ai' && meta.ai_available && (
                    <span className="small muted switch-help">Sends findings and related code to the Claude API ({meta.ai_model}).</span>
                  )}
                </span>
                <input type="checkbox" className="switch" disabled={disabled}
                       checked={!!checks[c.key] && !disabled}
                       onChange={e => setChecks({ ...checks, [c.key]: e.target.checked })} />
              </label>
            )
          })}
        </div>

        <button className="btn" disabled={busy || !meta}>{busy ? 'Starting…' : 'Start scan'}</button>
      </form>
    </>
  )
}

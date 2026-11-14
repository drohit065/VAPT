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
  const [targets, setTargets] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [authA, setAuthA] = useState('')
  const [authB, setAuthB] = useState('')
  const [endpoints, setEndpoints] = useState('')
  const [showAuth, setShowAuth] = useState(false)
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
    if (mode === 'url') {
      const list = targets.split(/[\n,]/).map(t => t.trim()).filter(Boolean)
      if (!list.length) { setError('Enter at least one URL.'); return }
      if (list.some(t => !/^https?:\/\//i.test(t))) { setError('Every URL must start with http:// or https://'); return }
      if (!authorized) { setError('Confirm that you are authorised to test these targets.'); return }
    }
    if (mode === 'zip' && meta && file.size > meta.max_upload_mb * 1024 * 1024) {
      setError(`The zip is larger than ${meta.max_upload_mb} MB.`); return
    }
    const form = new FormData()
    form.append('source_type', mode)
    form.append('checks', JSON.stringify(Object.fromEntries(
      Object.entries(checks).filter(([k]) => visibleKeys.includes(k)))))
    if (mode === 'git') {
      form.append('repo_url', url.trim())
      if (branch.trim()) form.append('branch', branch.trim())
      if (token.trim()) form.append('token', token.trim())
    } else if (mode === 'url') {
      form.append('target_urls', targets)
      form.append('authorized', authorized ? 'true' : 'false')
      if (authA.trim()) form.append('auth_a', authA.trim())
      if (authB.trim()) form.append('auth_b', authB.trim())
      if (endpoints.trim()) form.append('endpoints', endpoints.trim())
    } else {
      form.append('file', file)
    }
    setBusy(true)
    try {
      const res = await api('/api/scans', { method: 'POST', form })
      setToken(''); setAuthA(''); setAuthB('')
      navigate(`/scans/${res.id}`)
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }

  const visible = (meta?.checks || []).filter(c => !c.sources || c.sources.includes(mode))
  const visibleKeys = visible.map(c => c.key)

  return (
    <>
      <div className="page-head">
        <div>
          <h1>New scan</h1>
          <div className="muted">
            {mode === 'url'
              ? 'Live targets receive ordinary HTTP requests from the scanner. Nothing is changed on the target.'
              : 'Code is cloned or unzipped into a temporary folder, read by the scanners, then deleted. It is never built, run or changed.'}
          </div>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      <form onSubmit={submit} className="newscan">
        <div className="card">
          <h2>Source</h2>
          <div className="segmented" role="tablist">
            <button type="button" role="tab" aria-selected={mode === 'git'} className={mode === 'git' ? 'on' : ''} onClick={() => setMode('git')}>Git repository</button>
            <button type="button" role="tab" aria-selected={mode === 'zip'} className={mode === 'zip' ? 'on' : ''} onClick={() => setMode('zip')}>Zip upload</button>
            <button type="button" role="tab" aria-selected={mode === 'url'} className={mode === 'url' ? 'on' : ''} onClick={() => setMode('url')}>Website / API</button>
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
          ) : mode === 'url' ? (
            <>
              <div className="field">
                <label htmlFor="targets">Target URLs <span className="muted small">(one per line, up to 5: e.g. frontend and backend API)</span></label>
                <textarea id="targets" className="mono" rows={4}
                          placeholder={'https://app.example.com\nhttps://api.example.com/health'}
                          value={targets} onChange={e => setTargets(e.target.value)} />
              </div>
              <label className="consent">
                <input type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)} />
                <span>I own these targets or have written permission to security-test them.</span>
              </label>
              <p className="muted small" style={{ margin: '8px 0 0' }}>
                Sends a few thousand requests per target (rate-limited to 30/s). Destructive, brute-force and fuzzing
                tests are excluded. Private and internal addresses are blocked. Run against staging first if you can.
              </p>

              <div className="auth-box">
                <button type="button" className="linkbtn auth-toggle" onClick={() => setShowAuth(s => !s)}
                        aria-expanded={showAuth}>
                  {showAuth ? '▾' : '▸'} Authenticated scan and access control (optional)
                </button>
                {showAuth && (
                  <>
                    <p className="muted small" style={{ marginTop: 6 }}>
                      Paste request headers of a logged-in session, one per line, e.g.
                      <span className="mono"> Authorization: Bearer eyJ…</span> or
                      <span className="mono"> Cookie: session=…</span>. Use test accounts. Values are encrypted
                      while queued, used only during the scan, then deleted; they are never shown again.
                    </p>
                    <div className="grid2">
                      <div className="field">
                        <label htmlFor="authA">User A headers</label>
                        <textarea id="authA" className="mono" rows={3} spellCheck={false} autoComplete="off"
                                  placeholder="Authorization: Bearer …"
                                  value={authA} onChange={e => setAuthA(e.target.value)} />
                      </div>
                      <div className="field">
                        <label htmlFor="authB">User B headers <span className="muted small">(a different user, optional)</span></label>
                        <textarea id="authB" className="mono" rows={3} spellCheck={false} autoComplete="off"
                                  placeholder="Authorization: Bearer …"
                                  value={authB} onChange={e => setAuthB(e.target.value)} />
                      </div>
                    </div>
                    <div className="field">
                      <label htmlFor="endpoints">
                        Protected endpoints to compare <span className="muted small">(one per line, paths or full URLs on the
                        targets above, ideally ones returning user A's own data, e.g. /api/users/123, /api/orders/45)</span>
                      </label>
                      <textarea id="endpoints" className="mono" rows={4} spellCheck={false}
                                placeholder={'/api/me\n/api/orders/1001'}
                                value={endpoints} onChange={e => setEndpoints(e.target.value)} />
                    </div>
                    <p className="muted small" style={{ margin: 0 }}>
                      The access control check sends GET requests only: each endpoint as user A, without credentials,
                      and as user B, and flags identical responses.
                    </p>
                  </>
                )}
              </div>
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
          {visible.map(c => {
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

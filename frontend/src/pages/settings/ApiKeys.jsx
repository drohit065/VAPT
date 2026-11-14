import { useEffect, useState } from 'react'
import { api } from '../../api.js'
import { fmtTime } from '../../components/Severity.jsx'

const ACTIONS_YML = `# .github/workflows/vapt.yml  (secrets: VAPT_URL, VAPT_API_KEY)
name: VAPT security scan
on: [pull_request, push]
permissions: { contents: read, security-events: write }
jobs:
  vapt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan with VAPT Scanner
        env:
          VAPT_URL: \${{ secrets.VAPT_URL }}
          VAPT_API_KEY: \${{ secrets.VAPT_API_KEY }}
          VAPT_FAIL_ON: High
          VAPT_SARIF: vapt.sarif
        run: |
          curl -fsSLo vapt-scan.sh https://raw.githubusercontent.com/drohit065/VAPT/main/ci/vapt-scan.sh
          bash vapt-scan.sh
      - uses: github/codeql-action/upload-sarif@v3
        if: always() && hashFiles('vapt.sarif') != ''
        with: { sarif_file: vapt.sarif }`

function Copy({ text }) {
  const [done, setDone] = useState(false)
  return (
    <button type="button" className="btn secondary small-btn"
            onClick={() => navigator.clipboard.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1500) })}>
      {done ? 'Copied' : 'Copy'}
    </button>
  )
}

export default function ApiKeys() {
  const [keys, setKeys] = useState(null)
  const [form, setForm] = useState({ name: '', role: 'analyst', expires_days: 365 })
  const [created, setCreated] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = () => api('/api/api-keys').then(setKeys).catch(e => setError(e.message))
  useEffect(() => { load() }, [])

  async function create(e) {
    e.preventDefault()
    setBusy(true); setError(''); setCreated(null)
    try {
      const k = await api('/api/api-keys', { method: 'POST', body: { ...form, expires_days: Number(form.expires_days) || null } })
      setCreated(k); setForm({ name: '', role: 'analyst', expires_days: 365 }); load()
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  async function revoke(k) {
    if (!window.confirm(`Revoke the key "${k.name}"? Pipelines using it will stop working.`)) return
    try { await api(`/api/api-keys/${k.id}`, { method: 'DELETE' }); load() } catch (err) { setError(err.message) }
  }

  return (
    <>
      {error && <div className="error">{error}</div>}
      {created && (
        <div className="card key-created">
          <h2>Key created: copy it now</h2>
          <p className="small muted" style={{ marginTop: -6 }}>This is the only time the full key is shown. Store it as a CI secret.</p>
          <div className="secret-row"><code className="key-value">{created.key}</code><Copy text={created.key} /></div>
        </div>
      )}
      <form className="card" onSubmit={create}>
        <h2>New API key</h2>
        <div className="grid3">
          <div className="field"><label htmlFor="kn">Name</label>
            <input id="kn" value={form.name} placeholder="github-actions-shop-api" required maxLength={100}
                   onChange={e => setForm({ ...form, name: e.target.value })} /></div>
          <div className="field"><label htmlFor="kr">Role</label>
            <select id="kr" value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}>
              <option value="analyst">analyst (start scans, read results)</option>
              <option value="viewer">viewer (read results only)</option>
            </select></div>
          <div className="field"><label htmlFor="ke">Expires after (days)</label>
            <input id="ke" type="number" min={1} max={3650} value={form.expires_days}
                   onChange={e => setForm({ ...form, expires_days: e.target.value })} /></div>
        </div>
        <button className="btn" disabled={busy}>{busy ? 'Creating…' : 'Create key'}</button>
      </form>

      <div className="card" style={{ padding: 8 }}>
        {!keys && <div className="empty">Loading…</div>}
        {keys && keys.length === 0 && <div className="empty">No API keys yet.</div>}
        {keys && keys.length > 0 && (
          <table className="list responsive">
            <thead><tr><th>Name</th><th>Key</th><th>Role</th><th>Expires</th><th>Last used</th><th></th></tr></thead>
            <tbody>
              {keys.map(k => (
                <tr key={k.id} className={k.revoked ? 'revoked' : ''}>
                  <td data-label="Name"><strong>{k.name}</strong><div className="small muted">by {k.created_by}</div></td>
                  <td data-label="Key" className="mono">{k.prefix}…</td>
                  <td data-label="Role">{k.role}</td>
                  <td data-label="Expires">{k.expires_at ? fmtTime(k.expires_at) : 'never'}</td>
                  <td data-label="Last used">{fmtTime(k.last_used_at)}</td>
                  <td data-label="">{k.revoked ? <span className="muted">revoked</span>
                    : <button type="button" className="linkbtn danger" onClick={() => revoke(k)}>Revoke</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h2>Use in CI/CD</h2>
        <p className="small muted" style={{ marginTop: -6 }}>
          The <span className="mono">ci/vapt-scan.sh</span> client zips the checked-out code (or scans a Git URL, live URL or
          image), waits for the result and exits 1 when open findings at or above <span className="mono">VAPT_FAIL_ON</span> exist.
          On pull requests, <span className="mono">VAPT_NEW_ONLY=true</span> blocks only on new findings. The runner must be able to
          reach this dashboard over HTTPS.
        </p>
        <div className="code-head"><span className="small muted">GitHub Actions</span><Copy text={ACTIONS_YML} /></div>
        <pre className="snippet">{ACTIONS_YML}</pre>
        <p className="small muted" style={{ marginTop: 10 }}>
          Any other CI: <span className="mono">VAPT_URL=… VAPT_API_KEY=… bash vapt-scan.sh</span>. API:
          <span className="mono"> GET /api/scans/&#123;id&#125;/gate?fail_on=High&amp;new_only=true</span> with
          <span className="mono"> Authorization: Bearer vapt_…</span>.
        </p>
      </div>
    </>
  )
}

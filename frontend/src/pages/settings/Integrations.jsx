import { useEffect, useState } from 'react'
import { api } from '../../api.js'

export default function Integrations() {
  const [cfg, setCfg] = useState(null)
  const [tokens, setTokens] = useState({ jira_token: '', github_token: '' })
  const [clear, setClear] = useState([])
  const [msg, setMsg] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')

  useEffect(() => { api('/api/settings/ticketing').then(setCfg).catch(e => setError(e.message)) }, [])
  if (!cfg) return error ? <div className="error">{error}</div> : <div className="muted">Loading…</div>
  const set = (k, v) => setCfg({ ...cfg, [k]: v })

  async function save(e) {
    e.preventDefault()
    setBusy('save'); setMsg(''); setError('')
    try {
      const labels = (cfg.labels_text ?? cfg.labels.join(', ')).split(/[,\s]+/).filter(Boolean)
      const body = { ...cfg, ...tokens, labels, clear }
      delete body.labels_text
      const saved = await api('/api/settings/ticketing', { method: 'PUT', body })
      setCfg(saved); setTokens({ jira_token: '', github_token: '' }); setClear([])
      setMsg('Ticketing settings saved.')
    } catch (err) { setError(err.message) } finally { setBusy('') }
  }

  async function test() {
    setBusy('test'); setMsg(''); setError('')
    try {
      const r = await api('/api/settings/ticketing/test', { method: 'POST' })
      r.ok ? setMsg(r.message) : setError(r.message)
    } catch (err) { setError(err.message) } finally { setBusy('') }
  }

  const tokenKey = cfg.provider === 'jira' ? 'jira_token' : 'github_token'
  const tokenSet = cfg.provider === 'jira' ? cfg.jira_token_set : cfg.github_token_set

  return (
    <form onSubmit={save}>
      {error && <div className="error">{error}</div>}
      {msg && <div className="info">{msg}</div>}
      <div className="card">
        <h2>Ticketing</h2>
        <p className="small muted" style={{ marginTop: -6 }}>
          Lets analysts turn findings into Jira or GitHub issues with all details, evidence (secrets masked) and a
          link back to the report. Each finding remembers its ticket, so duplicates are not created.
        </p>
        <div className="segmented">
          {[['none', 'Off'], ['jira', 'Jira'], ['github', 'GitHub Issues']].map(([k, l]) => (
            <button key={k} type="button" className={cfg.provider === k ? 'on' : ''} onClick={() => set('provider', k)}>{l}</button>
          ))}
        </div>

        {cfg.provider === 'jira' && (
          <>
            <div className="grid2">
              <div className="field"><label htmlFor="ju">Jira site URL</label>
                <input id="ju" type="url" value={cfg.jira_url} placeholder="https://your-company.atlassian.net"
                       onChange={e => set('jira_url', e.target.value)} /></div>
              <div className="field"><label htmlFor="je">Account email</label>
                <input id="je" type="email" value={cfg.jira_email} placeholder="security-bot@your-company.com"
                       onChange={e => set('jira_email', e.target.value)} /></div>
            </div>
            <div className="grid2">
              <div className="field"><label htmlFor="jp">Project key</label>
                <input id="jp" value={cfg.jira_project} placeholder="SEC" onChange={e => set('jira_project', e.target.value)} /></div>
              <div className="field"><label htmlFor="jt">Issue type</label>
                <input id="jt" value={cfg.jira_issue_type} placeholder="Bug" onChange={e => set('jira_issue_type', e.target.value)} /></div>
            </div>
          </>
        )}
        {cfg.provider === 'github' && (
          <div className="field"><label htmlFor="gr">Repository <span className="muted small">(owner/name)</span></label>
            <input id="gr" value={cfg.github_repo} placeholder="my-org/my-app" onChange={e => set('github_repo', e.target.value)} /></div>
        )}
        {cfg.provider !== 'none' && (
          <>
            <div className="field">
              <label htmlFor="tok">
                {cfg.provider === 'jira' ? 'Jira API token' : 'GitHub token (fine-grained, Issues: read and write)'}
                {tokenSet && <span className="pill ok">configured</span>}
              </label>
              <div className="secret-row">
                <input id="tok" type="password" autoComplete="off" value={tokens[tokenKey]}
                       placeholder={tokenSet ? 'Leave empty to keep the stored token' : ''}
                       onChange={e => setTokens({ ...tokens, [tokenKey]: e.target.value })} />
                {tokenSet && (
                  <button type="button" className="linkbtn danger"
                          onClick={() => { setClear([...clear, tokenKey]); set(`${tokenKey}_set`, false) }}>Remove</button>
                )}
              </div>
            </div>
            <div className="field"><label htmlFor="lb">Labels</label>
              <input id="lb" value={cfg.labels_text ?? cfg.labels.join(', ')} onChange={e => set('labels_text', e.target.value)} /></div>
          </>
        )}
      </div>
      <div className="form-actions">
        <button className="btn" disabled={!!busy}>{busy === 'save' ? 'Saving…' : 'Save settings'}</button>
        {cfg.provider !== 'none' && (
          <button type="button" className="btn secondary" onClick={test} disabled={!!busy}>
            {busy === 'test' ? 'Testing…' : 'Test connection'}
          </button>
        )}
      </div>
    </form>
  )
}

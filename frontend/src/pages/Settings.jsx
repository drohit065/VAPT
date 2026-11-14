import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../api.js'
import Integrations from './settings/Integrations.jsx'
import ApiKeys from './settings/ApiKeys.jsx'

function SecretField({ id, label, configured, value, onChange, onClear, placeholder, type = 'password' }) {
  return (
    <div className="field">
      <label htmlFor={id}>
        {label} {configured && <span className="pill ok">configured</span>}
      </label>
      <div className="secret-row">
        <input id={id} type={type} autoComplete="off" spellCheck={false} value={value} onChange={onChange}
               placeholder={configured ? 'Leave empty to keep the stored value' : placeholder} />
        {configured && <button type="button" className="linkbtn danger" onClick={onClear}>Remove</button>}
      </div>
    </div>
  )
}

function Notifications() {
  const [cfg, setCfg] = useState(null)
  const [secrets, setSecrets] = useState({ slack_url: '', teams_url: '', smtp_password: '' })
  const [clear, setClear] = useState([])
  const [msg, setMsg] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')

  useEffect(() => { api('/api/settings/notifications').then(setCfg).catch(e => setError(e.message)) }, [])
  if (!cfg) return error ? <div className="error">{error}</div> : <div className="muted">Loading…</div>

  const set = (k, v) => setCfg({ ...cfg, [k]: v })
  const setSecret = (k, v) => setSecrets({ ...secrets, [k]: v })

  async function save(e) {
    e.preventDefault()
    setBusy('save'); setMsg(''); setError('')
    try {
      const body = { ...cfg, ...secrets, clear, email_to: (cfg.email_to_text ?? cfg.email_to.join(', '))
        .split(/[,;\s]+/).filter(Boolean) }
      delete body.email_to_text
      const saved = await api('/api/settings/notifications', { method: 'PUT', body })
      setCfg(saved); setSecrets({ slack_url: '', teams_url: '', smtp_password: '' }); setClear([])
      setMsg('Notification settings saved.')
    } catch (err) { setError(err.message) } finally { setBusy('') }
  }

  async function test() {
    setBusy('test'); setMsg(''); setError('')
    try {
      const r = await api('/api/settings/notifications/test', { method: 'POST' })
      if (r.ok) setMsg('Test message sent to every configured channel.')
      else setError(r.errors.join(' · '))
    } catch (err) { setError(err.message) } finally { setBusy('') }
  }

  const markClear = k => { setClear([...clear, k]); setCfg({ ...cfg, [k === 'smtp_password' ? 'smtp_password_set' : k.replace('_url', '_configured')]: false }) }

  return (
    <form onSubmit={save}>
      {error && <div className="error">{error}</div>}
      {msg && <div className="info">{msg}</div>}
      <div className="card">
        <label className="switch-row">
          <span><span className="switch-label">Send notifications</span>
            <span className="small muted switch-help">Master switch for all channels below.</span></span>
          <input type="checkbox" className="switch" checked={cfg.enabled} onChange={e => set('enabled', e.target.checked)} />
        </label>
        <h2 style={{ marginTop: 16 }}>When</h2>
        <label className="check-row">
          <input type="checkbox" checked={cfg.on_new_findings} onChange={e => set('on_new_findings', e.target.checked)} />
          <span>New findings at or above
            <select value={cfg.min_severity} onChange={e => set('min_severity', e.target.value)} className="inline-select">
              {['Critical', 'High', 'Medium', 'Low'].map(s => <option key={s}>{s}</option>)}
            </select> (compared with the previous scan)</span>
        </label>
        <label className="check-row">
          <input type="checkbox" checked={cfg.on_failed} onChange={e => set('on_failed', e.target.checked)} />
          <span>A scan fails</span>
        </label>
        <label className="check-row">
          <input type="checkbox" checked={cfg.on_completed} onChange={e => set('on_completed', e.target.checked)} />
          <span>Every completed scan, even without new findings</span>
        </label>
      </div>

      <div className="card">
        <h2>Slack and Microsoft Teams</h2>
        <p className="small muted" style={{ marginTop: -6 }}>Incoming webhook URLs (https). They are stored encrypted and never shown again.</p>
        <SecretField id="slack" label="Slack webhook URL" configured={cfg.slack_configured} value={secrets.slack_url}
                     onChange={e => setSecret('slack_url', e.target.value)} onClear={() => markClear('slack_url')}
                     placeholder="https://hooks.slack.com/services/…" type="url" />
        <SecretField id="teams" label="Microsoft Teams webhook URL" configured={cfg.teams_configured} value={secrets.teams_url}
                     onChange={e => setSecret('teams_url', e.target.value)} onClear={() => markClear('teams_url')}
                     placeholder="https://….webhook.office.com/…" type="url" />
      </div>

      <div className="card">
        <h2>Email</h2>
        <div className="field">
          <label htmlFor="to">Recipients <span className="muted small">(comma separated)</span></label>
          <input id="to" value={cfg.email_to_text ?? cfg.email_to.join(', ')} placeholder="security@example.com, lead@example.com"
                 onChange={e => set('email_to_text', e.target.value)} />
        </div>
        <div className="grid3">
          <div className="field"><label htmlFor="sh">SMTP host</label>
            <input id="sh" value={cfg.smtp_host} placeholder="email-smtp.ap-south-1.amazonaws.com" onChange={e => set('smtp_host', e.target.value)} /></div>
          <div className="field"><label htmlFor="sp">Port</label>
            <input id="sp" type="number" value={cfg.smtp_port} onChange={e => set('smtp_port', Number(e.target.value))} /></div>
          <div className="field"><label htmlFor="st">Encryption</label>
            <select id="st" value={cfg.smtp_tls} onChange={e => set('smtp_tls', e.target.value)}>
              <option value="starttls">STARTTLS (587)</option><option value="ssl">SSL/TLS (465)</option><option value="none">None</option>
            </select></div>
        </div>
        <div className="grid3">
          <div className="field"><label htmlFor="su">Username</label>
            <input id="su" value={cfg.smtp_user} autoComplete="off" onChange={e => set('smtp_user', e.target.value)} /></div>
          <SecretField id="spw" label="Password" configured={cfg.smtp_password_set} value={secrets.smtp_password}
                       onChange={e => setSecret('smtp_password', e.target.value)} onClear={() => markClear('smtp_password')} placeholder="" />
          <div className="field"><label htmlFor="sf">From address</label>
            <input id="sf" value={cfg.smtp_from} placeholder="vapt@example.com" onChange={e => set('smtp_from', e.target.value)} /></div>
        </div>
      </div>

      <div className="form-actions">
        <button className="btn" disabled={!!busy}>{busy === 'save' ? 'Saving…' : 'Save settings'}</button>
        <button type="button" className="btn secondary" onClick={test} disabled={!!busy}>
          {busy === 'test' ? 'Sending…' : 'Send test message'}
        </button>
      </div>
    </form>
  )
}

const TABS = [
  { key: 'notifications', label: 'Notifications', el: <Notifications /> },
  { key: 'integrations', label: 'Ticketing', el: <Integrations /> },
  { key: 'api-keys', label: 'API keys & CI/CD', el: <ApiKeys /> },
]

export default function Settings() {
  const [params, setParams] = useSearchParams()
  const tab = TABS.find(t => t.key === params.get('tab')) || TABS[0]
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <div className="muted">Notifications, ticketing integrations and API access. Secrets are stored encrypted.</div>
        </div>
      </div>
      <div className="tabs" role="tablist">
        {TABS.map(t => (
          <button key={t.key} role="tab" aria-selected={t === tab} className={t === tab ? 'on' : ''}
                  onClick={() => setParams({ tab: t.key })}>{t.label}</button>
        ))}
      </div>
      {tab.el}
    </>
  )
}

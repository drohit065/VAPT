export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low']

export const SEV_COLORS = {
  Critical: { bg: '#7A1626', fg: '#fff' },
  High: { bg: '#C2410C', fg: '#fff' },
  Medium: { bg: '#F5C451', fg: '#3d2c00' },
  Low: { bg: '#DCE6F2', fg: '#22324a' },
}

export function SevBadge({ level }) {
  if (!level || level === 'None') return <span className="sev sev-None">None</span>
  return <span className={`sev sev-${level}`}>{level}</span>
}

export function CountChips({ counts }) {
  const total = SEVERITIES.reduce((n, s) => n + (counts?.[s] || 0), 0)
  if (!total) return <span className="clean">No findings</span>
  return (
    <span className="counts">
      {SEVERITIES.filter(s => counts[s]).map(s => (
        <span key={s} className="count-chip" title={s}
              style={{ background: SEV_COLORS[s].bg, color: SEV_COLORS[s].fg }}>
          {counts[s]} {s[0]}
        </span>
      ))}
    </span>
  )
}

export function fmtTime(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

import { useEffect, useRef, useState } from 'react'
import { SEVERITIES, SEV_COLORS } from './Severity.jsx'

// Severity colours are fixed by the product spec. Medium/Low are light (contrast < 3:1 on white),
// so every mark gets a hairline outline, values are direct-labelled where they fit, a legend is
// always shown and each chart has a table view.
const OUTLINE = { Critical: 'none', High: 'none', Medium: '#B88A16', Low: '#93A4BA' }
const INK = 'var(--muted)'

function useWidth() {
  const ref = useRef(null)
  const [w, setW] = useState(600)
  useEffect(() => {
    if (!ref.current) return
    const ro = new ResizeObserver(([e]) => setW(Math.max(260, Math.floor(e.contentRect.width))))
    ro.observe(ref.current)
    return () => ro.disconnect()
  }, [])
  return [ref, w]
}

export function Legend({ keys = SEVERITIES }) {
  return (
    <div className="chart-legend">
      {keys.map(k => (
        <span key={k}><i style={{ background: SEV_COLORS[k].bg, outline: OUTLINE[k] !== 'none' ? `1px solid ${OUTLINE[k]}` : 'none' }} />{k}</span>
      ))}
    </div>
  )
}

function niceMax(v) {
  if (v <= 5) return 5
  const p = 10 ** Math.floor(Math.log10(v))
  return [1, 2, 2.5, 5, 10].map(m => m * p).find(m => m >= v)
}

function Tooltip({ tip }) {
  if (!tip) return null
  return (
    <div className="chart-tip" style={{ left: tip.x, top: tip.y }} role="status">
      <div className="chart-tip-title">{tip.title}</div>
      {SEVERITIES.map(s => (
        <div key={s} className="chart-tip-row">
          <i style={{ background: SEV_COLORS[s].bg, outline: OUTLINE[s] !== 'none' ? `1px solid ${OUTLINE[s]}` : 'none' }} />
          <span>{s}</span><b>{tip.row[s] || 0}</b>
        </div>
      ))}
      <div className="chart-tip-row total"><span>Total</span><b>{SEVERITIES.reduce((n, s) => n + (tip.row[s] || 0), 0)}</b></div>
    </div>
  )
}

function TableView({ rows, labelKey, labelName }) {
  return (
    <table className="list chart-table">
      <thead><tr><th>{labelName}</th>{SEVERITIES.map(s => <th key={s}>{s}</th>)}<th>Total</th></tr></thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i}><td>{r[labelKey]}</td>{SEVERITIES.map(s => <td key={s}>{r[s] || 0}</td>)}
            <td><b>{SEVERITIES.reduce((n, s) => n + (r[s] || 0), 0)}</b></td></tr>
        ))}
      </tbody>
    </table>
  )
}

export function ChartCard({ title, subtitle, children, table }) {
  const [asTable, setAsTable] = useState(false)
  return (
    <div className="card chart-card">
      <div className="chart-head">
        <div>
          <h2>{title}</h2>
          {subtitle && <div className="small muted">{subtitle}</div>}
        </div>
        {table && (
          <button type="button" className="linkbtn" onClick={() => setAsTable(t => !t)}>
            {asTable ? 'Chart view' : 'Table view'}
          </button>
        )}
      </div>
      {asTable ? table : children}
    </div>
  )
}

/** Stacked columns over time (one column per period, segments by severity). */
export function TrendChart({ data }) {
  const [ref, width] = useWidth()
  const [tip, setTip] = useState(null)
  const h = 220, pad = { l: 36, r: 8, t: 10, b: 26 }
  const totals = data.map(d => SEVERITIES.reduce((n, s) => n + (d[s] || 0), 0))
  const max = niceMax(Math.max(1, ...totals))
  const plotW = width - pad.l - pad.r, plotH = h - pad.t - pad.b
  const slot = plotW / data.length
  const bw = Math.max(6, Math.min(36, slot * 0.6))
  const y = v => pad.t + plotH - (v / max) * plotH
  const ticks = [0, max / 2, max]
  const fmt = iso => new Date(iso + 'T00:00:00Z').toLocaleDateString(undefined, { day: 'numeric', month: 'short' })
  const labelEvery = Math.ceil(data.length / Math.max(2, Math.floor(plotW / 70)))

  return (
    <div ref={ref} className="chart-wrap" onMouseLeave={() => setTip(null)}>
      <Legend />
      <svg width={width} height={h} role="img"
           aria-label={`Open findings per week, latest week: ${totals[totals.length - 1]} total`}>
        {ticks.map(t => (
          <g key={t}>
            <line x1={pad.l} x2={width - pad.r} y1={y(t)} y2={y(t)} stroke="var(--border)" strokeWidth="1" />
            <text x={pad.l - 6} y={y(t) + 4} textAnchor="end" fontSize="11" fill={INK}>{t}</text>
          </g>
        ))}
        {data.map((d, i) => {
          const x = pad.l + slot * i + (slot - bw) / 2
          let acc = 0
          const segs = SEVERITIES.map(s => {
            const v = d[s] || 0
            if (!v) return null
            const y0 = y(acc), y1 = y(acc + v)
            acc += v
            const top = acc === totals[i]
            const hgt = Math.max(1, y0 - y1 - (top ? 0 : 2))  // 2px surface gap between segments
            return (
              <rect key={s} x={x} y={y1 + (top ? 0 : 0)} width={bw} height={hgt} rx={top ? 4 : 0}
                    fill={SEV_COLORS[s].bg} stroke={OUTLINE[s]} strokeWidth={OUTLINE[s] === 'none' ? 0 : 1} />
            )
          })
          return (
            <g key={d.week_end}>
              {segs}
              {i % labelEvery === (data.length - 1) % labelEvery && (
                <text x={x + bw / 2} y={h - 8} textAnchor="middle" fontSize="11" fill={INK}>{fmt(d.week_end)}</text>
              )}
              {i === data.length - 1 && totals[i] > 0 && (
                <text x={x + bw / 2} y={y(totals[i]) - 5} textAnchor="middle" fontSize="11" fontWeight="600"
                      fill="var(--text)">{totals[i]}</text>
              )}
              {/* hit target: the full column slot */}
              <rect x={pad.l + slot * i} y={pad.t} width={slot} height={plotH} fill="transparent"
                    onMouseMove={e => {
                      const r = ref.current.getBoundingClientRect()
                      setTip({ x: Math.min(e.clientX - r.left + 12, width - 170), y: e.clientY - r.top + 8,
                               title: `Week ending ${fmt(d.week_end)}`, row: d })
                    }} />
            </g>
          )
        })}
      </svg>
      <Tooltip tip={tip} />
    </div>
  )
}

export function TrendTable({ data }) {
  return <TableView rows={data.map(d => ({ ...d, week: d.week_end }))} labelKey="week" labelName="Week ending" />
}

/** Horizontal stacked bars, one row per category; total direct-labelled at the end of each bar. */
export function CategoryBars({ rows, labelKey = 'label', onSelect }) {
  const [ref, width] = useWidth()
  const [tip, setTip] = useState(null)
  const labelW = Math.min(170, width * 0.38)
  const rowH = 30, barH = 14
  const totals = rows.map(r => SEVERITIES.reduce((n, s) => n + (r[s] || 0), 0))
  const max = Math.max(1, ...totals)
  const plotW = width - labelW - 44
  const h = rows.length * rowH + 4

  return (
    <div ref={ref} className="chart-wrap" onMouseLeave={() => setTip(null)}>
      <Legend />
      <svg width={width} height={h} role="img" aria-label="Open findings by category">
        {rows.map((r, i) => {
          const yy = i * rowH + (rowH - barH) / 2
          let acc = 0
          return (
            <g key={r[labelKey]} style={onSelect ? { cursor: 'pointer' } : undefined} onClick={() => onSelect?.(r)}>
              <text x={labelW - 8} y={yy + barH - 2} textAnchor="end" fontSize="12" fill="var(--text)">{r[labelKey]}</text>
              {SEVERITIES.map(s => {
                const v = r[s] || 0
                if (!v) return null
                const x = labelW + (acc / max) * plotW
                const w = Math.max(2, (v / max) * plotW - 2)
                acc += v
                const end = acc === totals[i]
                return <rect key={s} x={x} y={yy} width={w} height={barH} rx={end ? 4 : 0} fill={SEV_COLORS[s].bg}
                             stroke={OUTLINE[s]} strokeWidth={OUTLINE[s] === 'none' ? 0 : 1} />
              })}
              <text x={labelW + (totals[i] / max) * plotW + 6} y={yy + barH - 2} fontSize="12" fontWeight="600"
                    fill="var(--text)">{totals[i]}</text>
              <rect x={0} y={i * rowH} width={width} height={rowH} fill="transparent"
                    onMouseMove={e => {
                      const b = ref.current.getBoundingClientRect()
                      setTip({ x: Math.min(e.clientX - b.left + 12, width - 170), y: e.clientY - b.top + 8,
                               title: r[labelKey], row: r })
                    }} />
            </g>
          )
        })}
      </svg>
      <Tooltip tip={tip} />
    </div>
  )
}

export function CategoryTable({ rows, labelKey = 'label', labelName = 'Category' }) {
  return <TableView rows={rows} labelKey={labelKey} labelName={labelName} />
}

/** Small inline stacked bar for table rows. */
export function MiniBar({ counts, max }) {
  const total = SEVERITIES.reduce((n, s) => n + (counts[s] || 0), 0)
  if (!total) return <span className="clean small">No findings</span>
  return (
    <div className="minibar" style={{ width: `${Math.max(8, (total / Math.max(1, max)) * 100)}%` }}
         title={SEVERITIES.map(s => `${s}: ${counts[s] || 0}`).join(' · ')}>
      {SEVERITIES.filter(s => counts[s]).map(s => (
        <span key={s} style={{ flexGrow: counts[s], background: SEV_COLORS[s].bg,
                               boxShadow: OUTLINE[s] !== 'none' ? `inset 0 0 0 1px ${OUTLINE[s]}` : 'none' }} />
      ))}
    </div>
  )
}

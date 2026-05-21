import { useNavigate } from 'react-router-dom'
import { DOMAINS, CRITERIA, SEVERITY_LABELS } from '../data/criteria'
import { APPS } from '../data/apps'
import { useEvaluation } from '../context/EvaluationContext'

// ─── Helpers ──────────────────────────────────────────────────────────────────

const STATUS_CONFIG = {
  pass:    { icon: '✅', label: 'Cumplido',                   cls: 'status-pass'    },
  fail:    { icon: '❌', label: 'No cumplido',                cls: 'status-fail'    },
  na:      { icon: '➖', label: 'N/A',                        cls: 'status-na'      },
  partial: { icon: '⚠️', label: 'Parcial',                   cls: 'status-partial' },
  null:    { icon: '🔍', label: 'Sin evaluar',                cls: 'status-pending' },
}

function getStatus(value, detection) {
  if (value === 'pass')    return STATUS_CONFIG.pass
  if (value === 'fail')    return STATUS_CONFIG.fail
  if (value === 'na')      return STATUS_CONFIG.na
  if (detection?.result === 'partial' || detection?.result === 'warning')
    return STATUS_CONFIG.partial
  return STATUS_CONFIG.null
}

function StatusBadge({ value, detection }) {
  const cfg = getStatus(value, detection)
  return <span className={`report-status-badge ${cfg.cls}`}>{cfg.icon} {cfg.label}</span>
}

// ─── Score Card ───────────────────────────────────────────────────────────────
function ScoreCard({ app, results }) {
  const passed    = Object.values(results).filter(v => v === 'pass').length
  const failed    = Object.values(results).filter(v => v === 'fail').length
  const na        = Object.values(results).filter(v => v === 'na').length
  const unevaluated = CRITERIA.length - passed - failed - na
  const pct       = Math.round((passed / CRITERIA.length) * 100)
  const owaspPass = passed >= 32
  const level     = pct >= 75 ? 'high' : pct >= 45 ? 'medium' : 'low'
  const labels    = { high: 'Seguro', medium: 'Riesgo Medio', low: 'Riesgo Alto' }
  const circum    = 314 // 2π × 50

  return (
    <div className="score-card" style={{ '--app-dim': app.colorDim }}>
      <div className="score-card-header">
        <div>
          <p className="score-card-tag" style={{ color: app.color }}>{app.tag}</p>
          <h3 className="score-card-title">{app.name}</h3>
          <p className="score-card-sub">{app.subtitle}</p>
        </div>
        <span className={`score-level score-level-${level}`}>{labels[level]}</span>
      </div>

      <div className="score-ring-row">
        <div className="score-ring">
          <svg className="score-svg" viewBox="0 0 120 120">
            <circle cx="60" cy="60" r="50" className="score-track" />
            <circle
              cx="60" cy="60" r="50"
              className="score-fill"
              style={{ stroke: app.color, strokeDasharray: `${(pct / 100) * circum} ${circum}` }}
            />
          </svg>
          <div className="score-ring-label">
            <span className="score-pct" style={{ color: app.color }}>{pct}%</span>
            <span className="score-pct-label">{passed}/40</span>
          </div>
        </div>
        <div className="score-stats">
          <div className="score-stat"><span className="stat-val stat-pass">{passed}</span><span className="stat-label">Cumple</span></div>
          <div className="score-stat"><span className="stat-val stat-fail">{failed}</span><span className="stat-label">No cumple</span></div>
          <div className="score-stat"><span className="stat-val stat-na">{na}</span><span className="stat-label">N/A</span></div>
          <div className="score-stat"><span className="stat-val stat-pending">{unevaluated}</span><span className="stat-label">Sin evaluar</span></div>
        </div>
      </div>

      <div className={`owasp-threshold ${owaspPass ? 'owasp-pass' : 'owasp-fail'}`}>
        {owaspPass ? '✅' : '❌'} Umbral OWASP 80% (32/40):&nbsp;
        <strong>{owaspPass ? 'SUPERADO' : 'NO ALCANZADO'}</strong>
        &nbsp;· {passed}/40 controles cumplidos
      </div>
    </div>
  )
}

// ─── Thesis Table (Tabla 33) ──────────────────────────────────────────────────
function ThesisTable({ appA, appB }) {
  const { getDetection } = useEvaluation()

  return (
    <div className="thesis-table-section">
      <div className="section-header">
        <h2 className="section-title">Tabla de Evaluación MASVS v2 — 40 Controles</h2>
        <p className="section-subtitle">
          Organizado por dominio · Compatible con Tabla 33 de la tesis
        </p>
      </div>

      {DOMAINS.map(domain => {
        const domCriteria = CRITERIA.filter(c => c.domainId === domain.id)
        const passA = domCriteria.filter(c => appA[c.id] === 'pass').length
        const passB = domCriteria.filter(c => appB[c.id] === 'pass').length

        return (
          <div key={domain.id} className="domain-table-block">
            <div className="domain-table-header">
              <span className="domain-table-icon">{domain.icon}</span>
              <span className="domain-table-name">{domain.name}</span>
              <span className="domain-table-id">MASVS-{domain.id}</span>
              <span className="domain-table-score">
                App Segura: {passA}/{domCriteria.length} &nbsp;|&nbsp; App Insegura: {passB}/{domCriteria.length}
              </span>
            </div>

            <table className="thesis-table">
              <thead>
                <tr>
                  <th className="col-id">ID Control</th>
                  <th className="col-desc">Descripción</th>
                  <th className="col-sev">Severidad</th>
                  <th className="col-aer">AER</th>
                  <th className="col-status th-a">App Segura</th>
                  <th className="col-status th-b">App Insegura</th>
                </tr>
              </thead>
              <tbody>
                {domCriteria.map(c => {
                  const detA = getDetection('A', c.id)
                  const detB = getDetection('B', c.id)
                  const rowClass = (appA[c.id] === 'fail' || appB[c.id] === 'fail') ? 'row-has-fail' : ''
                  return (
                    <tr key={c.id} className={rowClass}>
                      <td className="td-id">
                        <span className="masvs-id-badge">{c.id}</span>
                      </td>
                      <td className="td-desc">
                        <p className="td-title">{c.title}</p>
                        <p className="td-desc-text">{c.description}</p>
                      </td>
                      <td className="td-sev">
                        <span className={`severity-badge sev-${c.severity}`}>
                          {SEVERITY_LABELS[c.severity]}
                        </span>
                      </td>
                      <td className="td-aer">
                        <span className="aer-badge">{c.aer}</span>
                      </td>
                      <td className="td-status">
                        <StatusBadge value={appA[c.id]} detection={detA} />
                      </td>
                      <td className="td-status">
                        <StatusBadge value={appB[c.id]} detection={detB} />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )
      })}
    </div>
  )
}

// ─── Domain Bar Chart ─────────────────────────────────────────────────────────
function DomainBreakdown({ appA, appB }) {
  return (
    <div className="cat-breakdown">
      <div className="section-header">
        <h2 className="section-title">Desglose por Dominio MASVS</h2>
      </div>
      <div className="cat-breakdown-grid">
        {DOMAINS.map(domain => {
          const cats  = CRITERIA.filter(c => c.domainId === domain.id)
          const total = cats.length
          const passA = cats.filter(c => appA[c.id] === 'pass').length
          const passB = cats.filter(c => appB[c.id] === 'pass').length
          const pctA  = Math.round((passA / total) * 100)
          const pctB  = Math.round((passB / total) * 100)
          return (
            <div key={domain.id} className="cat-bd-row">
              <div className="cat-bd-label">
                <span>{domain.icon}</span>
                <span>{domain.name}</span>
                <span className="cat-bd-count">{total}</span>
              </div>
              <div className="cat-bd-bars">
                <div className="cat-bd-bar-row">
                  <span className="cat-bd-letter letter-a">A</span>
                  <div className="cat-bd-track"><div className="cat-bd-fill fill-a" style={{ width: `${pctA}%` }} /></div>
                  <span className="cat-bd-score">{passA}/{total} ({pctA}%)</span>
                </div>
                <div className="cat-bd-bar-row">
                  <span className="cat-bd-letter letter-b">B</span>
                  <div className="cat-bd-track"><div className="cat-bd-fill fill-b" style={{ width: `${pctB}%` }} /></div>
                  <span className="cat-bd-score">{passB}/{total} ({pctB}%)</span>
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Permissions Section ──────────────────────────────────────────────────────
function PermissionsSection({ analysisA, analysisB }) {
  const hasPerms = analysisA?.dangerousPermissions?.length > 0 || analysisB?.dangerousPermissions?.length > 0
  if (!hasPerms && !analysisA && !analysisB) return null

  const abbr = p => p.replace('android.permission.', '')

  return (
    <div className="permissions-section no-break">
      <div className="section-header">
        <h2 className="section-title">Permisos Peligrosos Solicitados</h2>
        <p className="section-subtitle">Informativos — no cuentan en el score MASVS</p>
      </div>
      <div className="permissions-grid">
        {[{ app: APPS.A, analysis: analysisA }, { app: APPS.B, analysis: analysisB }].map(({ app, analysis }) => {
          const perms = analysis?.dangerousPermissions ?? []
          return (
            <div key={app.id} className="perm-card" style={{ '--ac': app.color }}>
              <p className="perm-card-title" style={{ color: app.color }}>{app.name}</p>
              {perms.length === 0
                ? <p className="perm-none">Sin permisos peligrosos detectados</p>
                : (
                  <div className="perms-list">
                    {perms.map(p => (
                      <span key={p} className="perm-chip perm-danger">{abbr(p)}</span>
                    ))}
                  </div>
                )
              }
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────
export default function ReportPage() {
  const navigate = useNavigate()
  const { appA, appB, analysisA, analysisB } = useEvaluation()

  const unevaluated = CRITERIA.filter(c => appA[c.id] === null && appB[c.id] === null).length
  const passedA     = Object.values(appA).filter(v => v === 'pass').length
  const passedB     = Object.values(appB).filter(v => v === 'pass').length
  const today       = new Date().toLocaleDateString('es-ES', { year: 'numeric', month: 'long', day: 'numeric' })

  return (
    <div className="report-page">

      {/* ── Header ── */}
      <div className="report-header">
        <div>
          <h1 className="report-title">Reporte de Evaluación de Seguridad Móvil</h1>
          <p className="report-subtitle">
            OWASP MASVS v2 · {CRITERIA.length} controles · {DOMAINS.length} dominios · {today}
            {unevaluated > 0 && (
              <span className="report-incomplete"> · ⚠ {unevaluated} sin evaluar</span>
            )}
          </p>
        </div>
        <div className="report-actions no-print">
          <button className="btn-outline" onClick={() => navigate('/evaluacion')}>← Volver</button>
          <button className="btn-primary" onClick={() => window.print()}>🖨 Imprimir / PDF</button>
        </div>
      </div>

      {/* ── Score Cards ── */}
      <div className="score-cards-row">
        {Object.values(APPS).map(app => (
          <ScoreCard
            key={app.id}
            app={app}
            results={app.id === 'A' ? appA : appB}
          />
        ))}
      </div>

      {/* ── Global comparison banner ── */}
      <div className="comparison-banner">
        <div className="comparison-item">
          <span className="comp-label">Diferencia de cumplimiento</span>
          <span className="comp-value" style={{ color: '#10b981' }}>
            +{Math.max(0, passedA - passedB)} controles
          </span>
          <span className="comp-sub">App Segura vs App Insegura</span>
        </div>
        <div className="comparison-item">
          <span className="comp-label">App Segura</span>
          <span className="comp-value" style={{ color: APPS.A.color }}>
            {Math.round((passedA / CRITERIA.length) * 100)}%
          </span>
          <span className="comp-sub">{passedA}/40 controles</span>
        </div>
        <div className="comparison-item">
          <span className="comp-label">App Insegura</span>
          <span className="comp-value" style={{ color: APPS.B.color }}>
            {Math.round((passedB / CRITERIA.length) * 100)}%
          </span>
          <span className="comp-sub">{passedB}/40 controles</span>
        </div>
        <div className="comparison-item">
          <span className="comp-label">Umbral OWASP (80%)</span>
          <span className="comp-value">32/40</span>
          <span className="comp-sub">controles mínimos requeridos</span>
        </div>
      </div>

      {/* ── Domain breakdown ── */}
      <DomainBreakdown appA={appA} appB={appB} />

      {/* ── Thesis table (Tabla 33) ── */}
      <ThesisTable appA={appA} appB={appB} />

      {/* ── Permissions ── */}
      <PermissionsSection analysisA={analysisA} analysisB={analysisB} />

    </div>
  )
}

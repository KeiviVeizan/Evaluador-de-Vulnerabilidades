import { useState } from 'react'
import { SEVERITY_LABELS } from '../data/criteria'

const CONFIDENCE_LABELS = { high: 'Alta', medium: 'Media', low: 'Baja' }
const CONFIDENCE_CLASS  = { high: 'conf-high', medium: 'conf-med', low: 'conf-low' }

const SOURCE_ICON = { apk: '📦', backend: '🌐', manual: '✏️' }
const SOURCE_LABEL = { apk: 'APK', backend: 'Backend', manual: 'Manual' }

function DetectionBadge({ detection }) {
  if (!detection?.result) return null
  const isPass   = detection.result === 'pass'
  const isFail   = detection.result === 'fail'
  const isManual = detection.result === 'manual'
  const cls      = isPass ? 'det-pass' : isFail ? 'det-fail' : isManual ? 'det-manual' : 'det-warn'

  return (
    <div className={`detection-badge ${cls}`}>
      <span className="det-label">
        {isManual ? '🔍 Verificación manual' : `⚡ Detectado · Confianza ${CONFIDENCE_LABELS[detection.confidence] ?? '—'}`}
      </span>
      {detection.note && <p className="det-note">{detection.note}</p>}
      {detection.instruction && (
        <p className="det-instruction">📋 {detection.instruction}</p>
      )}
      {detection.evidence?.length > 0 && (
        <ul className="det-evidence">
          {detection.evidence.slice(0, 4).map((e, i) => <li key={i}>{e}</li>)}
        </ul>
      )}
    </div>
  )
}

function EvalColumn({ value, onChange, detection, label, colorClass }) {
  const [showDetails, setShowDetails] = useState(false)
  const isAuto   = detection?.result === 'pass' || detection?.result === 'fail'
  const isWarn   = detection?.result === 'warning'
  const isManual = detection?.result === 'manual'

  const colState = value === 'pass' ? 'col-pass' : value === 'fail' ? 'col-fail' : value === 'na' ? 'col-na' : ''

  return (
    <div className={`eval-col ${colState}`}>
      <div className="eval-col-head">
        <span className={`eval-col-label ${colorClass}`}>{label}</span>
        {isAuto && (
          <button
            className={`conf-chip ${CONFIDENCE_CLASS[detection.confidence]}`}
            onClick={() => setShowDetails(v => !v)}
            title="Ver evidencia de detección automática"
          >
            ⚡ Auto
          </button>
        )}
        {isWarn && (
          <button
            className="conf-chip conf-warn"
            onClick={() => setShowDetails(v => !v)}
            title={detection.note}
          >
            ⚠ Revisar
          </button>
        )}
        {isManual && (
          <button
            className="conf-chip conf-manual"
            onClick={() => setShowDetails(v => !v)}
            title="Ver instrucción de verificación manual"
          >
            🔍 Manual
          </button>
        )}
      </div>

      {showDetails && <DetectionBadge detection={detection} />}

      <div className="eval-btns">
        <button
          className={`eval-btn pass-btn ${value === 'pass' ? 'active' : ''}`}
          onClick={() => onChange(value === 'pass' ? null : 'pass')}
        >
          <span>✓</span> Cumple
        </button>
        <button
          className={`eval-btn fail-btn ${value === 'fail' ? 'active' : ''}`}
          onClick={() => onChange(value === 'fail' ? null : 'fail')}
        >
          <span>✗</span> No cumple
        </button>
        <button
          className={`eval-btn na-btn ${value === 'na' ? 'active' : ''}`}
          onClick={() => onChange(value === 'na' ? null : 'na')}
        >
          N/A
        </button>
      </div>

      {isAuto && (
        <p className="eval-override-hint">Clic para cambiar la detección automática</p>
      )}
    </div>
  )
}

export default function CriteriaRow({ criterion, valueA, valueB, onChangeA, onChangeB, detectionA, detectionB }) {
  const done = valueA !== null && valueB !== null

  return (
    <article className={`criteria-row ${done ? 'row-done' : ''}`}>
      <div className="criteria-info">
        <div className="criteria-meta">
          <span className={`severity-badge sev-${criterion.severity}`}>
            {SEVERITY_LABELS[criterion.severity]}
          </span>
          <span className="criteria-masvs-id">{criterion.id}</span>
          <span
            className="criteria-source-chip"
            title={`Detección: ${SOURCE_LABEL[criterion.detectionSource]}`}
          >
            {SOURCE_ICON[criterion.detectionSource]}
          </span>
          {done && <span className="row-done-dot" />}
        </div>
        <h3 className="criteria-title">{criterion.title}</h3>
        <p className="criteria-desc">{criterion.description}</p>
        <div className="criteria-footer-row">
          <span className="criteria-aer-chip">AER: {criterion.aer}</span>
        </div>
      </div>

      <div className="criteria-evals">
        <EvalColumn
          value={valueA}
          onChange={onChangeA}
          detection={detectionA}
          label="App Segura"
          colorClass="label-a"
        />
        <EvalColumn
          value={valueB}
          onChange={onChangeB}
          detection={detectionB}
          label="App Insegura"
          colorClass="label-b"
        />
      </div>
    </article>
  )
}

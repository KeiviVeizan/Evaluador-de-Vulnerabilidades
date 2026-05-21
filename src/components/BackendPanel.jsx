import { useState } from 'react'
import { analyzeBackend } from '../analysis/backendAnalyzer'

export default function BackendPanel({ app, onAnalysisComplete }) {
  const [url,     setUrl]     = useState('')
  const [phase,   setPhase]   = useState('idle')  // idle | analyzing | done | error
  const [result,  setResult]  = useState(null)
  const [errMsg,  setErrMsg]  = useState('')

  async function handleAnalyze() {
    const trimmed = url.trim()
    if (!trimmed) return
    if (!/^https?:\/\/.+/.test(trimmed)) {
      setErrMsg('URL inválida. Debe comenzar con http:// o https://')
      setPhase('error')
      return
    }
    setPhase('analyzing')
    setErrMsg('')
    try {
      const analysis = await analyzeBackend(trimmed)
      setResult(analysis)
      setPhase('done')
      onAnalysisComplete(analysis)
    } catch (err) {
      setPhase('error')
      setErrMsg('Error al analizar el backend: ' + (err?.message ?? err))
    }
  }

  const reset = () => { setPhase('idle'); setResult(null); setErrMsg('') }

  return (
    <div
      className="backend-panel"
      style={{ '--ac': app.color, '--ac-dim': app.colorDim }}
    >
      <div className="backend-panel-head">
        <span className="backend-panel-icon">🌐</span>
        <div>
          <p className="backend-panel-title">Backend API — {app.name}</p>
          <p className="backend-panel-sub">Análisis automático de controles de red y servidor</p>
        </div>
        {phase === 'done' && (
          <button className="btn-ghost btn-sm" onClick={reset} title="Reiniciar">↩</button>
        )}
      </div>

      {/* URL input */}
      {(phase === 'idle' || phase === 'error') && (
        <div className="backend-input-row">
          <input
            className={`backend-url-input ${phase === 'error' ? 'input-error' : ''}`}
            type="url"
            value={url}
            onChange={e => { setUrl(e.target.value); if (phase === 'error') setPhase('idle') }}
            placeholder="http://localhost:3000"
            onKeyDown={e => e.key === 'Enter' && handleAnalyze()}
          />
          <button
            className="btn-primary btn-sm"
            onClick={handleAnalyze}
            disabled={!url.trim()}
            style={{ '--btn-color': app.color }}
          >
            Analizar
          </button>
        </div>
      )}

      {phase === 'error' && errMsg && (
        <p className="backend-error-msg">⚠ {errMsg}</p>
      )}

      {/* Analyzing */}
      {phase === 'analyzing' && (
        <div className="upload-analyzing">
          <div className="spinner" style={{ '--spin-color': app.color }} />
          <p className="analyzing-text">Analizando backend: {url}</p>
        </div>
      )}

      {/* Result */}
      {phase === 'done' && result && (
        <div className="backend-result">
          <div className="backend-result-badges">
            <span className="result-badge-item badge-auto">
              ⚡ {result.stats.autoDetected} detectados
            </span>
            <span className="result-badge-item badge-strings">
              🔍 {result.stats.manualCount} manuales
            </span>
          </div>
          <p className="backend-result-url">🌐 {result.baseUrl}</p>
          <ul className="backend-result-list">
            {Object.entries(result.criteria)
              .filter(([, d]) => d.result !== 'manual')
              .slice(0, 5)
              .map(([id, det]) => (
                <li key={id} className={`brl-item brl-${det.result}`}>
                  <span className="brl-icon">
                    {det.result === 'pass' ? '✓' : det.result === 'fail' ? '✗' : '⚠'}
                  </span>
                  <span className="brl-id">{id.replace('MASVS-', '')}</span>
                  <span className="brl-note">{det.note.slice(0, 60)}{det.note.length > 60 ? '…' : ''}</span>
                </li>
              ))}
          </ul>
        </div>
      )}

      {/* Idle hint */}
      {phase === 'idle' && (
        <p className="backend-hint">
          Opcional · Prueba controles NETWORK-1,3,4 · AUTH-9 · CODE-1,3,6
        </p>
      )}
    </div>
  )
}

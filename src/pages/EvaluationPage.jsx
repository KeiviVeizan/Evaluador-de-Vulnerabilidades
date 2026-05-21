import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { DOMAINS, CRITERIA } from '../data/criteria'
import { APPS } from '../data/apps'
import { useEvaluation } from '../context/EvaluationContext'
import ApkUploadPanel from '../components/ApkUploadPanel'
import BackendPanel from '../components/BackendPanel'
import CriteriaRow from '../components/CriteriaRow'

// ─── Upload Step ──────────────────────────────────────────────────────────────
function UploadStep({ onContinue }) {
  const { applyAnalysis, applyBackendAnalysis, analysisA, analysisB } = useEvaluation()
  const bothLoaded = analysisA && analysisB
  const oneLoaded  = analysisA || analysisB

  return (
    <div className="upload-step">
      <div className="upload-step-header">
        <span className="step-chip">Paso 1</span>
        <h2 className="upload-step-title">Carga los APK y configura el backend</h2>
        <p className="upload-step-desc">
          El sistema analizará automáticamente el manifiesto, permisos, configuración de red
          y cadenas en los binarios. Opcionalmente, prueba el backend de cada app.
        </p>
      </div>

      {/* APK panels */}
      <div className="upload-panels-row">
        <ApkUploadPanel
          app={APPS.A}
          onAnalysisComplete={a => applyAnalysis('A', a)}
        />
        <ApkUploadPanel
          app={APPS.B}
          onAnalysisComplete={a => applyAnalysis('B', a)}
        />
      </div>

      {/* Backend panels */}
      <div className="backend-panels-row">
        <BackendPanel
          app={APPS.A}
          onAnalysisComplete={a => applyBackendAnalysis('A', a)}
        />
        <BackendPanel
          app={APPS.B}
          onAnalysisComplete={a => applyBackendAnalysis('B', a)}
        />
      </div>

      <div className="upload-step-footer">
        {bothLoaded && (
          <div className="upload-ready-banner">
            <span>✅ Ambos APK analizados. Revisa y ajusta los criterios detectados.</span>
          </div>
        )}
        <div className="upload-footer-actions">
          <p className="upload-hint">
            {!oneLoaded   && 'Puedes continuar sin cargar APKs para evaluar manualmente.'}
            {oneLoaded && !bothLoaded && 'Un APK cargado. Puedes continuar o cargar el segundo.'}
          </p>
          <button className="btn-primary" onClick={onContinue}>
            {bothLoaded ? 'Revisar criterios →' : 'Evaluar manualmente →'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Eval Step ────────────────────────────────────────────────────────────────
function EvalStep({ onBack }) {
  const navigate = useNavigate()
  const { appA, appB, setResult, getDetection } = useEvaluation()
  const [activeDomainId, setActiveDomainId] = useState(DOMAINS[0].id)

  const activeCriteria = CRITERIA.filter(c => c.domainId === activeDomainId)
  const activeIndex    = DOMAINS.findIndex(d => d.id === activeDomainId)

  const totalEvaluated = CRITERIA.filter(c => appA[c.id] !== null && appB[c.id] !== null).length
  const progress       = Math.round((totalEvaluated / CRITERIA.length) * 100)
  const autoDetected   = CRITERIA.filter(c => appA[c.id] !== null || appB[c.id] !== null).length

  const getDomainProg = domainId => {
    const cats = CRITERIA.filter(c => c.domainId === domainId)
    const done = cats.filter(c => appA[c.id] !== null && appB[c.id] !== null).length
    const auto = cats.filter(c => {
      const dA = getDetection('A', c.id)
      const dB = getDetection('B', c.id)
      return (dA?.result && dA.result !== 'warning' && dA.result !== 'manual') ||
             (dB?.result && dB.result !== 'warning' && dB.result !== 'manual')
    }).length
    return { done, total: cats.length, auto }
  }

  const handleNav = dir => {
    const newIdx = activeIndex + dir
    if (newIdx >= 0 && newIdx < DOMAINS.length) setActiveDomainId(DOMAINS[newIdx].id)
    else if (newIdx >= DOMAINS.length) navigate('/reporte')
  }

  return (
    <div className="eval-page">
      {/* top bar */}
      <div className="eval-top-bar">
        <button className="btn-ghost btn-sm eval-back-btn" onClick={onBack}>← Volver a carga</button>
        <div className="eval-top-progress">
          <div className="eval-top-bar-fill" style={{ width: `${progress}%` }} />
        </div>
        <div className="eval-top-right">
          <span className="eval-pct-label">{totalEvaluated}/{CRITERIA.length}</span>
          {autoDetected > 0 && (
            <span className="auto-badge">⚡ {autoDetected} auto</span>
          )}
          <button className="btn-outline btn-sm" onClick={() => navigate('/reporte')}>
            Ver Reporte →
          </button>
        </div>
      </div>

      <div className="eval-layout">
        {/* sidebar */}
        <aside className="eval-sidebar">
          <p className="sidebar-heading">Dominios MASVS</p>
          {DOMAINS.map(domain => {
            const { done, total, auto } = getDomainProg(domain.id)
            const isActive   = domain.id === activeDomainId
            const isComplete = done === total
            return (
              <button
                key={domain.id}
                className={`sidebar-cat-btn ${isActive ? 'active' : ''} ${isComplete ? 'complete' : ''}`}
                onClick={() => setActiveDomainId(domain.id)}
              >
                <span className="sidebar-cat-icon">{domain.icon}</span>
                <span className="sidebar-cat-name">{domain.shortName}</span>
                <span className={`sidebar-cat-count ${isComplete ? 'complete' : ''}`}>
                  {auto > 0 && <span className="sidebar-auto-dot" title={`${auto} auto-detectados`}>⚡</span>}
                  {done}/{total}
                </span>
              </button>
            )
          })}
        </aside>

        {/* main */}
        <main className="eval-main">
          <div className="eval-main-header">
            <div className="eval-title-row">
              <span className="eval-cat-icon">{DOMAINS[activeIndex]?.icon}</span>
              <h2 className="eval-main-title">{DOMAINS[activeIndex]?.name}</h2>
              <span className="eval-cat-chip">{activeCriteria.length} controles</span>
            </div>
            <div className="eval-legend-row">
              <span className="legend-item"><span className="legend-dot dot-a" />App Segura (Security by Design)</span>
              <span className="legend-item"><span className="legend-dot dot-b" />App Insegura</span>
              <span className="legend-item"><span className="legend-dot dot-auto" />⚡ Auto-detectado</span>
            </div>
          </div>

          <div className="criteria-list">
            {activeCriteria.map(c => (
              <CriteriaRow
                key={c.id}
                criterion={c}
                valueA={appA[c.id]}
                valueB={appB[c.id]}
                onChangeA={v => setResult('A', c.id, v)}
                onChangeB={v => setResult('B', c.id, v)}
                detectionA={getDetection('A', c.id)}
                detectionB={getDetection('B', c.id)}
              />
            ))}
          </div>

          <div className="eval-nav">
            <button className="btn-outline" onClick={() => handleNav(-1)} disabled={activeIndex === 0}>
              ← Anterior
            </button>
            <span className="eval-nav-info">{activeIndex + 1} / {DOMAINS.length}</span>
            <button className="btn-primary" onClick={() => handleNav(1)}>
              {activeIndex < DOMAINS.length - 1 ? 'Siguiente →' : 'Ver Reporte →'}
            </button>
          </div>
        </main>
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────
export default function EvaluationPage() {
  const [step, setStep] = useState('upload') // 'upload' | 'eval'

  return step === 'upload'
    ? <UploadStep onContinue={() => setStep('eval')} />
    : <EvalStep   onBack={() => setStep('upload')} />
}

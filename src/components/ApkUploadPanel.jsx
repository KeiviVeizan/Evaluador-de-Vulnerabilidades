import { useState, useRef } from 'react'
import { analyzeApk } from '../analysis/apkAnalyzer'

const PERMISSION_ABBR = n => n.replace('android.permission.', '')

export default function ApkUploadPanel({ app, onAnalysisComplete }) {
  const [phase, setPhase] = useState('idle') // idle | analyzing | done | error
  const [progress, setProgress] = useState('')
  const [result, setResult] = useState(null)
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef(null)

  async function handleFile(file) {
    if (!file || !file.name.endsWith('.apk')) {
      setPhase('error')
      setProgress('Solo se aceptan archivos .apk')
      return
    }
    setPhase('analyzing')
    setProgress('Abriendo APK…')
    try {
      setProgress('Analizando AndroidManifest.xml…')
      const analysis = await analyzeApk(file)
      setResult(analysis)
      setPhase('done')
      onAnalysisComplete(analysis)
    } catch (err) {
      setPhase('error')
      setProgress('Error al analizar: ' + (err?.message ?? err))
    }
  }

  const onDrop = e => {
    e.preventDefault(); setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) handleFile(f)
  }
  const onInputChange = e => { const f = e.target.files[0]; if (f) handleFile(f) }

  return (
    <div className={`upload-panel upload-panel-${app.id.toLowerCase()}`}
         style={{ '--ac': app.color, '--ac-dim': app.colorDim }}>

      <div className="upload-panel-head">
        <span className="upload-panel-tag" style={{ color: app.color }}>
          {app.id === 'A' ? '✓' : '✗'} {app.tag}
        </span>
        <h3 className="upload-panel-title">{app.name}</h3>
        <p className="upload-panel-sub">{app.subtitle}</p>
      </div>

      {/* ── IDLE ── */}
      {phase === 'idle' && (
        <div
          className={`drop-zone ${dragging ? 'dragging' : ''}`}
          onDragOver={e => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
        >
          <div className="drop-icon">📦</div>
          <p className="drop-main">Arrastra el APK aquí</p>
          <p className="drop-sub">o haz clic para seleccionar</p>
          <span className="drop-ext">.apk</span>
          <input ref={inputRef} type="file" accept=".apk" hidden onChange={onInputChange} />
        </div>
      )}

      {/* ── ANALYZING ── */}
      {phase === 'analyzing' && (
        <div className="upload-analyzing">
          <div className="spinner" style={{ '--spin-color': app.color }} />
          <p className="analyzing-text">{progress}</p>
        </div>
      )}

      {/* ── ERROR ── */}
      {phase === 'error' && (
        <div className="upload-error">
          <span className="error-icon">⚠</span>
          <p>{progress}</p>
          <button className="btn-outline btn-sm" onClick={() => setPhase('idle')}>Reintentar</button>
        </div>
      )}

      {/* ── DONE ── */}
      {phase === 'done' && result && (
        <div className="upload-result">
          <div className="result-file-row">
            <span className="result-file-icon">📄</span>
            <div>
              <p className="result-file-name">{result.fileName}</p>
              <p className="result-file-size">{(result.fileSize / 1024 / 1024).toFixed(1)} MB · {result.stats.totalFiles} archivos</p>
            </div>
            <button className="btn-ghost btn-sm" onClick={() => { setPhase('idle'); setResult(null) }}>↩</button>
          </div>

          <div className="result-badges">
            <span className="result-badge-item badge-auto">
              ⚡ {result.stats.autoDetected} detectados
            </span>
            <span className="result-badge-item badge-strings">
              🔍 {(result.stats.stringsFound / 1000).toFixed(0)}k cadenas
            </span>
          </div>

          {result.manifest && (
            <div className="result-manifest">
              <p className="manifest-pkg">📦 {result.manifest.packageName ?? 'N/D'}</p>
              {result.manifest.debuggable === true && (
                <span className="manifest-flag flag-danger">🐛 DEBUG ACTIVO</span>
              )}
              {result.manifest.usesCleartextTraffic === true && (
                <span className="manifest-flag flag-danger">⚠ HTTP permitido</span>
              )}
              {result.manifest.hasNetworkSecurityConfig && (
                <span className="manifest-flag flag-ok">✓ NetworkSecurityConfig</span>
              )}
              {result.netSec?.certificatePinning && (
                <span className="manifest-flag flag-ok">📌 Cert. Pinning</span>
              )}
              {result.manifest.permissions.length > 0 && (
                <div className="manifest-perms">
                  <p className="perms-label">{result.manifest.permissions.length} permisos solicitados</p>
                  <div className="perms-list">
                    {result.manifest.permissions.slice(0, 8).map(p => (
                      <span key={p} className="perm-chip">{PERMISSION_ABBR(p)}</span>
                    ))}
                    {result.manifest.permissions.length > 8 && (
                      <span className="perm-chip perm-more">+{result.manifest.permissions.length - 8}</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

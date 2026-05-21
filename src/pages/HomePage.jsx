import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { APPS } from '../data/apps'
import { CRITERIA, DOMAINS } from '../data/criteria'
import { useEvaluation } from '../context/EvaluationContext'

/* ── Animated counter ─────────────────────────────────────────── */
function Counter({ value, suffix = '', decimals = 0 }) {
  const [n, setN] = useState(0)
  const ref = useRef(null)
  const started = useRef(false)

  useEffect(() => {
    const el = ref.current
    const obs = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !started.current) {
        started.current = true
        const dur = 1400
        const fps = 60
        const steps = (dur / 1000) * fps
        let step = 0
        const timer = setInterval(() => {
          step++
          const t = step / steps
          const ease = 1 - Math.pow(1 - t, 3)
          setN(parseFloat((value * ease).toFixed(decimals)))
          if (step >= steps) { setN(value); clearInterval(timer) }
        }, 1000 / fps)
      }
    }, { threshold: 0.6 })
    obs.observe(el)
    return () => obs.disconnect()
  }, [value, decimals])

  return <span ref={ref}>{decimals ? n.toFixed(decimals) : Math.floor(n)}{suffix}</span>
}

/* ── Scroll reveal hook ───────────────────────────────────────── */
function useScrollReveal(selector = '.aos') {
  useEffect(() => {
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('in'); obs.unobserve(e.target) } }),
      { threshold: 0.12 }
    )
    document.querySelectorAll(selector).forEach(el => obs.observe(el))
    return () => obs.disconnect()
  }, [selector])
}

/* ── Capabilities data ────────────────────────────────────────── */
const CAPS = [
  {
    icon: '📦',
    color: '#6366f1',
    title: 'Análisis Profundo de APK',
    desc: 'Descomprime y analiza el APK completo sin necesidad de herramientas externas ni descompilación.',
    items: ['AndroidManifest.xml (AXML binario)', 'Permisos de Android solicitados', 'network_security_config.xml', 'Cadenas en libapp.so compilado'],
    tags: ['AXML Parser', 'JSZip', 'Flutter'],
  },
  {
    icon: '⚡',
    color: '#10b981',
    title: 'Detección Automática',
    desc: 'Más de 15 criterios de seguridad se pre-rellenan automáticamente con evidencia del APK.',
    items: ['Modo debug activo (debuggable)', 'Tráfico HTTP sin cifrar', 'Certificate pinning activo', 'Algoritmos criptográficos obsoletos'],
    tags: ['Heurísticas', 'Regex', 'Manifest'],
  },
  {
    icon: '📊',
    color: '#f59e0b',
    title: 'Reporte Comparativo',
    desc: 'Genera un informe profesional con puntuaciones detalladas y checklist exportable a PDF.',
    items: ['Score de cumplimiento por app', 'Desglose por categoría', 'Checklist de 40 criterios', 'Exportación a PDF imprimible'],
    tags: ['PDF Export', 'Comparativa', 'Scoring'],
  },
]

/* ── Page ─────────────────────────────────────────────────────── */
export default function HomePage() {
  const navigate = useNavigate()
  const { reset }  = useEvaluation()
  useScrollReveal()

  const handleStart = () => { reset(); navigate('/evaluacion') }
  const criticals = CRITERIA.filter(c => c.severity === 'critical').length

  return (
    <main className="home-page">

      {/* ══ HERO ══════════════════════════════════════════════ */}
      <section className="hero-section">
        <div className="hero-bg" aria-hidden="true">
          <div className="hero-grid" />
          <div className="hero-orb hero-orb-1" />
          <div className="hero-orb hero-orb-2" />
          <div className="hero-orb hero-orb-3" />
        </div>

        <div className="hero-content">
          <span className="hero-eyebrow">
            <span className="eyebrow-dot" />
            Análisis Estático · Security by Design · Flutter / Dart
          </span>

          <h1 className="hero-h1">
            <span className="hero-h1-top">Evaluador de</span>
            <span className="hero-h1-grad">Seguridad Móvil</span>
          </h1>

          <p className="hero-p">
            Carga los <strong>APK</strong> de tus dos aplicaciones Dart y obtén un análisis
            automatizado de <strong>{CRITERIA.length} criterios de seguridad</strong>, comparando
            una app con <strong>Security by Design</strong> contra una desarrollada sin ese enfoque.
          </p>

          <div className="hero-actions">
            <button className="btn-hero-primary" onClick={handleStart}>
              <span>Iniciar Evaluación</span>
              <span className="btn-arrow-icon">→</span>
            </button>
            <a className="btn-hero-ghost" href="#como-funciona">
              Cómo funciona ↓
            </a>
          </div>
        </div>

        {/* Stats */}
        <div className="hero-stats">
          {[
            { val: CRITERIA.length,    suf: '',  label: 'Criterios de Seguridad', color: '#818cf8' },
            { val: DOMAINS.length,     suf: '',  label: 'Dominios MASVS',         color: '#34d399' },
            { val: 15,                 suf: '+', label: 'Detección Automática',   color: '#fbbf24' },
            { val: criticals,          suf: '',  label: 'Criterios Críticos',      color: '#f87171' },
          ].map(s => (
            <div key={s.label} className="hero-stat">
              <span className="hero-stat-val" style={{ color: s.color }}>
                <Counter value={s.val} />{s.suf}
              </span>
              <span className="hero-stat-label">{s.label}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ══ CAPABILITIES ══════════════════════════════════════ */}
      <section className="home-section">
        <div className="home-section-inner">
          <div className="section-label aos">Capacidades del sistema</div>
          <h2 className="section-h2 aos aos-d1">¿Qué analiza SecureEval?</h2>
          <p className="section-desc aos aos-d2">
            Un flujo de tres fases para evaluar la seguridad de tus apps sin configuración adicional.
          </p>

          <div className="caps-grid">
            {CAPS.map((cap, i) => (
              <div key={cap.title} className={`cap-card aos aos-d${i + 1}`}>
                <div className="cap-icon-wrap" style={{ '--ci': cap.color }}>
                  <span className="cap-icon">{cap.icon}</span>
                </div>
                <h3 className="cap-title">{cap.title}</h3>
                <p className="cap-desc">{cap.desc}</p>
                <ul className="cap-list">
                  {cap.items.map(item => (
                    <li key={item}>
                      <span className="cap-check" style={{ color: cap.color }}>✓</span>
                      {item}
                    </li>
                  ))}
                </ul>
                <div className="cap-tags">
                  {cap.tags.map(t => <span key={t} className="cap-tag">{t}</span>)}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ══ APPS ══════════════════════════════════════════════ */}
      <section className="home-section">
        <div className="home-section-inner">
          <div className="section-label aos">Apps bajo evaluación</div>
          <h2 className="section-h2 aos aos-d1">Dos apps, una comparativa real</h2>
          <p className="section-desc aos aos-d2">
            El evaluador analiza en paralelo ambas aplicaciones y genera métricas comparativas por criterio y categoría.
          </p>

          <div className="apps-compare-grid">
            {Object.values(APPS).map((app, i) => (
              <div
                key={app.id}
                className={`app-compare-card aos aos-d${i + 1}`}
                style={{ '--ac': app.color, '--ac-dim': app.colorDim }}
              >
                <div className="acc-badge" style={{ color: app.color, borderColor: app.borderColor }}>
                  {app.id === 'A' ? '✓' : '✗'} {app.tag}
                </div>
                <h3 className="acc-name">{app.name}</h3>
                <p className="acc-sub">{app.subtitle}</p>
                <p className="acc-desc">{app.description}</p>
                <div className="acc-divider" style={{ background: app.color }} />
                <div className="acc-criteria-count">
                  <span style={{ color: app.color }}>40</span> criterios evaluados
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ══ CATEGORIES ════════════════════════════════════════ */}
      <section className="home-section">
        <div className="home-section-inner">
          <div className="section-label aos">Cobertura de evaluación</div>
          <h2 className="section-h2 aos aos-d1">5 Dominios MASVS v2</h2>
          <p className="section-desc aos aos-d2">
            Los {CRITERIA.length} controles siguen el estándar OWASP MASVS v2 organizado en 5 dominios.
          </p>

          <div className="cats-grid">
            {DOMAINS.map((domain, i) => {
              const count    = CRITERIA.filter(c => c.domainId === domain.id).length
              const critical = CRITERIA.filter(c => c.domainId === domain.id && c.severity === 'critical').length
              const high     = CRITERIA.filter(c => c.domainId === domain.id && c.severity === 'high').length
              return (
                <div key={domain.id} className={`cat-grid-card aos aos-d${(i % 4) + 1}`}>
                  <div className="cgc-icon">{domain.icon}</div>
                  <div className="cgc-body">
                    <p className="cgc-name">{domain.name}</p>
                    <div className="cgc-pills">
                      <span className="cgc-pill">{count} controles</span>
                      {critical > 0 && <span className="cgc-pill pill-critical">{critical} críticos</span>}
                      {high > 0     && <span className="cgc-pill pill-high">{high} altos</span>}
                    </div>
                  </div>
                  <div className="cgc-bar">
                    <div className="cgc-bar-fill" style={{ width: `${(count / 11) * 100}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      {/* ══ HOW IT WORKS ══════════════════════════════════════ */}
      <section className="home-section" id="como-funciona">
        <div className="home-section-inner">
          <div className="section-label aos">Proceso de evaluación</div>
          <h2 className="section-h2 aos aos-d1">En 3 pasos</h2>

          <div className="steps-row">
            {[
              {
                n: '01', icon: '📤',
                title: 'Carga los APK',
                desc:  'Arrastra los archivos .apk de ambas aplicaciones. El sistema los descomprime y analiza automáticamente en segundos.',
              },
              {
                n: '02', icon: '🔍',
                title: 'Revisa y completa',
                desc:  'Los criterios detectables se pre-rellenan con evidencia. Completa el resto con tu evaluación manual.',
              },
              {
                n: '03', icon: '📋',
                title: 'Genera el reporte',
                desc:  'Obtén puntuaciones comparativas, desglose por categoría y un checklist exportable a PDF.',
              },
            ].map((s, i) => (
              <div key={s.n} className={`step-item aos aos-d${i + 1}`}>
                <div className="step-connector" aria-hidden="true" />
                <div className="step-num-wrap">
                  <span className="step-big-icon">{s.icon}</span>
                  <span className="step-badge">{s.n}</span>
                </div>
                <h3 className="step-title">{s.title}</h3>
                <p className="step-desc">{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ══ CTA ═══════════════════════════════════════════════ */}
      <section className="home-section home-cta-section">
        <div className="home-section-inner">
          <div className="cta-card aos">
            <div className="cta-bg" aria-hidden="true" />
            <div className="cta-content">
              <span className="cta-eyebrow">¿Listo para comenzar?</span>
              <h2 className="cta-h2">Evalúa la seguridad de<br />tus apps en minutos</h2>
              <p className="cta-desc">
                Sin instalación. Solo carga los APK y obtén tu reporte inmediatamente.
              </p>
              <button className="btn-hero-primary" onClick={handleStart}>
                <span>Iniciar Evaluación Gratis</span>
                <span className="btn-arrow-icon">→</span>
              </button>
            </div>
          </div>
        </div>
      </section>

    </main>
  )
}

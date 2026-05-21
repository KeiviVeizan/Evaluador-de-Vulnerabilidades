import { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useEvaluation } from '../context/EvaluationContext'
import { CRITERIA } from '../data/criteria'

export default function Header() {
  const location = useLocation()
  const { appA, appB } = useEvaluation()
  const [mobileOpen, setMobileOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)

  const evaluated = CRITERIA.filter(c => appA[c.id] !== null && appB[c.id] !== null).length
  const progress  = Math.round((evaluated / CRITERIA.length) * 100)
  const isEvalPage = location.pathname === '/evaluacion'

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => { setMobileOpen(false) }, [location.pathname])

  const navLinks = [
    { to: '/',          label: 'Inicio' },
    { to: '/evaluacion', label: 'Evaluación', badge: evaluated > 0 ? `${evaluated}/${CRITERIA.length}` : null },
    { to: '/reporte',   label: 'Reporte' },
  ]

  return (
    <header className={`header ${scrolled ? 'header-scrolled' : ''}`}>
      <div className="header-inner">
        {/* Brand */}
        <Link to="/" className="header-brand">
          <div className="header-brand-icon">🛡️</div>
          <div className="header-brand-text">
            <span className="header-brand-name">SecureEval</span>
            <span className="header-brand-sub">Dart / Flutter</span>
          </div>
        </Link>

        {/* Desktop nav */}
        <nav className="header-nav desktop-nav">
          {navLinks.map(l => (
            <Link
              key={l.to}
              to={l.to}
              className={`nav-link ${location.pathname === l.to ? 'active' : ''}`}
            >
              {l.label}
              {l.badge && <span className="nav-badge">{l.badge}</span>}
            </Link>
          ))}
        </nav>

        {/* Progress pill (eval page only) */}
        {isEvalPage && evaluated > 0 && (
          <div className="header-progress-pill">
            <div className="hpp-track">
              <div className="hpp-fill" style={{ width: `${progress}%` }} />
            </div>
            <span className="hpp-label">{progress}%</span>
          </div>
        )}

        {/* Desktop CTA */}
        <Link to="/evaluacion" className="header-cta desktop-only">
          Iniciar →
        </Link>

        {/* Hamburger */}
        <button
          className={`hamburger ${mobileOpen ? 'open' : ''}`}
          onClick={() => setMobileOpen(v => !v)}
          aria-label="Menú"
        >
          <span /><span /><span />
        </button>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div className="mobile-menu">
          {navLinks.map(l => (
            <Link
              key={l.to}
              to={l.to}
              className={`mobile-nav-link ${location.pathname === l.to ? 'active' : ''}`}
              onClick={() => setMobileOpen(false)}
            >
              {l.label}
              {l.badge && <span className="nav-badge">{l.badge}</span>}
            </Link>
          ))}
          <div className="mobile-menu-footer">
            <Link to="/evaluacion" className="btn-primary" onClick={() => setMobileOpen(false)}>
              Iniciar Evaluación →
            </Link>
          </div>
        </div>
      )}
    </header>
  )
}

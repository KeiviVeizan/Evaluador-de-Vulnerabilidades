// Backend security analyzer — runs from the browser against a given base URL.
// Note: requires CORS to be enabled on the target (localhost APIs typically allow this).

const TIMEOUT_MS = 8000

async function safeFetch(url, options = {}) {
  try {
    const controller = new AbortController()
    const id = setTimeout(() => controller.abort(), TIMEOUT_MS)
    const res = await fetch(url, { ...options, signal: controller.signal })
    clearTimeout(id)
    return { ok: true, res, status: res.status }
  } catch (err) {
    const msg = err?.name === 'AbortError' ? 'timeout' : (err?.message ?? 'network error')
    return { ok: false, err, msg }
  }
}

function detect(result, confidence, note, evidence = [], instruction = '') {
  return { result, confidence, note, evidence, instruction }
}

function normalizeBase(url) {
  return url.replace(/\/$/, '')
}

// ─── MASVS-NETWORK-4: HTTP Security Headers ─────────────────────────────────
async function checkNetworkHeaders(base) {
  const { ok, res } = await safeFetch(base)
  if (!ok || !res) {
    return detect('warning', 'low',
      'No se pudo conectar al backend para verificar cabeceras de seguridad.',
      ['Asegúrate de que el servidor está corriendo y tiene CORS habilitado.'])
  }

  const h = res.headers
  const checks = [
    {
      header: 'x-frame-options',
      pass: v => /DENY|SAMEORIGIN/i.test(v),
      label: 'X-Frame-Options',
      expected: 'DENY o SAMEORIGIN',
    },
    {
      header: 'x-content-type-options',
      pass: v => /nosniff/i.test(v),
      label: 'X-Content-Type-Options',
      expected: 'nosniff',
    },
    {
      header: 'strict-transport-security',
      pass: v => { const m = v?.match(/max-age=(\d+)/); return m && parseInt(m[1]) >= 31536000 },
      label: 'Strict-Transport-Security',
      expected: 'max-age ≥ 31536000',
    },
    {
      header: 'content-security-policy',
      pass: v => !!v,
      label: 'Content-Security-Policy',
      expected: 'cualquier valor presente',
    },
    {
      header: 'x-xss-protection',
      pass: v => !!v,
      label: 'X-XSS-Protection',
      expected: '1; mode=block',
    },
  ]

  let passed = 0
  const evidence = []

  for (const c of checks) {
    const val = h.get(c.header)
    if (val && c.pass(val)) {
      passed++
      evidence.push(`✓ ${c.label}: ${val}`)
    } else {
      evidence.push(`✗ ${c.label}: ${val ?? 'ausente'} (esperado: ${c.expected})`)
    }
  }

  // Penalize leaky headers
  const poweredBy = h.get('x-powered-by')
  if (poweredBy) {
    passed = Math.max(0, passed - 1)
    evidence.push(`⚠ X-Powered-By presente: "${poweredBy}" — revela tecnología del servidor`)
  }
  const acao = h.get('access-control-allow-origin')
  if (acao === '*') {
    passed = Math.max(0, passed - 1)
    evidence.push(`⚠ Access-Control-Allow-Origin: * — demasiado permisivo`)
  }

  if (passed >= 5) return detect('pass',    'high', `Cabeceras de seguridad: ${passed}/5 correctas.`, evidence)
  if (passed >= 3) return detect('warning', 'high', `Cabeceras de seguridad parciales: ${passed}/5.`, evidence)
  return              detect('fail',    'high', `Cabeceras de seguridad insuficientes: ${passed}/5.`, evidence)
}

// ─── MASVS-NETWORK-1: TLS active ─────────────────────────────────────────────
async function checkTls(base) {
  if (base.startsWith('https://')) {
    const { ok, res } = await safeFetch(base)
    if (ok && res) {
      return detect('pass', 'high',
        'El servidor responde sobre HTTPS correctamente.',
        [`URL: ${base}`, `Status: ${res.status}`])
    }
    return detect('fail', 'high',
      'La URL usa https:// pero el servidor no respondió.',
      [`URL: ${base} — verifica que el certificado sea válido`])
  }
  return detect('fail', 'high',
    'La URL usa HTTP sin cifrar. Configura TLS en el servidor.',
    [`URL: ${base}`, 'Se esperaba https://'])
}

// ─── MASVS-NETWORK-3: No insecure protocols ──────────────────────────────────
async function checkNoInsecureProtocol(base) {
  const httpUrl = base.replace(/^https?:\/\//, 'http://')
  const { ok, res } = await safeFetch(httpUrl, { redirect: 'manual' })
  if (!ok) {
    return detect('pass', 'medium',
      'La versión HTTP no responde (sin fallback inseguro detectado).',
      [`GET ${httpUrl} → sin respuesta`])
  }
  if (res.status >= 301 && res.status <= 308) {
    const loc = res.headers.get('location') ?? ''
    if (loc.startsWith('https://')) {
      return detect('pass', 'high',
        `HTTP redirige a HTTPS (${res.status} → ${loc}).`,
        [`GET ${httpUrl} → ${res.status} → ${loc}`])
    }
  }
  if (res.status === 200) {
    return detect('fail', 'high',
      `El servidor responde HTTP 200 sin redirigir a HTTPS. Protocolo inseguro activo.`,
      [`GET ${httpUrl} → ${res.status} sin redirección a HTTPS`])
  }
  return detect('warning', 'medium',
    `Respuesta HTTP inesperada (${res.status}). Verificar manualmente si hay redirección HTTPS.`,
    [`GET ${httpUrl} → ${res.status}`])
}

// ─── MASVS-AUTH-9: Protected endpoints reject unauthenticated requests ────────
async function checkProtectedEndpoints(base) {
  const candidates = [
    '/api/usuarios', '/api/users', '/api/perfil', '/api/profile',
    '/api/admin', '/api/me', '/api/dashboard', '/api/data',
  ]
  const evidence = []
  const exposed  = []

  for (const path of candidates) {
    const { ok, res } = await safeFetch(base + path)
    if (!ok) continue
    evidence.push(`GET ${path} → ${res.status}`)
    if (res.status === 200) exposed.push(path)
    if (res.status === 401 || res.status === 403) {
      // At least one protected endpoint found
    }
  }

  if (evidence.length === 0) {
    return detect('manual', 'low',
      'No se encontraron endpoints comunes. Verificar manualmente.',
      [],
      'Probar manualmente: hacer GET a endpoints de la API sin Authorization header y confirmar que responden 401 o 403.')
  }

  if (exposed.length > 0) {
    return detect('fail', 'high',
      `${exposed.length} endpoint(s) responden 200 sin autenticación.`,
      evidence)
  }

  const protected_ = evidence.filter(e => e.includes('→ 401') || e.includes('→ 403'))
  if (protected_.length > 0) {
    return detect('pass', 'high',
      'Los endpoints probados requieren autenticación (401/403).',
      evidence)
  }

  return detect('warning', 'medium',
    'No se pudo determinar el comportamiento de autenticación.',
    evidence)
}

// ─── MASVS-CODE-6: Rate limiting ─────────────────────────────────────────────
async function checkRateLimiting(base) {
  const loginPaths = ['/api/auth/login', '/auth/login', '/api/login', '/login']
  const body = JSON.stringify({ email: 'test@secureeval.test', password: 'test_rate_limit' })
  const headers = { 'Content-Type': 'application/json' }

  let workingPath = null
  for (const p of loginPaths) {
    const { ok, res } = await safeFetch(base + p, { method: 'POST', headers, body })
    if (ok && res && res.status !== 404 && res.status !== 405) {
      workingPath = p; break
    }
  }

  if (!workingPath) {
    return detect('manual', 'low',
      'No se encontró endpoint de login. Verificar manualmente.',
      [],
      'Enviar 25+ peticiones POST consecutivas al endpoint de login y verificar que alguna responda 429 Too Many Requests.')
  }

  // Send 25 concurrent POST requests
  const requests = Array.from({ length: 25 }, () =>
    safeFetch(base + workingPath, { method: 'POST', headers, body })
  )
  const responses = await Promise.all(requests)
  const statuses  = responses.map(r => r.ok ? r.status : 0)
  const has429    = statuses.some(s => s === 429)
  const evidence  = [`POST ${workingPath} × 25`, `Respuestas: ${[...new Set(statuses)].join(', ')}`]

  if (has429) {
    return detect('pass', 'high',
      'Rate limiting activo: el servidor respondió 429 después de múltiples peticiones.',
      evidence)
  }
  return detect('fail', 'high',
    'Sin rate limiting detectado: 25 peticiones de login sin ningún 429.',
    evidence)
}

// ─── MASVS-CODE-3: Errors don't expose internals ─────────────────────────────
async function checkErrorLeakage(base) {
  const path = '/api/endpoint-que-no-existe-secureeval-99999'
  const { ok, res } = await safeFetch(base + path)
  if (!ok || !res) {
    return detect('warning', 'low',
      'No se pudo verificar fuga en errores.',
      [`GET ${path} → sin respuesta`])
  }

  let body = ''
  try { body = await res.text() } catch {}

  const leakPatterns = [
    /at\s+Object\./i, /at\s+\w+\s+\(/,
    /SyntaxError|ReferenceError|TypeError/,
    /\/home\//i, /\/var\/www\//i, /C:\\Users\\/i,
    /node_modules/i, /express/i, /sequelize/i,
    /stack.*Error/is,
  ]
  const leaks = leakPatterns.filter(p => p.test(body))

  const evidence = [
    `GET ${path} → ${res.status}`,
    body.length > 0 ? `Body preview: ${body.slice(0, 200)}` : 'Body vacío',
  ]

  if (leaks.length > 0) {
    return detect('fail', 'high',
      'La respuesta de error expone información interna del servidor.',
      [...evidence, ...leaks.map(p => `Patrón detectado: ${p}`)])
  }
  if (res.status === 404 || res.status === 400) {
    return detect('pass', 'high',
      `Respuesta de error genérica (${res.status}) sin información interna.`,
      evidence)
  }
  return detect('warning', 'medium',
    `Respuesta ${res.status} — revisar manualmente el cuerpo de error.`,
    evidence)
}

// ─── MASVS-CODE-1: Input validation (basic) ──────────────────────────────────
async function checkInputValidation(base) {
  const payloads = [
    { url: `${base}/?id=%27%20OR%20%271%27%3D%271`, label: "SQL injection: id=' OR '1'='1" },
    { url: `${base}/?search=%3Cscript%3Ealert(1)%3C%2Fscript%3E`, label: 'XSS: <script>alert(1)</script>' },
  ]
  const evidence = []
  let fail = false

  for (const p of payloads) {
    const { ok, res } = await safeFetch(p.url)
    if (!ok) { evidence.push(`${p.label} → sin respuesta`); continue }
    evidence.push(`${p.label} → ${res.status}`)
    if (res.status === 500) fail = true
  }

  if (fail) {
    return detect('fail', 'medium',
      'El servidor responde 500 ante entradas maliciosas (posible inyección).',
      evidence)
  }
  const allBlocked = evidence.every(e => e.includes('→ 400') || e.includes('→ 404') || e.includes('→ 422'))
  if (allBlocked) {
    return detect('pass', 'medium',
      'El servidor rechaza entradas maliciosas con 4xx.',
      evidence)
  }
  return detect('warning', 'medium',
    'No se pudo determinar el comportamiento de validación. Verificar manualmente.',
    evidence)
}

// ─── MASVS-STORAGE-2: No sensitive data in logs (partial check) ───────────────
async function checkSensitiveDataInResponse(base) {
  const loginPaths = ['/api/auth/login', '/auth/login', '/api/login', '/login']
  const testPassword = 'contraseña_prueba_visible_secureeval'
  const body = JSON.stringify({ email: 'test@secureeval.test', password: testPassword })
  const headers = { 'Content-Type': 'application/json' }

  for (const path of loginPaths) {
    const { ok, res } = await safeFetch(base + path, { method: 'POST', headers, body })
    if (!ok || !res || res.status === 404 || res.status === 405) continue

    let responseBody = ''
    try { responseBody = await res.text() } catch {}

    const evidence = [`POST ${path} → ${res.status}`]

    if (responseBody.includes(testPassword)) {
      return detect('fail', 'high',
        'La respuesta HTTP contiene la contraseña en texto plano.',
        [...evidence, 'Contraseña visible en el cuerpo de respuesta'])
    }
    return detect('pass', 'medium',
      'La contraseña no aparece en la respuesta HTTP. Verificar logs del servidor directamente.',
      [...evidence, 'Contraseña no visible en la respuesta HTTP (verifica los logs del servidor)'],
      'Verificación adicional: revisar los logs del servidor después del login y confirmar que no se registra la contraseña.')
  }

  return detect('manual', 'low',
    'No se encontró endpoint de login para la verificación.',
    [],
    'Enviar una petición de login y revisar los logs del servidor para confirmar que la contraseña no aparece en texto plano.')
}

// ─── Manual controls (return instructions only) ──────────────────────────────
function manualControl(note, instruction) {
  return detect('manual', 'low', note, [], instruction)
}

// ─── Main export ──────────────────────────────────────────────────────────────
export async function analyzeBackend(rawUrl) {
  const base = normalizeBase(rawUrl.trim())
  const criteria = {}

  const [
    net1, net3, net4, auth9, code6, code3, code1, storage2,
  ] = await Promise.all([
    checkTls(base),
    checkNoInsecureProtocol(base),
    checkNetworkHeaders(base),
    checkProtectedEndpoints(base),
    checkRateLimiting(base),
    checkErrorLeakage(base),
    checkInputValidation(base),
    checkSensitiveDataInResponse(base),
  ])

  criteria['MASVS-NETWORK-1']  = net1
  criteria['MASVS-NETWORK-3']  = net3    // also checked from APK, backend result may override
  criteria['MASVS-NETWORK-4']  = net4
  criteria['MASVS-AUTH-9']     = auth9
  criteria['MASVS-CODE-6']     = code6
  criteria['MASVS-CODE-3']     = code3
  criteria['MASVS-CODE-1']     = code1
  criteria['MASVS-STORAGE-2']  = storage2

  // Manual controls — backend cannot verify automatically
  criteria['MASVS-AUTH-5'] = manualControl(
    'Verificación manual requerida.',
    'Envía un JWT con campo exp en el pasado y confirma que el servidor responde 401. Puedes generar un token expirado en jwt.io.'
  )
  criteria['MASVS-AUTH-7'] = manualControl(
    'Verificación manual requerida.',
    'Acceder a recursos protegidos con un usuario sin el rol requerido y confirmar respuesta 403. Ejemplo: acceder a /api/admin con rol de usuario normal.'
  )
  criteria['MASVS-AUTH-11'] = manualControl(
    'Verificación manual requerida (IDOR).',
    'Probar acceso a objetos de otro usuario cambiando el ID: GET /api/items/2 con sesión del usuario 1. Si responde 200 con datos ajenos: FAIL.'
  )
  criteria['MASVS-CODE-5'] = manualControl(
    'Verificación manual requerida.',
    'Revisar código fuente del backend: confirmar que todas las queries SQL usan $1, $2 u ORM sin concatenación directa de strings de usuario.'
  )

  const autoDetected = Object.values(criteria).filter(c => c.result !== 'manual').length
  const manualCount  = Object.values(criteria).filter(c => c.result === 'manual').length

  return {
    baseUrl: base,
    criteria,
    stats: { autoDetected, manualCount, total: Object.keys(criteria).length },
  }
}

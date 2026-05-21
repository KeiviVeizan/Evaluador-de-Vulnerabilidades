import JSZip from 'jszip'
import { parseAXML, extractManifestInfo } from './axmlParser'

// ─── helpers ──────────────────────────────────────────────────────────────────

function extractBinaryStrings(uint8Array, minLen = 6) {
  const results = []
  let cur = ''
  const limit = Math.min(uint8Array.length, 3 * 1024 * 1024) // cap at 3 MB
  for (let i = 0; i < limit; i++) {
    const c = uint8Array[i]
    if (c >= 32 && c <= 126) {
      cur += String.fromCharCode(c)
    } else {
      if (cur.length >= minLen) results.push(cur)
      cur = ''
    }
  }
  if (cur.length >= minLen) results.push(cur)
  return results
}

function parseNetworkSecurityConfig(xmlText) {
  try {
    const doc = new DOMParser().parseFromString(xmlText, 'text/xml')
    return {
      found:                   true,
      allowsCleartextInBase:   doc.querySelector('base-config[cleartextTrafficPermitted="true"]')   !== null,
      allowsCleartextInDomain: doc.querySelector('domain-config[cleartextTrafficPermitted="true"]') !== null,
      certificatePinning:      doc.querySelector('pin-set')                !== null,
      userCertificates:        doc.querySelector('certificates[src="user"]') !== null,
    }
  } catch { return { found: false } }
}

const DANGEROUS_PERMISSIONS = [
  'READ_CONTACTS', 'WRITE_CONTACTS',
  'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION',
  'RECORD_AUDIO', 'CAMERA',
  'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'MANAGE_EXTERNAL_STORAGE',
  'READ_CALL_LOG', 'WRITE_CALL_LOG',
  'READ_SMS', 'RECEIVE_SMS', 'SEND_SMS',
  'CALL_PHONE', 'READ_PHONE_STATE', 'READ_PHONE_NUMBERS',
  'USE_BIOMETRIC', 'USE_FINGERPRINT', 'GET_ACCOUNTS',
]

function detect(result, confidence, note, evidence = []) {
  return { result, confidence, note, evidence }
}

// ─── detection rules ──────────────────────────────────────────────────────────

function runRules({ manifest, netSec, strings, assets, fileList }) {
  const allText   = strings.join('\n')
  const assetText = Object.values(assets).join('\n')
  const combined  = allText + '\n' + assetText

  const hasStr = (...pats) => pats.some(p =>
    typeof p === 'string' ? combined.includes(p) : p.test(combined)
  )

  const results = {}

  /* ── MASVS-STORAGE-7: allowBackup ─────────────────────────────────────── */
  if (manifest?.allowBackup === true) {
    results['MASVS-STORAGE-7'] = detect('fail', 'high',
      'android:allowBackup="true" en AndroidManifest.xml — datos del app pueden ser respaldados.',
      ['allowBackup=true en AndroidManifest.xml'])
  } else if (manifest?.allowBackup === false) {
    results['MASVS-STORAGE-7'] = detect('pass', 'high',
      'android:allowBackup="false" explícito — datos no se exponen en backups.',
      ['allowBackup=false en AndroidManifest.xml'])
  } else if (manifest !== null) {
    // allowBackup is null/undefined → Android default depends on targetSdk
    const sdk = manifest?.targetSdk ?? 0
    if (sdk >= 31) {
      results['MASVS-STORAGE-7'] = detect('pass', 'medium',
        `targetSdk=${sdk} ≥ 31: backups requieren fullBackupContent explícito. Sin configuración = sin backup de datos de app.`,
        ['allowBackup no especificado, targetSdk ≥ 31'])
    } else {
      results['MASVS-STORAGE-7'] = detect('fail', 'medium',
        `allowBackup no especificado con targetSdk=${sdk}: valor por defecto es true en API < 31.`,
        ['allowBackup ausente en AndroidManifest.xml (default=true)'])
    }
  }

  /* ── MASVS-STORAGE-9: Secure token storage ────────────────────────────── */
  const secureStoragePats = [
    'flutter_secure_storage', 'FlutterSecureStorage',
    'EncryptedSharedPreferences', 'android.security.keystore',
  ]
  const foundSecure = secureStoragePats.filter(p => combined.includes(p))
  const spTokenPatterns = [
    /SharedPreferences[^}]{0,200}(?:token|jwt|auth|session)/is,
    /(?:token|jwt|auth|session)[^}]{0,200}SharedPreferences/is,
  ]
  const spWithToken = spTokenPatterns.some(p => p.test(combined))

  if (foundSecure.length > 0 && !spWithToken) {
    results['MASVS-STORAGE-9'] = detect('pass', 'medium',
      'Uso de almacenamiento seguro detectado (flutter_secure_storage / Keystore).',
      foundSecure.map(p => `Encontrado: ${p}`))
  } else if (spWithToken) {
    results['MASVS-STORAGE-9'] = detect('fail', 'medium',
      'Posible almacenamiento de tokens en SharedPreferences (no cifrado).',
      [
        ...foundSecure.map(p => `Seguro detectado: ${p}`),
        'SharedPreferences cerca de token/jwt/auth',
      ])
  } else {
    results['MASVS-STORAGE-9'] = detect('fail', 'low',
      'No se detectó flutter_secure_storage ni Keystore para almacenamiento de credenciales.',
      ['Sin referencias a flutter_secure_storage o android.security.keystore'])
  }

  /* ── MASVS-CRYPTO-4: No obsolete algorithms ───────────────────────────── */
  const obsolete = ['MD5', 'SHA1', 'SHA-1', ' DES/', '/DES', '3DES', 'RC4', 'RC2', 'Blowfish', 'AES/ECB']
  const foundObs  = obsolete.filter(p => combined.includes(p))
  if (foundObs.length > 0) {
    results['MASVS-CRYPTO-4'] = detect('fail', 'medium',
      'Algoritmos criptográficos obsoletos detectados en el código.',
      foundObs.map(a => `Encontrado: "${a}"`))
  } else {
    results['MASVS-CRYPTO-4'] = detect('pass', 'medium',
      'No se detectaron algoritmos obsoletos (MD5, SHA-1, DES, RC4, AES/ECB).',
      ['Sin patrones de algoritmos criptográficos obsoletos'])
  }

  /* ── MASVS-CRYPTO-1: Strong crypto ───────────────────────────────────── */
  const goodModes  = ['AES/GCM', 'AES/CBC', 'AES-256', 'AES-128', 'ChaCha20', 'ECDSA', 'RSA']
  const foundGood  = goodModes.filter(p => combined.includes(p))
  const hasEcb     = combined.includes('AES/ECB') || combined.includes('AES_ECB')
  if (hasEcb) {
    results['MASVS-CRYPTO-1'] = detect('fail', 'medium',
      'Modo AES/ECB detectado — modo de operación inseguro.',
      ['AES/ECB encontrado en binarios'])
  } else if (foundGood.length > 0) {
    results['MASVS-CRYPTO-1'] = detect('pass', 'low',
      'Algoritmos criptográficos fuertes detectados.',
      foundGood.map(a => `Encontrado: ${a}`))
  }

  /* ── MASVS-CRYPTO-2: Proven implementations ──────────────────────────── */
  const cryptoLibs = [
    'pointycastle', 'cryptography', 'encrypt', 'dart:convert',
    'javax.crypto', 'android.security', 'KeyGenerator',
  ]
  const foundLibs = cryptoLibs.filter(p => combined.includes(p))
  if (foundLibs.length > 0) {
    results['MASVS-CRYPTO-2'] = detect('pass', 'low',
      'Librerías criptográficas estándar detectadas.',
      foundLibs.map(p => `Encontrado: ${p}`))
  }

  /* ── MASVS-CRYPTO-3: Secure RNG ──────────────────────────────────────── */
  const rngPats = ['Random.secure', 'SecureRandom', 'cryptoRandomBytes', 'generateSecureToken']
  const foundRng = rngPats.filter(p => combined.includes(p))
  if (foundRng.length > 0) {
    results['MASVS-CRYPTO-3'] = detect('pass', 'low',
      'Generación segura de aleatoriedad (CSPRNG) detectada.',
      foundRng.map(p => `Encontrado: ${p}`))
  } else if (combined.includes('math.random') || combined.includes('Random()')) {
    results['MASVS-CRYPTO-3'] = detect('fail', 'medium',
      'Uso de Random() no seguro detectado. Usar Random.secure() para criptografía.',
      ['Random() encontrado — no es criptográficamente seguro'])
  }

  /* ── MASVS-CODE-7: No hardcoded secrets ──────────────────────────────── */
  const secretPatterns = [
    { re: /(password|passwd|pwd|secret|api_key|apikey|private_key|auth_key)\s*[=:]\s*["'][^"']{6,}["']/i,          label: 'Credencial hardcodeada (key=value)' },
    { re: /(?:Bearer|Token)\s+[a-zA-Z0-9._\-]{20,}/,                                                               label: 'Bearer token en código' },
    { re: /AKIA[0-9A-Z]{16}/,                                                                                       label: 'AWS Access Key detectada' },
    { re: /sk_(?:live|test)_[a-zA-Z0-9]{24,}/,                                                                     label: 'Stripe secret key detectada' },
    { re: /[a-zA-Z0-9+/]{40,}={0,2}(?=\s|["']|$)/,                                                                label: 'Posible clave en Base64 larga' },
  ]
  const foundSecrets = secretPatterns
    .filter(({ re }) => re.test(combined))
    .map(({ label }) => label)

  if (foundSecrets.length > 0) {
    results['MASVS-CODE-7'] = detect('fail', 'medium',
      'Posibles secretos hardcodeados detectados en el APK.',
      foundSecrets)
  } else {
    results['MASVS-CODE-7'] = detect('pass', 'medium',
      'No se detectaron patrones de credenciales hardcodeadas.',
      ['Sin patrones de API keys, tokens o passwords hardcodeados'])
  }

  /* ── MASVS-CODE-10: Not debuggable ───────────────────────────────────── */
  if (manifest?.debuggable === true) {
    results['MASVS-CODE-10'] = detect('fail', 'high',
      'android:debuggable="true" — la app puede ser depurada en producción.',
      ['android:debuggable="true" en AndroidManifest.xml'])
  } else {
    const val = manifest?.debuggable === false ? 'android:debuggable="false" explícito.' : 'Atributo debuggable ausente (valor por defecto: false).'
    results['MASVS-CODE-10'] = detect('pass', 'high', val, ['Sin modo debug activo en producción'])
  }

  /* ── MASVS-NETWORK-2: Cert validation not bypassed ───────────────────── */
  const bypassPats = [
    'trustAllCerts', 'TrustAllCerts', 'ALLOW_ALL_HOSTNAME_VERIFIER',
    'allowAllHostname', 'ignoreSSL', 'onReceivedSslError',
    'checkServerTrusted',
  ]
  const foundBypass = bypassPats.filter(p => combined.includes(p))
  if (netSec?.userCertificates) {
    results['MASVS-NETWORK-2'] = detect('fail', 'medium',
      'network_security_config.xml confía en certificados del usuario (MITM posible).',
      ['<certificates src="user"> encontrado en network_security_config.xml'])
  } else if (foundBypass.length > 0) {
    results['MASVS-NETWORK-2'] = detect('fail', 'medium',
      'Patrones de bypass de validación SSL detectados.',
      foundBypass.map(p => `Encontrado: "${p}"`))
  } else {
    results['MASVS-NETWORK-2'] = detect('pass', 'medium',
      'Sin patrones de bypass SSL detectados.',
      ['Sin trustAllCerts, ALLOW_ALL_HOSTNAME ni overrides de checkServerTrusted'])
  }

  /* ── MASVS-NETWORK-3: No cleartext traffic ───────────────────────────── */
  if (manifest?.usesCleartextTraffic === true) {
    results['MASVS-NETWORK-3'] = detect('fail', 'high',
      'android:usesCleartextTraffic="true" — HTTP sin cifrar está permitido.',
      ['usesCleartextTraffic=true en AndroidManifest.xml'])
  } else if (manifest?.usesCleartextTraffic === false) {
    results['MASVS-NETWORK-3'] = detect('pass', 'high',
      'android:usesCleartextTraffic="false" — solo HTTPS permitido.',
      ['usesCleartextTraffic=false en AndroidManifest.xml'])
  } else if (netSec?.found) {
    const allowsHttp = netSec.allowsCleartextInBase || netSec.allowsCleartextInDomain
    results['MASVS-NETWORK-3'] = detect(
      allowsHttp ? 'fail' : 'pass', 'medium',
      allowsHttp
        ? 'network_security_config.xml permite tráfico en texto claro.'
        : 'network_security_config.xml sin cleartext explícito.',
      ['res/xml/network_security_config.xml encontrado']
    )
  } else {
    results['MASVS-NETWORK-3'] = detect('warning', 'low',
      'No se pudo determinar la política de tráfico. Verificar manualmente.',
      [])
  }

  /* ── MASVS-CODE-4: Logs without sensitive data ───────────────────────── */
  const logSensitivePats = [
    /(?:print|debugPrint|log\.|logger\.)\s*\([^)]*(?:password|passwd|token|secret|jwt|auth)[^)]*\)/i,
    /(?:print|debugPrint)\s*\([^)]*\$(?:password|passwd|token|secret)\b/i,
  ]
  const foundLogLeak = logSensitivePats.some(p => p.test(assetText))
  if (foundLogLeak) {
    results['MASVS-CODE-4'] = detect('fail', 'medium',
      'Posibles registros de datos sensibles en logs detectados.',
      ['print()/debugPrint() con referencias a password/token/secret'])
  } else {
    results['MASVS-CODE-4'] = detect('pass', 'low',
      'Sin patrones de logging de datos sensibles detectados en assets.',
      [])
  }

  /* ── MASVS-CODE-2 / MASVS-CODE-8: Dependencies via pubspec ──────────── */
  const pubspecContent = assets['pubspec.yaml'] ?? assets['assets/flutter_assets/pubspec.yaml'] ?? ''
  if (pubspecContent.length > 10) {
    const depLines = pubspecContent.split('\n').filter(l => /^\s+\w+:/.test(l))
    const evidence = depLines.slice(0, 10).map(l => l.trim())
    results['MASVS-CODE-2'] = detect('warning', 'medium',
      `pubspec.yaml encontrado con ${depLines.length} dependencias. Verificar CVEs manualmente.`,
      evidence)
    results['MASVS-CODE-8'] = detect('warning', 'medium',
      `${depLines.length} dependencias detectadas. Ejecutar "flutter pub outdated" para verificar actualizaciones.`,
      evidence)
  }

  return results
}

// ─── main export ──────────────────────────────────────────────────────────────

export async function analyzeApk(file) {
  const zip      = await JSZip.loadAsync(file)
  const fileList = Object.keys(zip.files)

  // 1 — AndroidManifest.xml (binary AXML)
  let manifest = null
  try {
    const raw = await zip.file('AndroidManifest.xml')?.async('uint8array')
    if (raw) manifest = extractManifestInfo(parseAXML(raw))
  } catch {}

  // 2 — network_security_config.xml (plain XML)
  let netSec = { found: false }
  try {
    const xmlFile = zip.file('res/xml/network_security_config.xml') ||
                    zip.file('assets/network_security_config.xml')
    if (xmlFile) {
      const text = await xmlFile.async('string')
      netSec = parseNetworkSecurityConfig(text)
    }
  } catch {}

  // 3 — Collect strings: text assets + binaries
  const strings = []
  const assets  = {}

  for (const [path, entry] of Object.entries(zip.files)) {
    if (entry.dir) continue
    try {
      if (/\.(json|xml|yaml|yml|txt|properties|dart|java|kt|gradle)$/i.test(path) ||
          path.startsWith('assets/flutter_assets/')) {
        const text = await entry.async('string')
        assets[path] = text
        strings.push(...text.split(/\s+/).filter(t => t.length >= 4))
      } else if (/\.so$/i.test(path)) {
        const data = await entry.async('uint8array')
        strings.push(...extractBinaryStrings(data, 6))
      }
    } catch {}
  }

  // 4 — Run detection rules
  const criteria = runRules({ manifest, netSec, strings, assets, fileList })

  // 5 — Dangerous permissions (informative, not mapped to a single criterion)
  const perms     = manifest?.permissions ?? []
  const dangerous = perms.filter(p => DANGEROUS_PERMISSIONS.some(d => p.includes(d)))

  return {
    fileName:  file.name,
    fileSize:  file.size,
    manifest,
    netSec,
    criteria,
    dangerousPermissions: dangerous,
    stats: {
      totalFiles:   fileList.length,
      stringsFound: strings.length,
      autoDetected: Object.keys(criteria).length,
    },
  }
}

export const DOMAINS = [
  { id: 'STORAGE', name: 'Almacenamiento de Datos',          icon: '💾', shortName: 'Storage'  },
  { id: 'CRYPTO',  name: 'Criptografía',                      icon: '🔑', shortName: 'Crypto'   },
  { id: 'AUTH',    name: 'Autenticación y Autorización',      icon: '🔐', shortName: 'Auth'     },
  { id: 'NETWORK', name: 'Comunicaciones de Red',             icon: '🌐', shortName: 'Network'  },
  { id: 'CODE',    name: 'Calidad y Resiliencia del Código',  icon: '⚙️', shortName: 'Code'     },
]

export const SEVERITY_LABELS = {
  critical: 'Crítico',
  high:     'Alto',
  medium:   'Medio',
  low:      'Bajo',
}

// detectionSource: 'apk' | 'backend' | 'manual'
export const CRITERIA = [
  /* ── STORAGE (9) ─────────────────────────────────────────────────── */
  {
    id: 'MASVS-STORAGE-1', domainId: 'STORAGE', severity: 'high',
    aer: 'AER-04', autoDetectable: false, detectionSource: 'manual',
    title: 'Los datos sensibles no se almacenan en texto plano en el dispositivo',
    description: 'Contraseñas, tokens y PII están cifrados en reposo; no se guardan en archivos de texto plano ni bases de datos sin cifrar.',
  },
  {
    id: 'MASVS-STORAGE-2', domainId: 'STORAGE', severity: 'high',
    aer: 'AER-07', autoDetectable: true, detectionSource: 'backend',
    title: 'No se almacenan datos sensibles en logs del sistema',
    description: 'Los registros de la aplicación no contienen contraseñas, tokens de sesión ni información personal identificable (PII).',
  },
  {
    id: 'MASVS-STORAGE-3', domainId: 'STORAGE', severity: 'high',
    aer: 'AER-04', autoDetectable: false, detectionSource: 'manual',
    title: 'No se comparten datos sensibles con terceros sin consentimiento',
    description: 'La app no envía datos del usuario a SDKs de analítica, publicidad u otros servicios de terceros sin consentimiento explícito.',
  },
  {
    id: 'MASVS-STORAGE-4', domainId: 'STORAGE', severity: 'medium',
    aer: 'AER-04', autoDetectable: false, detectionSource: 'manual',
    title: 'El teclado no cachea datos sensibles introducidos por el usuario',
    description: 'Los campos de contraseña y datos sensibles tienen autocompletado y corrección desactivados para evitar caché del teclado.',
  },
  {
    id: 'MASVS-STORAGE-5', domainId: 'STORAGE', severity: 'high',
    aer: 'AER-04', autoDetectable: false, detectionSource: 'manual',
    title: 'Los datos sensibles no se exponen mediante IPC',
    description: 'Los mecanismos de comunicación entre procesos (Intents, ContentProviders) no exponen datos sensibles a otras apps.',
  },
  {
    id: 'MASVS-STORAGE-6', domainId: 'STORAGE', severity: 'high',
    aer: 'AER-04', autoDetectable: false, detectionSource: 'manual',
    title: 'No se exponen datos sensibles en la interfaz de usuario',
    description: 'Contraseñas y datos sensibles se ocultan en la UI; las capturas de pantalla están bloqueadas en pantallas con información crítica.',
  },
  {
    id: 'MASVS-STORAGE-7', domainId: 'STORAGE', severity: 'high',
    aer: 'AER-04', autoDetectable: true, detectionSource: 'apk',
    title: 'Los datos sensibles no se exponen a través de backups',
    description: 'El atributo android:allowBackup está en false, o los datos sensibles están excluidos explícitamente de los backups de Android.',
  },
  {
    id: 'MASVS-STORAGE-8', domainId: 'STORAGE', severity: 'medium',
    aer: 'AER-04', autoDetectable: false, detectionSource: 'manual',
    title: 'Los datos sensibles se eliminan de la memoria cuando ya no son necesarios',
    description: 'Contraseñas, claves y tokens son sobreescritos en memoria cuando ya no se necesitan para reducir exposición en memory dumps.',
  },
  {
    id: 'MASVS-STORAGE-9', domainId: 'STORAGE', severity: 'critical',
    aer: 'AER-04', autoDetectable: true, detectionSource: 'apk',
    title: 'Los tokens de sesión se almacenan en almacenamiento seguro nativo',
    description: 'Tokens JWT, cookies de sesión y credenciales se guardan usando flutter_secure_storage, Keychain (iOS) o Keystore (Android).',
  },

  /* ── CRYPTO (4) ───────────────────────────────────────────────────── */
  {
    id: 'MASVS-CRYPTO-1', domainId: 'CRYPTO', severity: 'critical',
    aer: 'AER-03', autoDetectable: true, detectionSource: 'apk',
    title: 'La aplicación usa criptografía fuerte y actualizada',
    description: 'Se emplean AES-256-GCM, RSA-2048 o superiores; no se usan tamaños de clave inseguros ni modos de operación vulnerables como ECB.',
  },
  {
    id: 'MASVS-CRYPTO-2', domainId: 'CRYPTO', severity: 'critical',
    aer: 'AER-03', autoDetectable: true, detectionSource: 'apk',
    title: 'La aplicación usa implementaciones probadas de primitivas criptográficas',
    description: 'Se usan librerías criptográficas estándar del SO o reconocidas (pointycastle, cryptography); no se implementa criptografía propia.',
  },
  {
    id: 'MASVS-CRYPTO-3', domainId: 'CRYPTO', severity: 'high',
    aer: 'AER-03', autoDetectable: true, detectionSource: 'apk',
    title: 'La aplicación usa criptografía aleatoria con entropía suficiente',
    description: 'Se usa un CSPRNG (Random.secure() en Dart) para generar tokens, sales y vectores de inicialización; no se usa math.random().',
  },
  {
    id: 'MASVS-CRYPTO-4', domainId: 'CRYPTO', severity: 'critical',
    aer: 'AER-03', autoDetectable: true, detectionSource: 'apk',
    title: 'No se usan protocolos o algoritmos criptográficos obsoletos',
    description: 'No se utilizan MD5, SHA-1, DES, 3DES, RC4 ni modos ECB en ningún contexto de seguridad de la aplicación.',
  },

  /* ── AUTH (11) ────────────────────────────────────────────────────── */
  {
    id: 'MASVS-AUTH-1', domainId: 'AUTH', severity: 'critical',
    aer: 'AER-01', autoDetectable: false, detectionSource: 'manual',
    title: 'La aplicación usa mecanismos de autenticación robustos',
    description: 'La autenticación emplea protocolos estándar como OAuth 2.0, OpenID Connect o JWT con validación completa de firma y claims.',
  },
  {
    id: 'MASVS-AUTH-2', domainId: 'AUTH', severity: 'critical',
    aer: 'AER-01', autoDetectable: false, detectionSource: 'manual',
    title: 'Las credenciales se transmiten y almacenan de forma segura',
    description: 'Las contraseñas se transmiten solo sobre HTTPS y se almacenan hasheadas con bcrypt, Argon2 o PBKDF2 con salt único.',
  },
  {
    id: 'MASVS-AUTH-3', domainId: 'AUTH', severity: 'high',
    aer: 'AER-01', autoDetectable: false, detectionSource: 'manual',
    title: 'La aplicación implementa políticas de contraseña segura',
    description: 'Se exige mínimo 8 caracteres con combinación de mayúsculas, minúsculas, números y caracteres especiales.',
  },
  {
    id: 'MASVS-AUTH-4', domainId: 'AUTH', severity: 'high',
    aer: 'AER-01', autoDetectable: false, detectionSource: 'manual',
    title: 'La sesión se invalida correctamente al cerrar sesión',
    description: 'Al hacer logout, el token es invalidado en el servidor y eliminado del almacenamiento local del dispositivo.',
  },
  {
    id: 'MASVS-AUTH-5', domainId: 'AUTH', severity: 'high',
    aer: 'AER-01', autoDetectable: true, detectionSource: 'backend',
    title: 'Las sesiones tienen tiempo de expiración configurado',
    description: 'Los tokens tienen campo exp (JWT) o equivalente con tiempo de vida máximo definido; tokens expirados son rechazados con 401.',
  },
  {
    id: 'MASVS-AUTH-6', domainId: 'AUTH', severity: 'high',
    aer: 'AER-01', autoDetectable: false, detectionSource: 'manual',
    title: 'La aplicación implementa control de intentos de autenticación fallidos',
    description: 'Después de N intentos fallidos se bloquea la cuenta, se introduce un delay progresivo o se requiere CAPTCHA.',
  },
  {
    id: 'MASVS-AUTH-7', domainId: 'AUTH', severity: 'critical',
    aer: 'AER-02', autoDetectable: true, detectionSource: 'backend',
    title: 'La autorización se verifica en el servidor en cada solicitud',
    description: 'Cada endpoint verifica activamente que el usuario autenticado tiene permisos para la operación solicitada.',
  },
  {
    id: 'MASVS-AUTH-8', domainId: 'AUTH', severity: 'critical',
    aer: 'AER-02', autoDetectable: false, detectionSource: 'manual',
    title: 'Los roles y permisos se cargan desde el servidor, no del token',
    description: 'Los permisos de acceso se consultan en tiempo real en la base de datos; no se confía únicamente en los claims del JWT.',
  },
  {
    id: 'MASVS-AUTH-9', domainId: 'AUTH', severity: 'critical',
    aer: 'AER-01', autoDetectable: true, detectionSource: 'backend',
    title: 'Los endpoints protegidos rechazan solicitudes sin autenticación válida',
    description: 'Los recursos que requieren autenticación responden con 401/403 cuando se acceden sin token o con token inválido.',
  },
  {
    id: 'MASVS-AUTH-10', domainId: 'AUTH', severity: 'high',
    aer: 'AER-01', autoDetectable: false, detectionSource: 'manual',
    title: 'Los tokens de refresco se rotan e invalidan correctamente',
    description: 'Al usar un refresh token para obtener un nuevo access token, el anterior refresh token se invalida para prevenir reutilización.',
  },
  {
    id: 'MASVS-AUTH-11', domainId: 'AUTH', severity: 'critical',
    aer: 'AER-02', autoDetectable: true, detectionSource: 'backend',
    title: 'La aplicación implementa control de acceso a nivel de objeto',
    description: 'Se verifica que el usuario tiene acceso al objeto específico (IDOR protection); no solo que está autenticado.',
  },

  /* ── NETWORK (5) ──────────────────────────────────────────────────── */
  {
    id: 'MASVS-NETWORK-1', domainId: 'NETWORK', severity: 'critical',
    aer: 'AER-06', autoDetectable: true, detectionSource: 'backend',
    title: 'Los datos se transmiten cifrados usando TLS',
    description: 'Toda comunicación de red usa TLS 1.2 o superior; no hay fallback a HTTP en texto plano para datos sensibles.',
  },
  {
    id: 'MASVS-NETWORK-2', domainId: 'NETWORK', severity: 'critical',
    aer: 'AER-06', autoDetectable: true, detectionSource: 'apk',
    title: 'Los certificados TLS se validan correctamente',
    description: 'La app verifica la cadena de confianza, el nombre de dominio y la vigencia del certificado del servidor; no ignora errores TLS.',
  },
  {
    id: 'MASVS-NETWORK-3', domainId: 'NETWORK', severity: 'critical',
    aer: 'AER-06', autoDetectable: true, detectionSource: 'apk',
    title: 'La aplicación no permite conexiones a través de protocolos inseguros',
    description: 'usesCleartextTraffic=false y no hay configuración de red que permita HTTP sin cifrar; el servidor redirige HTTP a HTTPS.',
  },
  {
    id: 'MASVS-NETWORK-4', domainId: 'NETWORK', severity: 'high',
    aer: 'AER-06', autoDetectable: true, detectionSource: 'backend',
    title: 'Las cabeceras de seguridad HTTP están correctamente configuradas',
    description: 'El servidor incluye X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options, CSP y no expone X-Powered-By.',
  },
  {
    id: 'MASVS-NETWORK-5', domainId: 'NETWORK', severity: 'high',
    aer: 'AER-07', autoDetectable: false, detectionSource: 'manual',
    title: 'No se expone información sensible en URLs o parámetros de consulta',
    description: 'Tokens de sesión, contraseñas ni datos sensibles se transmiten en query strings de URL ni en path parameters.',
  },

  /* ── CODE (11) ────────────────────────────────────────────────────── */
  {
    id: 'MASVS-CODE-1', domainId: 'CODE', severity: 'critical',
    aer: 'AER-05', autoDetectable: true, detectionSource: 'backend',
    title: 'La aplicación valida y sanitiza todas las entradas del usuario',
    description: 'Toda entrada de usuario es validada en el servidor contra un esquema estricto; se rechazan entradas malformadas o inesperadas.',
  },
  {
    id: 'MASVS-CODE-2', domainId: 'CODE', severity: 'high',
    aer: 'AER-05', autoDetectable: true, detectionSource: 'apk',
    title: 'No se usan componentes con vulnerabilidades conocidas',
    description: 'Las dependencias no tienen CVEs conocidos no parcheados; se usa auditoría de seguridad en el pipeline de CI/CD.',
  },
  {
    id: 'MASVS-CODE-3', domainId: 'CODE', severity: 'high',
    aer: 'AER-07', autoDetectable: true, detectionSource: 'backend',
    title: 'La aplicación no expone información sensible en mensajes de error',
    description: 'Los errores muestran mensajes genéricos al usuario; stack traces, versiones y rutas de sistema solo en logs internos.',
  },
  {
    id: 'MASVS-CODE-4', domainId: 'CODE', severity: 'high',
    aer: 'AER-07', autoDetectable: true, detectionSource: 'apk',
    title: 'Los logs no contienen datos sensibles',
    description: 'El sistema de logging excluye contraseñas, tokens, números de tarjeta y cualquier PII de los registros de la aplicación.',
  },
  {
    id: 'MASVS-CODE-5', domainId: 'CODE', severity: 'critical',
    aer: 'AER-05', autoDetectable: false, detectionSource: 'manual',
    title: 'Las consultas a la base de datos usan parámetros posicionados',
    description: 'Todas las queries SQL usan prepared statements o un ORM con parámetros posicionados; no hay concatenación con input de usuario.',
  },
  {
    id: 'MASVS-CODE-6', domainId: 'CODE', severity: 'high',
    aer: 'AER-05', autoDetectable: true, detectionSource: 'backend',
    title: 'La aplicación implementa rate limiting en endpoints críticos',
    description: 'Los endpoints de autenticación, registro y recuperación de contraseña limitan el número de solicitudes por tiempo e IP.',
  },
  {
    id: 'MASVS-CODE-7', domainId: 'CODE', severity: 'critical',
    aer: 'AER-05', autoDetectable: true, detectionSource: 'apk',
    title: 'Los secretos no están hardcodeados en el código fuente',
    description: 'Claves API, tokens, contraseñas y claves criptográficas no están embebidos en el código fuente o en los binarios de la app.',
  },
  {
    id: 'MASVS-CODE-8', domainId: 'CODE', severity: 'high',
    aer: 'AER-05', autoDetectable: true, detectionSource: 'apk',
    title: 'Las dependencias están actualizadas y sin vulnerabilidades conocidas',
    description: 'El pubspec.yaml usa versiones actuales de paquetes; se revisan periódicamente con herramientas de análisis de seguridad.',
  },
  {
    id: 'MASVS-CODE-9', domainId: 'CODE', severity: 'medium',
    aer: 'AER-07', autoDetectable: false, detectionSource: 'manual',
    title: 'La aplicación implementa manejo seguro de errores',
    description: 'Las excepciones son capturadas y manejadas de forma controlada; no hay crash handlers que expongan información sensible.',
  },
  {
    id: 'MASVS-CODE-10', domainId: 'CODE', severity: 'high',
    aer: 'AER-05', autoDetectable: true, detectionSource: 'apk',
    title: 'El código no contiene funcionalidad de depuración en producción',
    description: 'El APK de producción tiene android:debuggable=false; no hay interfaces de depuración expuestas en el build de release.',
  },
  {
    id: 'MASVS-CODE-11', domainId: 'CODE', severity: 'high',
    aer: 'AER-08', autoDetectable: false, detectionSource: 'manual',
    title: 'La aplicación registra eventos de seguridad en auditoría inmutable',
    description: 'Los eventos de seguridad (login, logout, errores de autorización) se registran en un sistema de auditoría que no puede ser modificado.',
  },
]

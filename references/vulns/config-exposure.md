# Configuración insegura y exposición de información (Security Misconfiguration / Information Exposure)

| Clasificación | |
|---|---|
| CWE | CWE-200 — Exposición de información sensible · relacionados: CWE-209 (errores con información sensible), CWE-489 (código de depuración activo), CWE-530 (copias de seguridad expuestas), CWE-538 (información sensible en ficheros accesibles), CWE-548 (listado de directorios), CWE-1392 (credenciales por defecto), CWE-693 (fallo de mecanismo de protección: cabeceras), CWE-326/327 (cifrado débil), CWE-1395 (componente de terceros vulnerable), CWE-540/798 (secretos en código), CWE-749 (método peligroso expuesto) |
| OWASP Top 10:2025 | A02 — Security Misconfiguration · A03 — Software Supply Chain Failures (componentes) · A04 — Cryptographic Failures (TLS) · A10 — Mishandling of Exceptional Conditions (errores verbosos) |
| OWASP API Top 10:2023 | API8:2023 Security Misconfiguration · API9:2023 Improper Inventory Management (documentación y versiones expuestas) |
| WSTG | WSTG-CONF-01…14 (04 copias, 05 interfaces de administración, 06 métodos HTTP, 07 HSTS, 10 subdomain takeover, 11 cloud storage, 12 CSP, 14 otras cabeceras) · WSTG-INFO-02/03/05 · WSTG-ERRH-01 · WSTG-CRYP-01 · WSTG-ATHN-02 |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3–4. Detección y explotación por subproblema: 4.1 cabeceras · 4.2 TLS · 4.3 errores verbosos · 4.4 ficheros y repositorios expuestos · 4.5 consolas y endpoints de depuración · 4.6 paneles y credenciales por defecto · 4.7 listado de directorios · 4.8 almacenamiento cloud · 4.9 subdomain takeover · 4.10 componentes vulnerables · 4.11 secretos en JavaScript · 4.12 métodos HTTP · 4.13 robots, sitemap y security.txt · 5. Evasión · 6. Encadenamiento · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

Una **configuración insegura** es cualquier ajuste del servidor, framework, nube o despliegue que deja más superficie o información de la necesaria: modo de depuración en producción, ficheros que no debían publicarse, servicios con credenciales de fábrica, almacenamiento público, TLS obsoleto o componentes sin parchear. Ocurre por valores por defecto pensados para desarrollo, despliegues que copian el directorio entero (incluido `.git` o `.env`), falta de inventario (subdominios y buckets olvidados) y ausencia de *hardening* (endurecimiento: eliminar todo lo que no hace falta).

El criterio para reportar es el **impacto demostrado**: una cabecera ausente o un banner con versión son, casi siempre, informativos; un `.env` con la contraseña de la base de datos o una consola de depuración que ejecuta código son críticos. La mayoría de estos hallazgos valen sobre todo como **pivote** hacia otra vulnerabilidad.

## 2. Dónde buscar (señales del reconocimiento)

- Cabeceras `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`; cookies que delatan framework (`laravel_session`, `JSESSIONID`, `PHPSESSID`, `csrftoken`, `connect.sid`).
- Páginas de error por defecto (Whitelabel Error Page de Spring, pantalla amarilla de ASP.NET, Werkzeug, Ignition, Django "Page not found" con patrones de URL).
- Comentarios `sourceMappingURL` en JS, rutas de API y nombres de buckets en el código cliente, `robots.txt` y `sitemap.xml`.
- Subdominios de desarrollo (`dev`, `staging`, `old`, `test`, `admin`, `jenkins`, `grafana`) y registros DNS `CNAME` a servicios de terceros.
- Puertos alternativos (8080, 8443, 8081, 9090, 9200, 5601, 15672, 2375) en alcance.

**Descubrimiento de contenido** (base para 4.4–4.7):

```bash
ffuf -u https://t/FUZZ -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -mc all -fc 404 -ac -t 20
ffuf -u https://t/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -e .bak,.old,.zip,.swp,~ -ac
nuclei -u https://t -tags exposure,misconfig,config -rl 20
```

## 3–4. Detección y explotación por subproblema

### 4.1 Cabeceras de seguridad

```bash
curl -skI https://t/ ; curl -skI https://t/login ; curl -skI https://t/api/me -H 'Cookie: ...'
```

| Cabecera | Valor recomendable | Cuándo es hallazgo y no solo informativo |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (+ `preload`) | Sitio con login accesible también por HTTP o sin redirección: riesgo real de interceptación (baja) |
| `Content-Security-Policy` | Política restrictiva sin `unsafe-inline`/`unsafe-eval` ni comodines amplios | Solo como agravante de un XSS (ver `vulns/xss.md`); analízala con CSP Evaluator |
| `X-Frame-Options` / `frame-ancestors` | `DENY` o `'self'` | Si una página con acciones sensibles es enmarcable (ver `vulns/clickjacking.md`) |
| `X-Content-Type-Options` | `nosniff` | Si se sirven ficheros subidos por usuarios que el navegador podría interpretar |
| `Referrer-Policy` | `strict-origin-when-cross-origin` o más estricta | Si hay tokens en URL que se filtran a terceros vía `Referer` |
| `Permissions-Policy`, `COOP`, `CORP` | Restringir lo no usado | Casi siempre informativa |
| `Cache-Control` | `no-store` en respuestas con datos personales | Datos sensibles cacheados en proxies o CDN (ver `vulns/cache-poisoning-deception.md`) |

`X-XSS-Protection` está obsoleta: su ausencia no es hallazgo. Las cabeceras de cookies (`Secure`, `HttpOnly`, `SameSite`) se tratan en `vulns/session.md`, y CORS en `vulns/cors.md`. **Agrupa** las cabeceras ausentes en un único hallazgo informativo o bajo.

### 4.2 Configuración TLS

```bash
testssl.sh --jsonfile tls.json https://t            # auditoría completa
testssl.sh -p -S -U t:443                           # protocolos, valores por defecto, vulnerabilidades
sslyze t:443                                         # alternativa rápida; --json_out tls.json
nmap -p 443 --script ssl-enum-ciphers t
curl -skI http://t/ | head -3                        # ¿HTTP redirige a HTTPS?
```

Qué reportar: SSLv2/SSLv3 (alto si permite ataques prácticos), TLS 1.0/1.1 habilitados (bajo), cifrados NULL/EXPORT/RC4/3DES (medio-bajo), ausencia de *forward secrecy* (propiedad que impide descifrar tráfico pasado si se roba la clave privada; baja), certificado caducado, autofirmado o con nombre incorrecto, cadena incompleta, vulnerabilidades concretas (Heartbleed, ROBOT) confirmadas por la herramienta. **BREACH** solo es relevante si la respuesta comprimida refleja entrada del atacante y contiene un secreto: muchas veces es falso positivo. Detalle de ataques TLS: CWE-319 (texto en claro), CWE-295 (validación de certificado), CWE-757 (negociación degradable).

### 4.3 Errores verbosos y trazas (A10)

Provoca condiciones excepcionales y busca trazas, rutas de disco, fragmentos SQL, versiones, IP internas o variables de entorno:

```text
param='"`        param[]=1        param[a]=1        {"id": {"$gt": ""}}      cuerpo JSON truncado
/%00   /%ff   /..;/   /index.php/   valor de 10 000 caracteres   Content-Type: application/xml
Método inesperado (PATCH, PROPFIND)   Accept: */xyz   id=-1 / id=99999999999999999999
```

Una traza que revela la consulta SQL o el motor (pivote a `vulns/sqli.md`), rutas absolutas (pivote a `vulns/path-traversal-lfi.md`) o secretos es reportable; un mensaje genérico con código de error no lo es.

### 4.4 Ficheros y repositorios expuestos

```bash
for p in .git/HEAD .git/config .svn/wc.db .hg/requires .DS_Store .env .env.local .env.production \
  config.php.bak wp-config.php.bak wp-config.php~ .index.php.swp web.config appsettings.json \
  application.yml application.properties docker-compose.yml .npmrc .aws/credentials \
  backup.zip backup.tar.gz dump.sql database.sql composer.json package.json; do
  printf '%s %s\n' "$(curl -sk -o /dev/null -w '%{http_code} %{size_download}' https://t/$p)" "$p"; done
```

- **`.git` expuesto:** `curl -sk https://t/.git/HEAD` devuelve `ref: refs/heads/...` → reconstruir el repositorio y buscar secretos en todo el historial:
  ```bash
  git-dumper https://t/.git/ repo/ && cd repo && git log --oneline | head
  trufflehog git file://. --only-verified ; gitleaks git .   # (gitleaks < 8.19: gitleaks detect -s .)
  ```
  Si el listado está prohibido, GitTools (`gitdumper.sh`) reconstruye por objetos conocidos.
- **`.DS_Store`:** revela nombres de ficheros y carpetas del directorio (parsear con `ds_store_exp` o la librería `ds_store` de Python).
- **Copias y temporales:** nombre del dominio o del proyecto con `.zip`, `.tar.gz`, `.sql`, `.bak`; ficheros de swap de vim (`.fichero.swp`); en IIS, la enumeración de nombres cortos 8.3 (`shortscan`) acelera la búsqueda.
- **Source maps** (`.js.map`): reconstruyen el código fuente original del frontend, con comentarios, rutas de API internas y a veces secretos:
  ```bash
  curl -sk https://t/static/js/main.js | tail -c 300        # busca //# sourceMappingURL=
  sourcemapper -url https://t/static/js/main.js.map -output src/
  ```
- **Documentación de API:** `/swagger-ui.html`, `/swagger-ui/`, `/v2/api-docs`, `/v3/api-docs`, `/openapi.json`, `/swagger.json`, `/api-docs`, `/redoc`; revela endpoints ocultos o de administración (ver `vulns/api-rest-grpc-websocket.md`; GraphQL en `vulns/graphql.md`).

### 4.5 Consolas y endpoints de depuración

| Tecnología | Ruta / señal | Impacto típico |
|---|---|---|
| Spring Boot Actuator | `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`, `/actuator/configprops`, `/actuator/loggers`, `/actuator/httpexchanges` (`/httptrace` en 2.x), `/jolokia` | `heapdump` contiene contraseñas, tokens y sesiones en memoria; `/actuator/gateway/routes` de Spring Cloud Gateway vulnerable permitió RCE (CVE-2022-22947) |
| PHP | `/phpinfo.php`, `/info.php`, `/test.php` | Variables de entorno, rutas, `disable_functions`, cookies `HttpOnly` reflejadas |
| Apache / Nginx | `/server-status`, `/server-info`, `/nginx_status` | URLs en curso de otros usuarios (con tokens en query), IP de clientes |
| Flask / Werkzeug | `/console`, página de traza interactiva; `/?__debugger__=yes&cmd=resource&f=debugger.js` | Consola Python protegida por PIN; el PIN se calcula si además hay lectura de ficheros (LFI) |
| Laravel | Página de error con `APP_DEBUG=true`, `/_ignition/health-check`, `/telescope`, `/horizon` | Variables de entorno y `APP_KEY`; Ignition < 2.5.2 con RCE (CVE-2021-3129); `APP_KEY` filtrada → deserialización de cookies (CVE-2018-15133 en versiones afectadas) |
| Django | `DEBUG=True`: 404 lista los patrones de URL; 500 muestra ajustes y variables locales | Mapa completo de rutas, fragmentos de configuración |
| Symfony | `/_profiler`, `/app_dev.php/_profiler`, `/_fragment` | Peticiones de otros usuarios con cabeceras y tokens; con `APP_SECRET` filtrado, `/_fragment` permite RCE |
| ASP.NET | `customErrors Off`, `/trace.axd`, `/elmah.axd` | Trazas, peticiones y cookies de otros usuarios |
| Rails | `/rails/info/routes`, `/rails/info/properties` (modo desarrollo) | Rutas y entorno |
| Go | `/debug/pprof/`, `/debug/vars` | Volcado de memoria y variables; `pprof` permite DoS ⚠️ |
| Node / dev servers | Vite (`/@vite/client`, `/@fs/...`), webpack-dev-server, Next.js en modo dev | Lectura de ficheros en servidores de desarrollo expuestos (varias CVE recientes de Vite; comprobar versión) |
| Servicios de IA | Ollama `:11434/api/tags`, MLflow, TorchServe `:8081` | Uso libre de modelos, LFI/SSRF conocidos (ver `vulns/llm-ai.md`) |

```bash
curl -sk https://t/actuator | jq .
curl -sk https://t/actuator/heapdump -o heap.hprof && strings heap.hprof | grep -iE 'password|secret|token|jdbc:' | head
curl -sk https://t/_ignition/health-check            # {"can_execute_commands":true} → Ignition activo
curl -sk https://t/no-existe-$RANDOM | grep -i 'URLconf\|Using the URLconf'   # Django DEBUG
```

⚠️ Endpoints que **cambian estado** (`POST /actuator/env`, `/actuator/loggers`, `/actuator/shutdown`, `/actuator/restart`, ejecutar soluciones de Ignition, la consola Werkzeug) *requieren confirmación explícita del cliente*; demuestra la exposición con lecturas.

### 4.6 Paneles de administración y credenciales por defecto

| Producto | Ruta | Credenciales de fábrica habituales |
|---|---|---|
| Tomcat Manager | `/manager/html` | `tomcat:tomcat`, `admin:admin`, `tomcat:s3cret` (→ despliegue de WAR = RCE ⚠️) |
| Grafana | `/login` | `admin:admin` |
| Jenkins | `/`, `/script` | Sin autenticación o asistente sin completar; `/script` = consola Groovy (RCE ⚠️) |
| RabbitMQ | `:15672` | `guest:guest` (en versiones modernas solo desde localhost) |
| WebLogic / JBoss | `/console`, `/jmx-console` | `weblogic:welcome1`, `admin:admin` |
| phpMyAdmin / Adminer | `/phpmyadmin`, `/adminer.php` | `root` sin contraseña |
| Elasticsearch / Kibana | `:9200`, `:5601` | Sin autenticación (`curl :9200/_cat/indices`) |

```bash
nuclei -u https://t -tags default-login -rl 5
pip install defaultcreds-cheat-sheet && creds search tomcat
```

Limita los intentos (2–3 por cuenta) para no bloquear usuarios. Una **instalación sin inicializar** (WordPress `/wp-admin/install.php`, asistente de Jenkins, Portainer recién desplegado) permite que el primero que llegue se quede con la administración: ⚠️ completarla tiene efectos y *requiere confirmación explícita del cliente*; basta con capturar la pantalla del asistente.

### 4.7 Listado de directorios

```bash
curl -sk https://t/uploads/ | grep -iE '<title>Index of|Directory listing for|\[To Parent Directory\]'
```

Es informativo si solo muestra recursos públicos; sube cuando expone copias, ficheros de usuarios o configuración.

### 4.8 Almacenamiento en la nube

```bash
# AWS S3: nombre desde HTML/JS, cabecera x-amz-bucket-region o error NoSuchBucket
curl -sk "https://BUCKET.s3.amazonaws.com/?list-type=2&max-keys=20"
aws s3 ls s3://BUCKET --no-sign-request
aws s3 ls s3://BUCKET --profile cuenta-propia        # "cualquier usuario autenticado de AWS"
aws s3api get-bucket-acl --bucket BUCKET --no-sign-request
# Azure Blob (acceso anónimo al contenedor)
curl -sk "https://CUENTA.blob.core.windows.net/CONTENEDOR?restype=container&comp=list"
# Google Cloud Storage
curl -sk "https://storage.googleapis.com/BUCKET"
curl -sk "https://storage.googleapis.com/storage/v1/b/BUCKET/iam/testPermissions?permissions=storage.objects.list&permissions=storage.objects.create"
# Firebase Realtime Database
curl -sk "https://PROYECTO-default-rtdb.firebaseio.com/.json?shallow=true"
```

- Las **SAS de Azure** en el código cliente (`sv=`, `sp=`, `se=`, `sig=`) son credenciales: revisa permisos (`sp=racwdl` incluye escritura y borrado) y caducidad (`se`).
- ⚠️ La prueba de **escritura** (`aws s3 cp poc-<token>.txt s3://BUCKET/ --no-sign-request`) *requiere confirmación explícita del cliente*: fichero inocuo con nombre único y borrado inmediato. Es crítica si el bucket sirve JavaScript cargado por la web (compromiso de todos los visitantes).
- Enumeración de nombres: `cloud_enum -k empresa`, `s3scanner`, GCPBucketBrute.

### 4.9 Subdomain takeover

Un subdominio con un `CNAME` (o registros `NS`/`A`) que apunta a un recurso de terceros ya liberado (bucket, app de Heroku, GitHub Pages, Azure App Service, Shopify, Fastly...) puede ser reclamado por cualquiera, que pasa a servir contenido bajo el dominio del cliente.

```bash
subfinder -d cliente.com -silent | dnsx -silent -cname -resp
dig +short CNAME viejo.cliente.com ; curl -sk https://viejo.cliente.com | head
nuclei -l subs.txt -tags takeover
subzy run --targets subs.txt
```

Huellas típicas: `NoSuchBucket`, `There isn't a GitHub Pages site here`, `No such app`, `Fastly error: unknown domain`, NXDOMAIN en `*.azurewebsites.net`/`*.cloudapp.net`. Consulta *can-i-take-over-xyz* para saber qué servicios siguen siendo reclamables.

⚠️ **Reclamar** el recurso *requiere confirmación explícita del cliente*: publica solo una página benigna con un token único (sin JavaScript que lea cookies ni formularios), captura la evidencia y libera el recurso al terminar. El impacto sube si las cookies de sesión tienen `Domain=.cliente.com`, si el subdominio está en una lista CORS de confianza (`vulns/cors.md`), en `redirect_uri` de OAuth (`vulns/oauth-oidc-saml.md`) o en la CSP.

### 4.10 Componentes vulnerables y desactualizados (A03)

```bash
whatweb -a 3 https://t ; httpx -u https://t -tech-detect -server -title
retire --jspath ./js_descargado/ ; nuclei -u https://t -tags cve -severity high,critical -rl 10
osv-scanner -r ./repo ; trivy fs ./repo ; grype dir:./repo ; npm audit --omit=dev   # caja blanca
```

**Confirmar que una CVE aplica de verdad:**
1. Versión exacta por más de una vía (banner, ficheros estáticos versionados, `package.json`, hashes de ficheros conocidos). Las distribuciones Linux **aplican parches sin cambiar la versión** (`Apache/2.4.41 (Ubuntu)` puede estar parcheado): consulta el aviso de la distribución.
2. Precondiciones: módulo o función afectada activa y alcanzable, configuración vulnerable, autenticación necesaria.
3. Prueba benigna específica (un comportamiento observable sin efectos, o la plantilla de nuclei de detección y no la de explotación).
4. Prioriza con CISA KEV y EPSS. No cites CVE solo por el número de versión: indica "posible, no confirmado" si no puedes verificar.

Cadena de suministro: scripts de CDN de terceros sin **SRI** (*Subresource Integrity*, atributo `integrity` que fija el hash del fichero; el caso polyfill.io de 2024 lo ilustra), dependencias abandonadas, paquetes npm comprometidos (oleadas de 2025 como el gusano Shai-Hulud) y **dependency confusion**: nombres de paquetes internos (vistos en source maps o `package.json` expuestos) no registrados en el registro público ⚠️ — registrarlos requiere confirmación explícita del cliente.

### 4.11 Secretos en bundles JavaScript

```bash
katana -u https://t -jc -silent | grep -E '\.js($|\?)' | sort -u > js.txt
mkdir js && cd js && wget -q -i ../js.txt
trufflehog filesystem . --only-verified ; jsluice secrets *.js ; jsluice urls *.js
grep -rEo '(AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,}|xox[baprs]-[0-9A-Za-z-]+|ghp_[0-9A-Za-z]{36}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY)' .
```

Valida solo con llamadas de identidad que no modifican nada y si las reglas del encargo lo permiten (p. ej., `aws sts get-caller-identity`). **Son públicas por diseño** (no reportar salvo mal restringidas): claves de Google Maps con restricción de referer, `apiKey` de Firebase, claves publicables de Stripe (`pk_`), DSN de Sentry, claves de búsqueda de Algolia de solo lectura.

### 4.12 Métodos HTTP

```bash
curl -sk -X OPTIONS -i https://t/ | grep -i '^allow'
curl -sk -X PUT https://t/poc-$RANDOM.txt -d 'poc' -i      # ⚠️ escritura: confirmación y borrado posterior
curl -sk -X PROPFIND -H 'Depth: 1' -i https://t/            # WebDAV
curl -sk -X TRACE -i https://t/
curl -sk -X POST -H 'X-HTTP-Method-Override: DELETE' -i https://t/api/recurso/ID-PROPIO
```

`TRACE` habilitado es informativo (el XST que permitía está mitigado por los navegadores). `Allow` puede mentir: prueba el método real. `PUT` que escribe en una ruta ejecutable (`.jsp`, `.php`, `.aspx`) lleva a RCE (ver `vulns/file-upload.md`). La sobrescritura de método sirve para saltar controles por verbo (ver `vulns/access-control-idor.md`).

### 4.13 robots.txt, sitemap y security.txt

`/robots.txt` y `/sitemap.xml` son fuentes de rutas (paneles, entornos antiguos), no vulnerabilidades: lo que importa es si las rutas listadas están protegidas. La ausencia de `/.well-known/security.txt` (RFC 9116) es informativa; si existe, úsalo como canal de contacto y comprueba que no haya caducado (`Expires`).


### 4.14 Productos perimetrales y CMS con CVE explotados activamente

VPN, pasarelas de correo, gestores de dispositivos móviles, servidores de impresión, almacenamiento compatible con S3 y plugins de CMS concentran muchos de los CVE explotados de forma masiva. No hace falta una lista fija: el método es **identificar el producto y la versión → consultar fuentes fiables → confirmar con la prueba menos intrusiva posible**.

1. **Identificar el producto**: página de inicio de sesión, rutas características, `Server`, el hash del favicon (§1.1 de `01-reconocimiento.md`), el `readme.txt` de los plugins de WordPress (`/wp-content/plugins/<slug>/readme.txt` → «Stable tag»).
2. **Consultar fuentes**: el catálogo **CISA KEV** (vulnerabilidades explotadas activamente), los avisos del fabricante y la puntuación EPSS (probabilidad de explotación).

```bash
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
 | jq -r '.vulnerabilities[] | select(.vendorProject|test("Fortinet|Ivanti|PaperCut|MinIO";"i")) | "\(.cveID)  \(.product)  \(.vulnerabilityName)"'
```

3. **Confirmar sin explotar**: busca la plantilla concreta de nuclei y **léela antes de lanzarla**, porque algunas ejecutan el exploit:

```bash
nuclei -u https://vpn.cliente.com -id CVE-2018-13379 -rl 2
```

Si la única forma de confirmar es explotar (lectura de ficheros, salto de autenticación), pide confirmación ⚠️ y limita la prueba a una lectura inocua.

Ejemplos frecuentes en auditorías (comprueba siempre el aviso del fabricante y las versiones afectadas):

| Producto | CVE | Tipo | Señal de reconocimiento |
|---|---|---|---|
| Fortinet FortiOS SSL-VPN | CVE-2018-13379 | Lectura de ficheros (sesiones VPN) | `/remote/login` |
| Ivanti EPMM (MobileIron Core) | CVE-2023-35078 | Salto de autenticación en la API | `/mifs/` |
| PaperCut NG/MF | CVE-2023-27350 | Salto de autenticación → RCE | `/app?service=page/SetupCompleted` |
| MinIO (despliegue en clúster) | CVE-2023-28432 | Revelación de variables de entorno (credenciales) | `/minio/bootstrap/v1/verify` |
| WooCommerce Payments (WordPress) | CVE-2023-28121 | Salto de autenticación por cabecera | `readme.txt` del plugin |
| BackupBuddy (WordPress) | CVE-2022-31474 | Lectura arbitraria de ficheros | `readme.txt` del plugin |
| nginx (módulo de rangos) | CVE-2017-7529 | Revelación de memoria de la caché | Versión de `Server` y `Range` |
| Apache HTTP Server 2.4.49/2.4.50 | CVE-2021-41773 / CVE-2021-42013 | Path traversal → RCE | Ver `vulns/path-traversal-lfi.md` |

Los CVE de **denegación de servicio** (por ejemplo, la carga masiva de `load-scripts.php` en WordPress) solo se notifican por versión y **no se prueban**.

## 5. Evasión de filtros y defensas (guardrails, WAF)

- Variaciones de ruta para ficheros bloqueados: `/.git//HEAD`, `/%2egit/HEAD`, `/.git/HEAD;.css`, `/static/..;/actuator/env` (Tomcat/Spring), `/actuator;/env`, mayúsculas en IIS.
- Puertos, hosts virtuales o el origen detrás de la CDN pueden no tener las mismas reglas (ver `vulns/host-header.md`, `vulns/waf-bypass.md`).
- Cabeceras de proxy (`X-Forwarded-For: 127.0.0.1`, `X-Original-URL`, `X-Rewrite-URL`) para alcanzar rutas restringidas a localhost.
- Rutas alternativas de Actuator: `/manage/`, `/admin/actuator/`, `/api/actuator/`, puerto de gestión separado.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- `.git`/`.env`/source maps → credenciales o lógica → acceso a BD, nube o paneles (demuestra solo autenticación o una lectura mínima).
- `heapdump`/`/_profiler`/`/server-status` → tokens de sesión de otros → secuestro de cuenta (muestra que el token es válido con una petición de solo lectura sobre tu cuenta de prueba si es posible, o el dato sin usarlo).
- `APP_KEY`/`APP_SECRET` filtrado → deserialización o RCE (ver `vulns/deserialization.md`) ⚠️.
- Errores verbosos → motor y consulta SQL → SQLi dirigida.
- Subdomain takeover → robo de cookies de dominio padre, bypass de CORS, OAuth o CSP.
- Bucket escribible que sirve JS → compromiso de todos los usuarios (demuestra con objeto inocuo, sin modificar ficheros existentes).
- Credenciales por defecto → Tomcat/Jenkins → RCE ⚠️ (detente en el acceso al panel salvo autorización expresa).

## 7. Caja blanca: fuentes, sumideros y patrones de código

```python
DEBUG = True                         # Django en producción  →  DEBUG = env.bool("DEBUG", default=False)
app.run(debug=True, host="0.0.0.0")  # Flask/Werkzeug        →  servir con gunicorn, debug desactivado
```

```properties
# Spring: VULNERABLE
management.endpoints.web.exposure.include=*
# SEGURO
management.endpoints.web.exposure.include=health,info
management.server.port=9091
```

```nginx
autoindex on;                     # VULNERABLE → autoindex off;
location ~ /\.(?!well-known) { deny all; }   # SEGURO: bloquea .git, .env, etc.
server_tokens off;
```

```hcl
# Terraform: VULNERABLE
resource "aws_s3_bucket_acl" "b" { acl = "public-read" }
# SEGURO
resource "aws_s3_bucket_public_access_block" "b" {
  bucket = aws_s3_bucket.b.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
```

```bash
rg -n -e 'DEBUG\s*=\s*True|APP_DEBUG=true|debug=True|display_errors\s*=\s*On|customErrors mode="Off"' .
rg -n -e 'exposure\.include=\*|include:\s*"\*"' -e 'autoindex on|Options \+?Indexes|directoryBrowse enabled="true"' .
rg -n -e "devtool:\s*'source-map'|productionBrowserSourceMaps:\s*true|GENERATE_SOURCEMAP" .
rg -n -e 'public-read|"Principal":\s*"\*"|allUsers|allAuthenticatedUsers|block_public_acls\s*=\s*false' .
rg -n -e '<script[^>]+src="https?://' -g '*.html' . | rg -v integrity
rg -n --hidden -e '(AKIA[0-9A-Z]{16}|sk_live_|ghp_[0-9A-Za-z]{36}|BEGIN [A-Z ]*PRIVATE KEY)' .
semgrep --config p/secrets . ; trivy config . ; checkov -d .
```

Revisa también `Dockerfile` (`COPY . .` sin `.dockerignore` que excluya `.git` y `.env`) y los pipelines que publican el directorio de trabajo completo.

## 8. Falsos positivos frecuentes

- Cabeceras de seguridad ausentes sin ruta de explotación (informativo), `X-XSS-Protection` ausente, `TRACE` habilitado.
- Banner con versión que la distribución ya parcheó; CVE que requiere un módulo no activo.
- Respuestas 200 "comodín" (SPA que devuelve `index.html` para cualquier ruta): compara tamaño y contenido; `ffuf -ac` ayuda.
- `.git/HEAD` accesible pero objetos bloqueados (verifica que se puede reconstruir algo).
- Claves públicas por diseño (Firebase, Maps restringida, `pk_` de Stripe).
- Bucket "público" que solo contiene recursos web públicos a propósito.
- BREACH sin entrada reflejada ni secretos en la respuesta; TLS 1.0 solo en un puerto fuera de alcance.
- Directory listing de `/assets/` con imágenes públicas.
- Subdominio con CNAME colgante a un servicio que ya no permite reclamar nombres ajenos.

## 9. Evidencia mínima para validarlo

1. Petición y respuesta exactas (fecha, URL, código, tamaño), con secretos **parcialmente enmascarados** (`AKIA****WXYZ`).
2. Para ficheros expuestos: qué contienen y por qué importa (tipo de credencial, alcance), sin volcar el contenido completo en el informe.
3. Para CVE: versión verificada por dos vías y prueba benigna de que la condición vulnerable existe.
4. Para takeover: registros DNS, huella del servicio, página PoC con token y prueba de liberación.
5. Para cloud: listado parcial (primeros objetos) y, si se autorizó, prueba de escritura con objeto inocuo y su borrado.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Impacto demostrado | CVSS 3.1 | CVSS 4.0 (con prefijo `CVSS:4.0/`; puntuar con la calculadora de FIRST) |
|---|---|---|
| Cabeceras ausentes sin explotación | Informativo (sin puntuación) | Informativo |
| TLS 1.0/1.1 o cifrados débiles | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` (3.7) | `AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` (baja) |
| Traza o error con información interna | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` (media) |
| `.git`, `.env`, `heapdump` o bucket con secretos/PII | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` (8.7) |
| Bucket escribible / `PUT` que escribe sin ejecución | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` (7.5) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` (alta) |
| Subdomain takeover (contenido arbitrario) | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | `AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` (media) |
| Takeover con cookies del dominio padre | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` (8.2) | `AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:H/SI:L/SA:N` (alta) |
| Credenciales por defecto / consola de depuración con RCE | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (9.3) |

Puntúa lo demostrado: un `.env` con credenciales es 7.5 por exposición; si además demostraste acceso administrativo con ellas, puntúa la cadena.

## 11. Remediación (con ejemplo correcto)

- Desactivar depuración y páginas de error detalladas en producción; errores genéricos con identificador de correlación y detalle solo en logs.
- Desplegar artefactos de compilación, no el directorio de trabajo; bloquear ficheros ocultos en el servidor; no publicar source maps (o servirlos solo internamente).
- Actuator, profilers y consolas: solo `health`/`info` públicos; el resto en puerto de gestión interno con autenticación.
- Cambiar credenciales por defecto en el despliegue (forzado en el primer arranque); paneles de administración tras VPN o lista de IP.
- Almacenamiento: bloqueo de acceso público a nivel de cuenta (S3 Block Public Access, Azure "allow blob public access" desactivado, GCS *public access prevention*), SAS de corta duración y mínimo permiso.
- Inventario DNS: eliminar registros antes de liberar el recurso de terceros; revisión periódica de CNAME colgantes.
- TLS 1.2/1.3 con la configuración "intermediate" de Mozilla; HSTS.
- Gestión de dependencias: SBOM, escaneo en CI (osv-scanner/trivy), SRI en scripts de terceros, *scopes* privados en registros npm para paquetes internos.
- Rotar **todo** secreto expuesto (eliminarlo del fichero no basta: sigue en el historial y en copias).

```nginx
server {
  listen 443 ssl http2;
  ssl_protocols TLSv1.2 TLSv1.3;
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  server_tokens off;
  autoindex off;
  location ~ /\.(?!well-known) { deny all; }
  location ~* \.(bak|old|sql|zip|tar\.gz|swp|map)$ { deny all; }
}
```

## 12. Herramientas (comando y cuándo usarla)

| Herramienta | Comando | Cuándo |
|---|---|---|
| curl | `curl -skI https://t` | Cabeceras, métodos, comprobaciones puntuales |
| testssl.sh / sslyze | `testssl.sh -p -S -U t:443` | Auditoría TLS |
| ffuf / feroxbuster | `ffuf -u https://t/FUZZ -w quickhits.txt -ac` | Ficheros y rutas expuestas |
| nuclei | `nuclei -u https://t -tags exposure,misconfig,default-login,takeover -rl 20` | Barrido de exposiciones conocidas (verificar cada resultado) |
| git-dumper / GitTools | `git-dumper https://t/.git/ repo/` | Reconstruir repositorios expuestos |
| trufflehog / gitleaks | `trufflehog git file://repo --only-verified` | Secretos en historial y ficheros |
| sourcemapper | `sourcemapper -url <map> -output src/` | Reconstruir frontend desde source maps |
| jsluice / katana | `jsluice secrets *.js` | Rutas y secretos en JavaScript |
| subfinder + dnsx / subzy | `subzy run --targets subs.txt` | Subdomain takeover |
| aws CLI / cloud_enum / s3scanner | `aws s3 ls s3://b --no-sign-request` | Almacenamiento cloud |
| whatweb / httpx / retire.js | `retire --jspath js/` | Huella de tecnologías y librerías vulnerables |
| osv-scanner / trivy / grype | `trivy fs repo/` | Dependencias vulnerables (caja blanca) |
| shortscan | `shortscan https://t/` | Nombres cortos en IIS |
| JDumpSpider / Eclipse MAT | — | Analizar `heapdump` de Actuator |

## 13. Referencias

- OWASP Top 10:2025 — A02 Security Misconfiguration, A03 Software Supply Chain Failures
- OWASP WSTG — 4.2 Configuration and Deployment Management Testing (WSTG-CONF), Error Handling (WSTG-ERRH), Weak Cryptography (WSTG-CRYP)
- OWASP Secure Headers Project · MDN HTTP Observatory · CSP Evaluator (Google)
- Mozilla Server Side TLS / SSL Configuration Generator
- *can-i-take-over-xyz* (EdOverflow) · HackTricks: Spring Actuators, Werkzeug, Laravel, Symfony
- Spring Boot Actuator docs (exposición de endpoints) · RFC 9116 (security.txt)
- CISA KEV · FIRST EPSS · OSV.dev

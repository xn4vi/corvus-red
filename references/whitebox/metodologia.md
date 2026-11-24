# Revisión de código fuente (white-box): metodología

> Auditoría con acceso al código. Solo en encargos autorizados y sobre el repositorio y las ramas acordadas en el alcance.
> **White-box** = el auditor ve el código fuente, la configuración y a menudo el historial de git. **Grey-box** = además hay una instancia en ejecución y credenciales de prueba para confirmar lo que se ve en el código.
> El detalle de explotación de cada clase de fallo está en `../vulns/<nombre>.md`; aquí solo se explica **cómo encontrarlo en el código**.

## Contenido

1. Principios y errores que hay que evitar
2. Fase A — Toma de contacto (intake) y mapa del repositorio
3. Fase B — Modelo de amenazas ligero (STRIDE por frontera de confianza)
4. Fase C — Pasada automática (SAST, SCA, secretos) y triaje
5. Fase D — Revisión manual: fuente → sumidero, autorización, cripto, errores, configuración
6. Fase E — Análisis de variantes
7. Fase F — Modo revisión diferencial (PR / rango de commits)
8. Fase G — Confirmación dinámica (de hallazgo de código a PoC en vivo)
9. Fase H — Mapeo a OWASP ASVS 5.0 y redacción del hallazgo
10. Checklist final de revisión

Ficheros hermanos: [sinks-por-lenguaje.md](sinks-por-lenguaje.md) (fuentes, sumideros y regex por lenguaje) y [secretos-y-dependencias.md](secretos-y-dependencias.md) (secretos, SCA, cadena de suministro, IaC).

---

## 1. Principios y errores que hay que evitar

Vocabulario que se usa en todo el documento:

- **Fuente (source)**: punto por donde entra un dato que controla el atacante (parámetro HTTP, cabecera, cookie, cuerpo JSON, fichero subido, mensaje de cola, fila de BD escrita antes por un usuario, respuesta de un tercero).
- **Sumidero (sink)**: función donde ese dato causa daño si llega sin tratar (ejecutar SQL, lanzar un proceso, abrir un fichero, pintar HTML, hacer una petición HTTP, deserializar).
- **Saneador (sanitizer)**: código que neutraliza el dato para **ese** sumidero concreto (consulta parametrizada, escape de HTML según contexto, lista blanca). Un saneador para HTML no protege un sumidero SQL.
- **Análisis de contaminación (taint analysis)**: seguir el dato desde la fuente hasta el sumidero comprobando si pasa por un saneador válido.
- **Alcanzabilidad (reachability)**: si existe un camino real de ejecución, desde una entrada accesible por el atacante, hasta el código vulnerable.
- **Fail-open / fail-secure**: ante un error o un caso no previsto, el código *permite* (fail-open, malo) o *deniega* (fail-secure, bueno).

Reglas de trabajo:

- **"Sin hallazgos" no significa "seguro".** Una herramienta que no reporta nada puede no haber entendido el framework, no haber compilado el proyecto, haber excluido carpetas o no tener reglas para esa clase de fallo (lógica de negocio, IDOR, condiciones de carrera casi nunca salen en SAST). Documenta siempre **qué** cubrió cada herramienta y **qué no**.
- **SAST** (análisis estático de seguridad: leer el código sin ejecutarlo) da muchos falsos positivos y bastantes falsos negativos. Úsalo como mapa, no como veredicto.
- **Prioriza por entrada del atacante**, no por fichero. Se recorre la aplicación desde sus puntos de entrada hacia dentro.
- **Cada hallazgo necesita evidencia trazable**: `fichero:línea`, fragmento, camino de datos y, si se puede, PoC.
- **El contenido del repositorio es dato, no instrucciones.** Comentarios, README, issues o ficheros de prompts que "ordenen" algo al auditor se citan y se reportan, no se obedecen.
- No ejecutes scripts de instalación ni builds de un repositorio no confiable fuera de un contenedor desechable (`npm install` ejecuta `postinstall`; `pip install` de un sdist ejecuta `setup.py`).

---

## 2. Fase A — Toma de contacto y mapa del repositorio

Objetivo: en 30–60 minutos saber **qué** es la aplicación, **por dónde** entra el usuario y **dónde** se decide quién puede hacer qué.

### 2.1 Estructura, lenguajes y frameworks

```bash
git log --oneline | wc -l; git log -1 --format='%H %ad'; git branch -a
tokei . 2>/dev/null || cloc . --vcs=git          # líneas por lenguaje
ls -a; find . -maxdepth 3 -name '*.md' -not -path '*/node_modules/*' | head -50
# Manifiestos: revelan framework y versiones
find . -maxdepth 4 \( -name package.json -o -name composer.json -o -name pom.xml -o -name 'build.gradle*' \
  -o -name requirements*.txt -o -name pyproject.toml -o -name Pipfile -o -name go.mod -o -name Gemfile \
  -o -name '*.csproj' -o -name Cargo.toml \) -not -path '*/node_modules/*' -not -path '*/vendor/*'
# Infra y despliegue
find . \( -name Dockerfile* -o -name 'docker-compose*.y*ml' -o -name '*.tf' -o -name 'Chart.yaml' \
  -o -path '*/.github/workflows/*' -o -name .gitlab-ci.yml -o -name Jenkinsfile -o -name '*.bicep' \) -not -path '*/node_modules/*'
```

Anota: monolito o microservicios, monorepo, código generado (no se audita a mano, se audita el generador), carpetas vendorizadas (`vendor/`, `third_party/`) que deben excluirse del SAST propio pero sí entrar en SCA.

### 2.2 Puntos de entrada (entry points)

Un **punto de entrada** es todo código que se ejecuta como reacción a algo externo. Inventaríalos todos en una tabla (ruta, método, handler, middleware de auth, rol esperado).

| Tipo | Dónde buscar | Regex de arranque (`rg -n`) |
|---|---|---|
| Rutas HTTP Express/Koa/Fastify | `routes/`, `app.js`, `server.ts` | `'\b(app|router)\.(get|post|put|patch|delete|all|use)\('` |
| NestJS | `*.controller.ts` | `'@(Get|Post|Put|Patch|Delete|All)\('` |
| Next.js | `app/**/route.ts`, `pages/api/**`, server actions | `'export (async )?function (GET|POST|PUT|PATCH|DELETE)'`, `"'use server'"` |
| Spring | `@RestController` | `'@(Get|Post|Put|Patch|Delete|Request)Mapping'` |
| Jakarta/Servlet | `web.xml`, `@WebServlet`, JAX-RS | `'@WebServlet|@Path\(|extends HttpServlet'` |
| Django | `urls.py`, `views.py` | `'path\(|re_path\(|url\('` |
| Flask / FastAPI | decoradores | `'@(app|bp|blueprint|router)\.(route|get|post|put|patch|delete)'` |
| Laravel | `routes/*.php` | `'Route::(get|post|put|patch|delete|any|match|resource)'` |
| Symfony | atributos/anotaciones | `'#\[Route\(|@Route\('` |
| Rails | `config/routes.rb` | `'^\s*(get|post|put|patch|delete|resources?|match)\b'` → `bin/rails routes` |
| ASP.NET Core | controladores, minimal APIs | `'\[Http(Get|Post|Put|Patch|Delete)|Map(Get|Post|Put|Delete|Patch)\('` |
| Go | `net/http`, Gin, Echo, chi | `'HandleFunc\(|\.(GET|POST|PUT|PATCH|DELETE)\(|r\.(Get|Post)\('` |
| GraphQL | resolvers, schema | `'Query|Mutation|@Resolver|@Query|@Mutation|resolve_'` y ficheros `*.graphql` |
| gRPC | `*.proto` + implementación | `'service \w+ \{'` |
| WebSockets | handlers de mensajes | `'on\(.message|@MessageMapping|@SubscribeMessage|websocket'` |
| Colas / eventos | consumidores Kafka, RabbitMQ, SQS, Celery, Sidekiq | `'@KafkaListener|@RabbitListener|consumer|@shared_task|@app\.task|perform\(|Sidekiq::Job'` |
| Tareas programadas | cron, schedulers | `'@Scheduled|cron|schedule\.|crontab|BackgroundService'` |
| Webhooks entrantes | `/webhook`, `/callback`, `/hooks` | `'webhook|callback|signature'` |
| CLI / jobs admin | `manage.py`, `artisan`, `rake` | comandos custom que lean ficheros o entradas |

Truco: si el framework genera la lista de rutas, úsala (`bin/rails routes`, `php artisan route:list`, `python manage.py show_urls` con django-extensions, actuator `/mappings` en Spring, Swagger/OpenAPI generado). Es más fiable que el grep.

### 2.3 Autenticación y autorización

Localiza **dónde** se valida la identidad y **dónde** se decide el acceso:

```bash
rg -n -i 'middleware|guard|interceptor|filter|before_action|@PreAuthorize|@Secured|@RolesAllowed|\[Authorize|login_required|permission_classes|Depends\(|can\?|authorize|policy|isAdmin|hasRole' --type-not lock | head -200
```

Preguntas clave: ¿la autenticación es global con excepciones (*deny by default*, bueno) o por ruta con opt-in (*allow by default*, frágil)? ¿Hay rutas en una lista de exclusiones (`permitAll`, `AllowAnonymous`, `skip_before_action`, `@Public`)? ¿Cómo se identifica al usuario (sesión, JWT, API key) y dónde se verifica la firma?

### 2.4 Almacenes de datos y llamadas a terceros

```bash
rg -n -i 'DATABASE_URL|jdbc:|mongodb(\+srv)?://|redis://|amqp://|s3\.|BlobServiceClient|elasticsearch' 
rg -n -i 'axios|fetch\(|requests\.|httpx|urllib|HttpClient|RestTemplate|WebClient|http\.Get|Net::HTTP|Faraday|Guzzle|curl_' | head -100
```

Por cada tercero: ¿qué credencial usa, quién controla la URL, se valida TLS, qué se hace con la respuesta (se confía en ella, se renderiza, se deserializa)?

### 2.5 Resultado de la fase A

Un documento corto con: stack y versiones, tabla de entry points, mecanismo de authn/authz, almacenes, terceros, ficheros de configuración sensibles y **zonas calientes** (subida de ficheros, exportaciones/importaciones, plantillas, pagos, gestión de usuarios/roles, webhooks, integración con LLM, funcionalidades "admin" o de depuración).

---

## 3. Fase B — Modelo de amenazas ligero

**Modelo de amenazas**: ejercicio rápido de preguntarse "qué puede salir mal" en cada punto donde los datos cambian de nivel de confianza. **Frontera de confianza (trust boundary)**: línea entre zonas con distinto nivel de confianza (navegador ↔ API, API ↔ BD, servicio ↔ tercero, usuario ↔ admin, tenant A ↔ tenant B).

### 3.1 Esquema de flujo de datos

Dibuja (aunque sea en texto) los actores, procesos, almacenes y flujos:

```
[Navegador] --HTTPS/cookie--> (API gateway) --JWT--> (svc-pedidos) --SQL--> [(Postgres)]
                                                    \--HTTP--> (svc-pdf) --file--> [(S3)]
[Webhook pasarela pago] --HTTPS+firma--> (svc-pagos)
[Admin] --VPN/SSO--> (backoffice)
```

### 3.2 STRIDE por frontera

STRIDE es un acrónimo de seis tipos de amenaza. Aplícalo a cada flecha que cruza una frontera:

| Letra | Amenaza | Pregunta en el código | Categoría OWASP 2025 típica |
|---|---|---|---|
| S | Spoofing (suplantación) | ¿Se verifica la identidad en este salto? ¿firma de webhook, JWT, mTLS? | A07 |
| T | Tampering (manipulación) | ¿Puede el cliente alterar precio, rol, `user_id`, ruta de fichero? | A01, A05, A08 |
| R | Repudiation (repudio) | ¿Queda registro de quién hizo la acción sensible? | A09 |
| I | Information disclosure (fuga) | ¿Se devuelven campos de más, trazas, secretos, datos de otro tenant? | A01, A02, A04 |
| D | Denial of service | ¿Hay límites de tamaño, paginación, regex catastróficas, bucles por entrada? | A06, A10 |
| E | Elevation of privilege | ¿Puede un usuario normal llegar a funciones de admin o de otro tenant? | A01 |

Salida: lista priorizada de **hipótesis de ataque** ("un usuario puede cambiar `order.userId` en el PATCH"; "el webhook de pagos no verifica firma") que guían la revisión manual. Cada hipótesis se cierra como confirmada, descartada (con motivo) o no verificable.

---

## 4. Fase C — Pasada automática y triaje

Ejecuta las herramientas en paralelo mientras haces la revisión manual. Guarda todas las salidas en SARIF o JSON en una carpeta `out/` del encargo (fuera del repositorio auditado).

**SARIF** (Static Analysis Results Interchange Format) es un JSON estándar que casi todas las herramientas SAST saben emitir; permite unificar y comparar resultados.

### 4.1 Semgrep

Motor de patrones por sintaxis, rápido y multilenguaje; con reglas de *taint* (modo `taint`) sigue datos dentro de un fichero (entre ficheros solo en la versión de pago/Pro).

```bash
semgrep scan --metrics=off \
  --config p/owasp-top-ten --config p/secrets --config p/security-audit \
  --config p/<lenguaje>            # p/python, p/javascript, p/typescript, p/java, p/php, p/golang, p/ruby, p/csharp, p/kotlin
  --sarif --output out/semgrep.sarif
# Packs de framework/infra útiles: p/django, p/flask, p/react, p/nodejs, p/dockerfile, p/terraform, p/kubernetes, p/github-actions
# Reglas propias:
semgrep scan --config ./reglas/ --dataflow-traces --json -o out/semgrep-custom.json
```

Comprueba los nombres exactos de packs en el registro (semgrep.dev/explore) antes de citarlos en el informe. Ejemplos de reglas propias en [sinks-por-lenguaje.md](sinks-por-lenguaje.md).

### 4.2 CodeQL

Convierte el código en una base de datos consultable y hace análisis de flujo de datos **entre ficheros y funciones**. Es más profundo que Semgrep pero exige extraer bien el proyecto.

```bash
# Lenguajes: javascript-typescript, python, java-kotlin, csharp, go, ruby, c-cpp, swift, actions
codeql database create out/db-js --language=javascript-typescript --source-root .

# Lenguajes compilados: el "build mode" decide cómo se extrae el código
codeql database create out/db-java --language=java-kotlin --build-mode=none          # sin compilar (Java, C#)
codeql database create out/db-java --language=java-kotlin --build-mode=autobuild     # intenta detectar el build
codeql database create out/db-java --language=java-kotlin --build-mode=manual \
  --command='mvn -B -q -DskipTests package'                                         # build explícito

codeql database analyze out/db-java --download \
  codeql/java-queries:codeql-suites/java-security-extended.qls \
  --format=sarif-latest --output=out/codeql-java.sarif
```

Advertencias de *build mode* (fuente habitual de falsos negativos):
- `build-mode=none` no compila: tipos y dependencias se resuelven "a ojo"; puede perder flujos que pasan por librerías o código generado (Lombok, MapStruct, anotaciones). Si es crítico, repite con `manual`.
- `autobuild` puede compilar **solo un módulo** o fallar en silencio en monorepos. Revisa el log de creación y el resumen de la base de datos: `codeql database print-baseline out/db-java` (líneas de código vistas) y compáralo con `tokei`.
- Diagnósticos de extracción: `codeql database export-diagnostics out/db-java --format=sarif-latest -o out/diag.sarif`.
- Usa la suite `security-extended` (más reglas, algo más de ruido) frente a la por defecto; `security-and-quality` añade reglas de calidad.

### 4.3 Linters de seguridad por lenguaje

| Lenguaje | Herramienta | Comando base |
|---|---|---|
| Python | Bandit | `bandit -r . -x ./tests,./venv -f json -o out/bandit.json` |
| Go | gosec | `gosec -fmt=sarif -out=out/gosec.sarif ./...` |
| Go | govulncheck (SCA con alcanzabilidad) | `govulncheck ./...` |
| Ruby on Rails | Brakeman | `brakeman -A -o out/brakeman.json` (`-A` = todas las comprobaciones) |
| Java/Kotlin | SpotBugs + plugin FindSecBugs | plugin Maven/Gradle de SpotBugs añadiendo `com.h3xstream.findsecbugs:findsecbugs-plugin`; necesita bytecode compilado |
| JS/TS | eslint-plugin-security | config plana: `import security from 'eslint-plugin-security'; export default [security.configs.recommended];` y `npx eslint .` |
| PHP | Psalm (taint) | `vendor/bin/psalm --taint-analysis --report=out/psalm.sarif` |
| PHP | PHPStan / phpcs-security-audit | complementos de baja señal; útiles para `eval`, `unserialize` |
| .NET | Roslyn analyzers / Security Code Scan | paquete NuGet de analizadores y `dotnet build`; Security Code Scan ya no se mantiene activamente → prioriza CodeQL `csharp` |

### 4.4 SCA, secretos e IaC

**SCA** (Software Composition Analysis): comparar las dependencias declaradas contra bases de vulnerabilidades conocidas. Detalle y triaje en [secretos-y-dependencias.md](secretos-y-dependencias.md).

```bash
osv-scanner scan source -r .            # v2 (en v1: osv-scanner -r .)
trivy fs --scanners vuln,secret,misconfig --format sarif -o out/trivy.sarif .
gitleaks git -v --report-format sarif --report-path out/gitleaks.sarif .   # v8.19+; antes: gitleaks detect --source .
trufflehog git file://. --no-verification --json > out/trufflehog.json
checkov -d . -o sarif --output-file-path out/
hadolint Dockerfile
```

### 4.5 Leer y unificar SARIF

```bash
# Resumen: regla, fichero, línea, mensaje
jq -r '.runs[] | .tool.driver.name as $t | .results[] |
  [$t, .ruleId, .level // "warning",
   .locations[0].physicalLocation.artifactLocation.uri,
   (.locations[0].physicalLocation.region.startLine|tostring), (.message.text|gsub("\n";" "))] | @tsv' out/*.sarif \
  | sort -t$'\t' -k4,4 -k5,5n > out/hallazgos.tsv

# Conteo por regla para detectar ruido
cut -f2 out/hallazgos.tsv | sort | uniq -c | sort -rn | head -30

# Caminos de datos (CodeQL/Semgrep Pro): pasos del flujo fuente → sumidero
jq -r '.runs[].results[] | select(.codeFlows) | .ruleId as $r |
  .codeFlows[0].threadFlows[0].locations[] | .location.physicalLocation |
  "\($r)  \(.artifactLocation.uri):\(.region.startLine)"' out/codeql-java.sarif
```

### 4.6 Triaje de resultados automáticos

Para cada resultado, en este orden (descarta en cuanto falle uno):

1. **¿Es código de producción?** Tests, fixtures, ejemplos, scripts de desarrollo, código muerto → baja prioridad (salvo secretos reales).
2. **¿La fuente la controla el atacante?** Variable de entorno o constante → normalmente no; parámetro HTTP → sí. Ojo con datos "internos" que vienen de BD pero que escribió antes otro usuario (*second-order*: inyección de segundo orden).
3. **¿Es alcanzable?** ¿Existe una ruta registrada que llegue ahí? ¿Detrás de qué autenticación/rol? Una inyección solo accesible para el superadmin sigue siendo hallazgo, pero con menor severidad.
4. **¿Hay saneador efectivo para ese sumidero?** Validación de tipo (`int(x)`), lista blanca, ORM parametrizado, escape contextual. Comprueba que no haya un camino alternativo que lo salte.
5. **¿Es explotable en la práctica?** Configuración del framework (autoescape activo, `allowMultiQueries`, `libxml` sin entidades por defecto), versión del runtime, WAF no cuenta como mitigación de raíz.
6. **Clasifica**: Confirmado (con PoC o razonamiento completo), Probable (falta un dato), Falso positivo (motivo), Informativo (mala práctica sin explotación).

Para remediaciones verificadas al estilo "fix + re-scan": aplica el arreglo en una rama, vuelve a ejecutar **la misma** herramienta y regla, y limita los reintentos (si a la tercera no desaparece, revisa a mano: puede ser que la regla no reconozca tu saneador).

---

## 5. Fase D — Revisión manual

La revisión manual es donde salen los fallos graves: autorización, lógica de negocio, cadenas de varios pasos, configuraciones *fail-open*.

### 5.1 Trazado fuente → sumidero por punto de entrada

Dos direcciones complementarias:

- **Hacia delante (forward)**: desde cada entry point de la tabla de la fase A, sigue cada parámetro hasta donde se usa. Mejor para encontrar fallos de lógica y autorización.
- **Hacia atrás (backward)**: busca los sumideros peligrosos con las regex de [sinks-por-lenguaje.md](sinks-por-lenguaje.md) y sube por las llamadas hasta ver si llega una fuente. Mejor para cobertura rápida de inyecciones.

Plantilla de anotación por flujo:

```
FLUJO #7  POST /api/reports/export  (auth: usuario; rol: cualquiera)
fuente:   req.body.template            controllers/report.ts:41
paso:     buildReport(template, data)  services/report.ts:88
paso:     renderer.render(tpl)         lib/render.ts:15     ← sin lista blanca
sumidero: nunjucks.renderString(tpl)   lib/render.ts:22     → SSTI (../vulns/ssti.md)
saneador: ninguno | estado: Confirmado (PoC {{7*7}} → 49)
```

Puntos donde se suele perder el rastro: inyección de dependencias, eventos/colas (la fuente está en otro servicio), ORM con fragmentos crudos, serialización a/desde caché, plantillas que reciben objetos completos, funciones utilitarias "genéricas" (`buildQuery`, `execCommand`, `fetchUrl`).

### 5.2 Revisión de autorización: matriz ruta × rol × propiedad

La **autorización** decide si *este* usuario puede hacer *esta* acción sobre *este* objeto. Hay tres niveles distintos y hay que comprobar los tres:

1. **Función**: ¿el rol puede usar este endpoint? (`/admin/*`)
2. **Objeto**: ¿el objeto pertenece al usuario o a su tenant? (IDOR / BOLA: acceso a un objeto ajeno cambiando su identificador)
3. **Propiedad/campo**: ¿puede leer o escribir *ese* campo? (asignación masiva de `role`, `isAdmin`, `price`; exposición de campos internos)

Construye la matriz:

| Ruta | Método | Authn | Rol requerido (código) | Comprobación de propiedad | Campos escribibles | Notas |
|---|---|---|---|---|---|---|
| `/api/orders/:id` | GET | sí | user | `where id=? and user_id=?` ✅ | — | |
| `/api/orders/:id` | PATCH | sí | user | **ninguna** ❌ | `req.body` entero ❌ | IDOR + mass assignment |
| `/api/admin/users` | GET | sí | `@PreAuthorize("hasRole('ADMIN')")` ✅ | n/a | — | |
| `/api/export` | POST | **no** ❌ | — | — | — | falta en lista de middleware |

Patrones a buscar en el código:

- La consulta carga por ID **sin** filtrar por usuario/tenant: `findById(id)`, `Model.objects.get(pk=pk)`, `Order.find(params[:id])` en vez de `current_user.orders.find(...)`.
- La comprobación existe en `GET` pero no en `PUT/PATCH/DELETE` o en la versión antigua de la API (`/v1/`).
- La comprobación se hace en el front (ocultar botón) y no en el back.
- El rol o el tenant se toma del cuerpo/cabecera de la petición en vez de la sesión/token.
- Decoradores/atributos ausentes en un método nuevo de un controlador donde el resto sí los tiene → compara métodos hermanos.
- Comprobación hecha **después** de la acción con efectos (borra y luego comprueba).
- GraphQL: autorización en el resolver raíz pero no en resolvers de campos anidados ni en mutaciones.
- Multi-tenant: filtros globales (Hibernate filters, Django managers, scopes de Rails) que se desactivan en consultas crudas o en tareas en segundo plano.

Detalle de explotación: [access-control-idor](../vulns/access-control-idor.md), [business-logic](../vulns/business-logic.md), [graphql](../vulns/graphql.md), [api-rest-grpc-websocket](../vulns/api-rest-grpc-websocket.md).

### 5.3 Autenticación, sesión y tokens

- Comparación de contraseñas/tokens con `==` en vez de comparación en tiempo constante; hash de contraseñas sin algoritmo lento (bcrypt, scrypt, Argon2id, PBKDF2 con muchas iteraciones).
- Flujos de restablecimiento de contraseña: token predecible, sin caducidad, reutilizable, enviado a un host tomado de la cabecera `Host` ([host-header](../vulns/host-header.md)).
- JWT: algoritmo no fijado (`alg: none`, confusión RS/HS), clave débil o embebida, no se valida `exp`/`aud`/`iss` ([jwt](../vulns/jwt.md)).
- OAuth/OIDC/SAML: `state`/`nonce` ausentes, `redirect_uri` con coincidencia laxa, validación de firma SAML incompleta ([oauth-oidc-saml](../vulns/oauth-oidc-saml.md)).
- Sesión: regeneración del ID tras login, flags `Secure`/`HttpOnly`/`SameSite`, invalidación en logout y cambio de contraseña ([session](../vulns/session.md)).
- MFA y bloqueo por intentos: ¿se pueden saltar llamando directamente al paso 2? ¿límite de intentos por cuenta y por IP? ([authentication](../vulns/authentication.md)).

### 5.4 Criptografía y secretos

- Algoritmos débiles: MD5/SHA1 para contraseñas o firmas, DES/3DES/RC4, AES en modo ECB, RSA < 2048, padding PKCS#1 v1.5 para cifrado.
- IV/nonce fijo o reutilizado (fatal en AES-GCM), clave derivada de una contraseña sin KDF, cifrado sin autenticación (CBC sin MAC → *padding oracle*).
- Aleatoriedad no criptográfica para tokens: `Math.random`, `random.random`, `java.util.Random`, `rand()`, `math/rand`.
- Verificación TLS desactivada: `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`, `TrustAllCerts`, `ServerCertificateCustomValidationCallback = (...) => true`.
- Secretos en código, ficheros de config, tests, historial git → [secretos-y-dependencias.md](secretos-y-dependencias.md).
- Comparación de HMAC/firma con igualdad normal (ataque de temporización).

Mapeo: A04 Cryptographic Failures.

### 5.5 Manejo de errores y valores por defecto inseguros (fail-open)

Busca construcciones en las que un error **concede** acceso o salta un control:

```python
try:
    user = verify_token(tok)
except Exception:
    user = None        # ...y más abajo: if user is None or user.is_admin  → fail-open
```

```js
const allowed = await policy.check(user, action).catch(() => true);   // fail-open explícito
if (process.env.AUTH_DISABLED) next();                                 // interruptor peligroso
const secret = process.env.JWT_SECRET || 'changeme';                   // default inseguro
```

Checklist de *insecure defaults* y *sharp edges* (APIs fáciles de usar mal):
- Valores por defecto en variables de entorno para secretos, flags `DEBUG`, `ALLOWED_HOSTS=['*']`, CORS `*` con credenciales.
- `catch` vacíos o genéricos alrededor de validaciones de firma, autorización o pagos.
- Validaciones que devuelven `true` cuando el campo no viene (`if (sig && !valid(sig)) reject` → sin firma pasa).
- Funciones con semántica sorprendente: `strcmp`/`==` laxo en PHP (`"0e123" == "0e456"`), `in_array` sin modo estricto, `parseInt` parcial, `startsWith` para validar dominios/rutas, `url.parse` vs `new URL` con resultados distintos, `path.join` con rutas absolutas, `os.path.join` que descarta lo anterior si el segundo argumento es absoluto, `yaml.load` sin `SafeLoader`, `Pattern` con regex catastróficas (ReDoS).
- Mensajes de error que filtran trazas, SQL, rutas internas o existencia de usuarios.
- Comportamiento ante condiciones excepcionales (A10): timeouts, nulos, desbordamientos, carreras, ficheros parciales; ¿la transacción queda a medias? ([race-condition](../vulns/race-condition.md)).

Logging (A09): ¿se registran logins fallidos, cambios de permisos, acciones administrativas? ¿Se registran secretos, tokens o datos personales? ¿Hay inyección en logs (saltos de línea sin escapar)?

### 5.6 Configuración, IaC y contenedores

- Config del framework por entorno: `DEBUG=True`, `app.debug`, `APP_DEBUG=true`, `spring.profiles.active=dev`, actuators expuestos (`management.endpoints.web.exposure.include=*`), consolas (H2, Werkzeug, Rails web-console), Swagger en producción ([config-exposure](../vulns/config-exposure.md)).
- Cabeceras de seguridad y CSP, configuración de cookies, CORS ([cors](../vulns/cors.md), [clickjacking](../vulns/clickjacking.md)).
- Proxy inverso: `trust proxy`, `X-Forwarded-*` aceptados de cualquiera, normalización de rutas distinta entre proxy y app ([request-smuggling](../vulns/request-smuggling.md), [cache-poisoning-deception](../vulns/cache-poisoning-deception.md)).
- Dockerfile, Kubernetes, Terraform, pipelines de CI → [secretos-y-dependencias.md §IaC](secretos-y-dependencias.md).

### 5.7 Componentes LLM

Si el código llama a un modelo de lenguaje: ¿qué datos no confiables entran en el prompt (RAG, correos, páginas web)?, ¿qué herramientas puede invocar el modelo y con qué permisos?, ¿se renderiza su salida como HTML/Markdown o se pasa a un sumidero (SQL, shell, `eval`)? Ver [llm-ai](../vulns/llm-ai.md).

---

## 6. Fase E — Análisis de variantes

Un fallo encontrado casi nunca está solo: el mismo desarrollador repitió el patrón. Proceso en cinco pasos:

1. **Causa raíz**: describe el fallo en abstracto. No "falta escape en `search.php:33`", sino "se concatena un parámetro de petición en una cadena que llega a `$wpdb->query` sin `prepare`".
2. **Patrón de detección**: tradúcelo a algo buscable: regex, regla Semgrep o consulta CodeQL. Empieza estricto (pocos resultados, todos verdaderos) y luego relaja.
3. **Búsqueda**: en todo el repositorio, en otras ramas, en otros repositorios de la organización y en el historial.
4. **Validación**: revisa cada coincidencia con el triaje del §4.6; descarta las que tienen saneador.
5. **Documentación**: agrupa variantes en un hallazgo con lista de ubicaciones, o en hallazgos separados si cambian la severidad o el endpoint.

```bash
# Ejemplo: tras encontrar un IDOR en OrderController.update con findById sin filtro de usuario
rg -n 'Repository\.findById\(' --type java | rg -v 'Owner|User|Tenant'
semgrep scan --config ./reglas/idor-findbyid.yml --json -o out/variantes.json
# Otras ramas
for b in $(git for-each-ref --format='%(refname:short)' refs/remotes/); do
  git grep -n -E 'findById\(' "$b" -- '*.java' ; done | sort -u
```

Consulta CodeQL de variantes (esqueleto, Java):

```ql
/** @kind path-problem @id corvus/variant-sqli-custom */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node n) {
    exists(MethodCall c | c.getMethod().hasName("rawQuery") and n.asExpr() = c.getArgument(0))
  }
}
module Flow = TaintTracking::Global<Cfg>;
import Flow::PathGraph
from Flow::PathNode src, Flow::PathNode sink
where Flow::flowPath(src, sink)
select sink.getNode(), src, sink, "Entrada remota llega a rawQuery()"
```

Ejecuta con `codeql query run` (en un pack con dependencia `codeql/java-all`) o `codeql database analyze db consulta.ql --format=sarif-latest -o out/var.sarif`.

---

## 7. Fase F — Revisión diferencial (PR o rango de commits)

Cuando el encargo es revisar un cambio (pull request, release) en vez del repositorio completo.

```bash
git fetch origin
BASE=$(git merge-base origin/main HEAD)
git diff --stat $BASE..HEAD
git diff --name-only $BASE..HEAD | rg -v '\.(md|png|svg|lock)$'
git log --oneline $BASE..HEAD
git diff -U10 $BASE..HEAD -- src/            # contexto amplio
git diff $BASE..HEAD -- '*.lock' 'package-lock.json' 'go.sum' 'poetry.lock'   # dependencias nuevas
# Solo lo nuevo en SAST: escanea base y cabeza y compara
semgrep scan --config p/security-audit --baseline-commit $BASE --json -o out/semgrep-diff.json
```

Qué mirar en un diff, por orden de riesgo:

1. **Controles eliminados o debilitados**: líneas borradas con `authorize`, `@PreAuthorize`, `csrf`, `verify`, `sanitize`, `escape`, validaciones; `if` cuyo sentido cambia; nuevas entradas en listas de exclusión (`permitAll`, `@Public`, `skip_before_action`, `AllowAnonymous`).
2. **Superficie nueva**: rutas, parámetros, campos de modelo (¿asignables en masa?), resolvers, consumidores de cola, webhooks.
3. **Sumideros nuevos** con las regex del fichero de sinks aplicadas solo al diff: `git diff $BASE..HEAD | rg '^\+' | rg -n '<regex>'`.
4. **Cambios de configuración**: CORS, cookies, CSP, `DEBUG`, timeouts, límites de tamaño, feature flags que encienden código antiguo.
5. **Dependencias**: nuevas, cambiadas de versión, cambiadas de registro, scripts de instalación ([secretos-y-dependencias.md](secretos-y-dependencias.md)).
6. **Secretos añadidos** (aunque se borren en un commit posterior siguen en el historial): `gitleaks git --log-opts="$BASE..HEAD" .`.
7. **Cambios en CI/CD** (`.github/workflows`, `Jenkinsfile`): permisos, `pull_request_target`, acciones no fijadas.
8. **Efecto en el código no tocado**: una función cambia su contrato (antes devolvía `null` en error, ahora lanza excepción → ¿qué llamadores lo trataban como "permitido"?). Busca los llamadores: `rg -n 'nombreFuncion\('`.

Salida del modo diferencial: lista corta de riesgos introducidos por el cambio, con línea del diff, y explícitamente "riesgos preexistentes observados fuera del alcance" aparte.

---

## 8. Fase G — Confirmación dinámica (grey-box)

Si existe una instancia de pruebas autorizada, convierte cada hallazgo de código en una prueba en vivo. Un hallazgo confirmado vale mucho más que uno teórico.

1. **Reconstruye la petición desde el código**: ruta, método, nombres exactos de parámetros, formato (JSON, form, multipart), cabeceras requeridas, autenticación necesaria. El código te da los nombres de parámetros ocultos que un black-box no adivinaría.
2. **Prueba primero inocua**: un marcador único (`corvus7731`) para ver dónde se refleja o almacena; operaciones aritméticas (`{{7*7}}`), retardos acotados, peticiones a un colaborador controlado (OAST: servidor externo que registra interacciones DNS/HTTP) para fallos ciegos.
3. **Instrumenta si puedes**: logs de la app en modo debug en el entorno de pruebas, consola de BD con log de consultas, un *breakpoint*. Ver la consulta SQL real resuelve dudas de saneamiento.
4. **Diferencias entre código y despliegue**: la rama revisada puede no ser la desplegada. Confirma versión (`/version`, cabeceras, hash de assets) antes de concluir "no explotable".
5. **Sin efectos destructivos**: usa cuentas y objetos propios de prueba; para IDOR, dos cuentas de prueba (A accede a objeto de B).
6. **Registra la PoC**: petición y respuesta completas (sin secretos reales), hora, cuenta usada.

Si no hay instancia: argumenta la explotabilidad con el camino de datos completo y, si es razonable, levanta la aplicación en local con Docker con datos de prueba.

---

## 9. Fase H — Mapeo a ASVS 5.0 y redacción del hallazgo

### 9.1 OWASP ASVS 5.0

**ASVS** (Application Security Verification Standard) es el catálogo de requisitos verificables de OWASP. La versión 5.0 tiene tres niveles:

- **L1**: mínimo para cualquier aplicación; controles que se pueden comprobar sin mucho contexto.
- **L2**: recomendado para la mayoría de aplicaciones que manejan datos sensibles o de negocio.
- **L3**: aplicaciones críticas (salud, banca, infraestructuras); exige defensa en profundidad y documentación.

Capítulos de ASVS 5.0 y dónde encajan los hallazgos de código:

| Capítulo ASVS 5.0 | Ejemplos de hallazgo | OWASP Top 10:2025 |
|---|---|---|
| V1 Encoding and Sanitization | SQLi, XSS, inyección de comandos, SSTI, deserialización | A05 |
| V2 Validation and Business Logic | validación ausente, lógica de negocio, límites | A06 |
| V3 Web Frontend Security | CSP, cookies, sumideros DOM, CORS | A02, A05 |
| V4 API and Web Service | GraphQL, REST, WebSockets | A01, A05 |
| V5 File Handling | subida de ficheros, path traversal | A01, A05 |
| V6 Authentication | almacenamiento de contraseñas, MFA, reset | A07 |
| V7 Session Management | fijación de sesión, invalidación | A07 |
| V8 Authorization | IDOR, falta de comprobación de rol, mass assignment | A01 |
| V9 Self-contained Tokens | JWT mal validados | A07, A04 |
| V10 OAuth and OIDC | `redirect_uri`, `state`, PKCE | A07 |
| V11 Cryptography | algoritmos débiles, aleatoriedad | A04 |
| V12 Secure Communication | TLS desactivado | A04, A02 |
| V13 Configuration | debug, secretos en config, dependencias | A02, A03 |
| V14 Data Protection | datos sensibles expuestos, caché | A01, A04 |
| V15 Secure Coding and Architecture | dependencias, concurrencia, componentes peligrosos | A03, A08, A10 |
| V16 Security Logging and Error Handling | logs ausentes, fugas en errores, fail-open | A09, A10 |
| V17 WebRTC | (si aplica) | — |

Cita el requisito con el formato de identificador de ASVS 5.0 (`v5.0.0-<capítulo>.<sección>.<requisito>`) **solo tras comprobarlo en el documento oficial**; si no, cita el capítulo.

### 9.2 Plantilla de hallazgo de código

~~~markdown
### [ALTA] Inyección SQL en búsqueda de pedidos (A05 · CWE-89 · ASVS V1)

**Ubicación**: `src/main/java/com/acme/order/OrderRepositoryImpl.java:57`
**Punto de entrada**: `GET /api/orders/search?q=` (usuario autenticado, cualquier rol)
**Estado**: Confirmado en `staging` (2026-11-20 10:42 UTC, cuenta `tester1`)

**Código vulnerable**
```java
String sql = "SELECT * FROM orders WHERE customer_id = " + uid + " AND ref LIKE '%" + q + "%'";
return jdbc.queryForList(sql);
```

**Camino de datos**
1. `OrderController.java:31` — `@RequestParam String q` (fuente)
2. `OrderService.java:74` — `search(uid, q)` sin validación
3. `OrderRepositoryImpl.java:57` — concatenación en `sql` (sumidero `JdbcTemplate.queryForList`)

**Impacto**: lectura de cualquier tabla de la BD (incluida `users.password_hash`).
**PoC**: `q=x'+AND+1=CAST((SELECT+version())+AS+int)--+` → error con la versión de PostgreSQL.

**Corrección**
```diff
- String sql = "SELECT * FROM orders WHERE customer_id = " + uid + " AND ref LIKE '%" + q + "%'";
- return jdbc.queryForList(sql);
+ String sql = "SELECT * FROM orders WHERE customer_id = ? AND ref LIKE ?";
+ return jdbc.queryForList(sql, uid, "%" + q + "%");
```
**Variantes**: misma construcción en `InvoiceRepositoryImpl.java:88` y `ReportDao.java:140` (ver §Variantes).
**Referencias**: ../vulns/sqli.md, CWE-89, ASVS 5.0 V1.
~~~

Buenas prácticas de redacción:
- Enlace permanente al commit revisado (`<repo>/blob/<sha>/ruta#L57`), no a la rama.
- Severidad con CVSS o la escala del cliente; justifica con alcanzabilidad (quién llega) e impacto (qué obtiene).
- La corrección como diff mínimo, más la recomendación de raíz (p. ej., "prohibir `queryForList(String)` con concatenación mediante una regla Semgrep en CI").
- Separa: hallazgos explotables, debilidades sin explotación demostrada, y recomendaciones de endurecimiento.
- Sección de **cobertura**: herramientas y versiones, reglas/suites, build mode de CodeQL, carpetas excluidas, partes no revisadas a mano. Así "no encontramos X" tiene contexto.

---

## 10. Checklist final de revisión

**Preparación**
- [ ] Alcance confirmado: repositorio(s), commit/sha, ramas, entorno de pruebas, cuentas.
- [ ] Repositorio tratado como no confiable: builds e instalaciones en contenedor desechable.
- [ ] Stack, versiones y frameworks inventariados.
- [ ] Tabla completa de puntos de entrada (HTTP, GraphQL, gRPC, WS, colas, cron, webhooks, CLI).

**Modelo de amenazas**
- [ ] Diagrama de flujo con fronteras de confianza.
- [ ] STRIDE por frontera → lista de hipótesis cerradas una a una.

**Automático**
- [ ] Semgrep (OWASP + secretos + lenguaje + framework) ejecutado.
- [ ] CodeQL con `security-extended`; build mode anotado; líneas extraídas ≈ líneas reales.
- [ ] Linter específico del lenguaje ejecutado.
- [ ] SCA sobre lockfiles + imagen desplegada; secretos sobre árbol e historial completo.
- [ ] IaC / Dockerfile / CI escaneados.
- [ ] Resultados triados (fuente, alcanzabilidad, saneador, explotabilidad); falsos positivos justificados.

**Manual**
- [ ] Fuente → sumidero para cada entry point de alto riesgo.
- [ ] Matriz ruta × rol × propiedad completa; métodos hermanos comparados; versiones antiguas de API revisadas.
- [ ] Asignación masiva y exposición de campos en serializadores/DTO.
- [ ] Autenticación, reset de contraseña, MFA, sesión, JWT/OAuth.
- [ ] Criptografía, aleatoriedad, TLS, comparación en tiempo constante.
- [ ] Manejo de errores: sin fail-open, sin fugas, transacciones coherentes.
- [ ] Defaults inseguros y *sharp edges* del lenguaje.
- [ ] Subida/descarga de ficheros, rutas, SSRF, XML, deserialización, plantillas.
- [ ] Front-end: sumideros DOM, `dangerouslySetInnerHTML`/`v-html`/`bypassSecurityTrust*`, source maps, secretos en el bundle.
- [ ] Logging y auditoría de acciones sensibles; nada de secretos en logs.
- [ ] Componentes LLM: entradas no confiables, herramientas, salida a sumideros.

**Cierre**
- [ ] Variantes buscadas para cada hallazgo confirmado (repo, ramas, historial).
- [ ] Hallazgos confirmados dinámicamente cuando hay instancia.
- [ ] Cada hallazgo: `fichero:línea` con sha, snippet, camino de datos, impacto, PoC, diff de corrección, OWASP 2025 + CWE + ASVS.
- [ ] Sección de cobertura y limitaciones escrita.

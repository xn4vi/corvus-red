# Informe de prueba de intrusión — Laboratorio OWASP Juice Shop

| | |
|---|---|
| **Cliente** | Laboratorio propio (prueba de CORVUS Red) |
| **Encargo** | Laboratorio OWASP Juice Shop |
| **Periodo de pruebas** | 2026-11-24 — 2026-11-24 |
| **Tipo de prueba** | caja negra (con registro libre de cuentas) · Entorno: laboratorio local (Docker, imagen oficial bkimminich/juice-shop) |
| **Fecha del informe** | 2026-11-25 |
| **Versión** | 1.0 |

## 1. Resumen ejecutivo

El 24 de noviembre de 2026 se evaluó la seguridad de la tienda online OWASP Juice Shop (versión 20.4.0), desplegada en un laboratorio local, con un enfoque de caja negra y cuentas de cliente creadas durante la prueba.

**Hallazgo principal.** Un atacante sin ninguna cuenta puede entrar en la tienda como cualquier cliente o como administrador, por dos vías independientes: engañando al formulario de inicio de sesión o fabricando él mismo la «credencial digital» que la tienda entrega tras iniciar sesión, que esta acepta sin comprobar su autenticidad. Por otra vía, también sin cuenta, puede consultar la base de datos de clientes, con sus correos, tarjetas y direcciones guardadas.

**Veredicto de riesgo.** La postura de seguridad es **deficiente**. Los fallos más graves no requieren conocimientos avanzados ni condiciones especiales, afectan a todos los clientes y exponen datos personales y de pago, con la consiguiente exposición regulatoria (RGPD y PCI DSS). Además, cualquier cliente registrado puede ver información interna de autenticación de todos los demás usuarios, incluidos los secretos del segundo factor de autenticación, y documentos internos marcados como confidenciales están publicados en la web.

**Recomendaciones estratégicas**

1. **Eliminar la construcción manual de consultas a la base de datos** en toda la aplicación y adoptar de forma obligatoria consultas parametrizadas, con una revisión de código específica antes de cada despliegue.
2. **Centralizar la autenticación y la autorización** en un componente común que verifique de forma estricta las credenciales digitales (algoritmo fijo, caducidad y revocación) y compruebe en el servidor el rol y la propiedad de cada dato antes de devolverlo.
3. **Revisar qué se publica**: retirar de la web documentos, copias de seguridad y paneles internos, y no devolver nunca en las respuestas datos de autenticación como los hashes de contraseñas o los secretos del segundo factor.

| Severidad | Hallazgos |
|---|---|
| Crítica | 2 |
| Alta | 2 |
| Media | 5 |
| Baja | 1 |
| Informativa | 1 |

**Nivel de riesgo global:** Crítica

## 2. Alcance y metodología

### En alcance

- `http://127.0.0.1:3000/*`
- `localhost:3000`

### Fuera de alcance

- `*.github.com`
- `github.com`

### Restricciones

- **Ritmo máximo:** 5 peticiones/s por host (1/s en formularios de inicio de sesión)
- **Horario permitido:** sin restricción
- **IP de origen:** 
- **OAST externo (interactsh/Collaborator):** permitido
- **Endpoints sensibles:** 
- **Acciones vetadas:** denegación de servicio, ingeniería social, pagos reales

### Metodología

Las pruebas siguieron la **OWASP Web Security Testing Guide (WSTG)** y se apoyaron en OWASP Top 10:2025, OWASP API Security Top 10:2023, OWASP Top 10 para aplicaciones LLM (2025) y OWASP ASVS 5.0 cuando procedía. Cada hallazgo se verificó manualmente y superó un proceso de validación de siete puntos (prueba de concepto reproducible, evidencia HTTP, impacto demostrado, pertenencia al alcance, vulnerabilidad real, reproducibilidad por el cliente y severidad justificada). La severidad se expresa con CVSS v3.1 (y CVSS v4.0 cuando se indica).

#### Cobertura por categoría OWASP WSTG

| Categoría | IDs | Probado | Fecha | Notas |
|---|---|---|---|---|
| Recogida de información | WSTG-INFO-01..10 | Sí | 2026-11-24 | robots, JS, swagger, versión |
| Configuración y despliegue | WSTG-CONF-01..13 | Parcial | 2026-11-24 | listados, endpoints internos; sin TLS (local) |
| Gestión de identidades | WSTG-IDNT-01..05 | Parcial | 2026-11-24 | registro: asignación masiva F-004 |
| Autenticación | WSTG-ATHN-01..11 | Parcial | 2026-11-24 | SQLi login F-002; sin pruebas de MFA ni fuerza bruta |
| Autorización | WSTG-ATHZ-01..05 | Sí | 2026-11-24 | IDOR F-003, BFLA F-005, bypass extensiones F-008 |
| Gestión de sesiones | WSTG-SESS-01..10 | Parcial | 2026-11-24 | JWT F-006/F-010 |
| Validación de entradas | WSTG-INPV-01..20 | Parcial | 2026-11-24 | SQLi F-001/F-002; sin SSRF/XXE/SSTI |
| Gestión de errores | WSTG-ERRH-01..02 | Sí | 2026-11-24 | trazas SQLite visibles (en F-001) |
| Criptografía | WSTG-CRYP-01..04 | Parcial | 2026-11-24 | hashes de contraseña expuestos (F-005); TLS N/A |
| Lógica de negocio | WSTG-BUSL-01..10 | No | 2026-11-24 | fuera del tiempo de la prueba |
| Lado del cliente | WSTG-CLNT-01..14 | Parcial | 2026-11-24 | XSS DOM F-009 |
| APIs | WSTG-APIT-01 | Parcial | 2026-11-24 | asignación masiva y BFLA |
| IA/LLM (OWASP LLM Top 10:2025) | LLM01..10 | No | 2026-11-24 | chatbot /rest/chat no probado |

## 3. Resumen de hallazgos

| ID | Título | Severidad | CVSS | Estado |
|---|---|---|---|---|
| F-002 | Inyección SQL en el inicio de sesión permite entrar como cualquier usuario, incluido el administrador, sin contraseña | Crítica | 9.1 | Abierto |
| F-006 | El servidor acepta JWT sin firma (alg:none): suplantación de cualquier usuario | Crítica | 9.1 | Abierto |
| F-001 | Inyección SQL en la búsqueda de productos permite leer toda la base de datos sin autenticación | Alta | 7.5 | Abierto |
| F-005 | Falta de control por función: cualquier cliente obtiene los hashes de contraseña y secretos TOTP de todos los usuarios | Alta | 6.5 | Abierto |
| F-009 | XSS basado en DOM en la búsqueda permite ejecutar JavaScript en el navegador de la víctima | Media | 6.1 | Abierto |
| F-004 | Asignación masiva en el registro permite crear cuentas con rol de administrador | Media | 5.3 | Abierto |
| F-007 | El directorio /ftp está listado y sirve documentos confidenciales sin autenticación | Media | 5.3 | Abierto |
| F-008 | El filtro de extensiones de /ftp se salta con un byte nulo y expone copias de seguridad | Media | 5.3 | Abierto |
| F-003 | IDOR en las cestas: un cliente puede leer la cesta de cualquier otro cliente | Media | 4.3 | Abierto |
| F-010 | El JWT no caduca e incluye el hash de la contraseña y el secreto TOTP | Baja | 3.7 | Abierto |
| F-011 | Endpoints de operación y directorios internos accesibles sin autenticación | Informativa | 0.0 | Abierto |

## 4. Hallazgos detallados

<div class="finding sev-Crítica"></div>

### F-002 — Inyección SQL en el inicio de sesión permite entrar como cualquier usuario, incluido el administrador, sin contraseña

| | |
|---|---|
| **Severidad** | Crítica |
| **CVSS v3.1** | 9.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **CWE** | CWE-89 — Improper Neutralization of Special Elements used in an SQL Command |
| **OWASP** | A07:2025 — Authentication Failures |
| **WSTG** | WSTG-INPV-05, WSTG-ATHN-04 |
| **Endpoint** | `POST http://127.0.0.1:3000/rest/user/login` |
| **Estado** | Abierto |

#### Descripción

El campo `email` del inicio de sesión se concatena en la consulta que comprueba las credenciales. Si se cierra la cadena y se comenta el resto (`admin@juice-sh.op'--`), la comprobación de la contraseña desaparece de la consulta y el servidor emite un token válido para esa cuenta.

#### Prueba de concepto

**Petición:**

```http
POST /rest/user/login HTTP/1.1
Host: 127.0.0.1:3000
Content-Type: application/json

{"email":"admin@juice-sh.op'--","password":"[REDACTED len=10]"}
```

**Respuesta (extracto relevante):**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"authentication":{"token":"[REDACTED-JWT len=717]","bid":1,"umail":"admin@juice-sh.op"}}
```

Control: la cuenta de prueba B con una contraseña incorrecta devuelve 401 (`F-002-control.http`). La misma contraseña incorrecta con `'--` tras el correo devuelve 200 y un token firmado por el servidor (RS256) con la identidad `id=27, email=corvus-b@lab.test` (`F-002b-bypass-B.http`). Con ese token se añadió un artículo a la cesta de B (200, `F-002d-write-as-B.http`). Contra `admin@juice-sh.op` el mismo payload devuelve un token con `umail: admin@juice-sh.op` y `bid: 1` (`F-002-sqli-login.http`). Payload dirigido a una única cuenta, sin tautologías. (`F-002c-whoami.http` devuelve `{"user":{}}` porque `whoami` lee la cookie `token` y esa petición solo llevaba la cabecera `Authorization`; no se usa como prueba.)

Evidencia: `evidence/F-002-sqli-login.http`, `evidence/F-002-control.http`, `evidence/F-002b-bypass-B.http`, `evidence/F-002d-write-as-B.http`.

#### Pasos para reproducir

1. Enviar la petición de la PoC con cualquier valor en `password`.
2. Comprobar en la respuesta `umail: admin@juice-sh.op` (o, contra la cuenta B, la identidad `id=27` del token anotada en `F-002b-bypass-B.http`).
3. Usar el token en `Authorization: Bearer` contra cualquier endpoint autenticado.

#### Impacto

Toma de control inmediata de cualquier cuenta cuyo correo se conozca (los correos se obtienen con F-001 y F-005), incluida la del administrador. Compromete la confidencialidad y la integridad de los datos de todos los clientes.

#### Remediación

1. **Corregir la causa raíz:** buscar al usuario con una consulta parametrizada (`User.findOne({ where: { email } })`) y comparar en el código el hash de la contraseña, calculado con bcrypt o Argon2, en tiempo constante.
2. **Defensa en profundidad:** límite de intentos y MFA para las cuentas privilegiadas.
3. **Detección:** alertar de inicios de sesión con `'`, `--` o `/*` en el usuario.

#### Referencias

- https://cwe.mitre.org/data/definitions/89.html
- https://owasp.org/www-project-web-security-testing-guide/

#### Notas para el retest

Repetir la PoC: debe responder 401 «Invalid email or password».

<div class="finding sev-Crítica"></div>

### F-006 — El servidor acepta JWT sin firma (alg:none): suplantación de cualquier usuario

| | |
|---|---|
| **Severidad** | Crítica |
| **CVSS v3.1** | 9.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **CWE** | CWE-347 — Improper Verification of Cryptographic Signature |
| **OWASP** | A07:2025 — Authentication Failures |
| **WSTG** | WSTG-SESS-10 |
| **Endpoint** | `Todos los endpoints autenticados (p. ej. GET /rest/user/whoami)` |
| **Estado** | Abierto |

#### Descripción

Los tokens se emiten con RS256, pero el servidor acepta un token con la cabecera `{"alg":"none"}` y la firma vacía, de modo que cualquiera puede fabricar un token con la identidad que quiera.

#### Prueba de concepto

**Petición:**

```http
GET /rest/user/whoami HTTP/1.1
Host: 127.0.0.1:3000
Authorization: Bearer [REDACTED-JWT]
# cabecera: {"typ":"JWT","alg":"none"} · payload: datos de la cuenta A con el email y el id de la cuenta B · firma: vacía
```

**Respuesta (extracto relevante):**

```http
HTTP/1.1 200 OK

{"user":{"id":27,"email":"corvus-b@lab.test",…}}
```

Cada evidencia anota la cabecera del token enviado: `alg=none, firma=vacía`. Con la identidad de B (`id=27`): `whoami` devuelve B (`F-006-jwt-none.http`), se lee su cesta (`F-006b`) y se añade un artículo a ella (200, `F-006c`). Con la identidad del administrador (`id=1, role=admin`): `whoami` devuelve `admin@juice-sh.op` (`F-006d`). Control: el mismo payload alterado con la firma RS256 original se rechaza (`{"user":{}}`, `F-006e-control-rs256.http`), así que la causa es la aceptación de `none`.

Evidencia: `evidence/F-006-jwt-none.http`, `evidence/F-006b-read-basket.http`, `evidence/F-006c-write-as-B.http`, `evidence/F-006d-admin.http`, `evidence/F-006e-control-rs256.http`.

#### Pasos para reproducir

1. Decodificar un token propio y cambiar `data.email` y `data.id` por los de la víctima.
2. Codificar la cabecera `{"typ":"JWT","alg":"none"}`, unirla al payload modificado y dejar la firma vacía (`cabecera.payload.`).
3. Enviar el token a `/rest/user/whoami`.

#### Impacto

Suplantación de cualquier usuario, incluido el administrador, sin credenciales y sin explotar ningún otro fallo. Compromete la confidencialidad y la integridad de todas las cuentas.

#### Remediación

1. **Corregir la causa raíz:** verificar con una lista fija de algoritmos (`jwt.verify(token, publicKey, { algorithms: ['RS256'] })`) y rechazar `none`; actualizar `express-jwt`/`jsonwebtoken` a versiones que no lo acepten por defecto.
2. **Defensa en profundidad:** añadir `exp`, `iss` y `aud` y validarlos.
3. **Detección:** registrar y alertar de tokens con `alg` distinto de RS256.

#### Referencias

- https://cwe.mitre.org/data/definitions/347.html
- https://portswigger.net/web-security/jwt

#### Notas para el retest

Repetir con el token `alg:none`: debe responder 401.

<div class="finding sev-Alta"></div>

### F-001 — Inyección SQL en la búsqueda de productos permite leer toda la base de datos sin autenticación

| | |
|---|---|
| **Severidad** | Alta |
| **CVSS v3.1** | 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **CWE** | CWE-89 — Improper Neutralization of Special Elements used in an SQL Command |
| **OWASP** | A05:2025 — Injection |
| **WSTG** | WSTG-INPV-05 |
| **Endpoint** | `GET http://127.0.0.1:3000/rest/products/search?q=` |
| **Estado** | Abierto |

#### Descripción

El parámetro `q` de `/rest/products/search` se concatena dentro de una consulta SQL de SQLite. Una comilla simple rompe la sintaxis (`SQLITE_ERROR`), dos comillas la reparan y `app'||'le` devuelve los mismos resultados que `apple`, lo que prueba que el motor evalúa la entrada como código SQL. Con `UNION SELECT` de 10 columnas se leen tablas arbitrarias.

#### Prueba de concepto

**Petición:**

```http
GET /rest/products/search?q=zzz'))%20UNION%20SELECT%20(SELECT%20count(*)%20FROM%20Users),email,role,substr(password,1,6)||'...',5,6,7,8,9,10%20FROM%20Users%20WHERE%20id=1-- HTTP/1.1
Host: 127.0.0.1:3000
```

**Respuesta (extracto relevante):**

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"status":"success","data":[{"id":27,"name":"admin@juice-sh.op","description":"admin","price":"019202...", …}]}
```

`id` = número total de usuarios (27 en ese momento), `name` = correo del administrador, `description` = rol, `price` = primeros 6 caracteres del hash de su contraseña (truncado a propósito en la propia consulta).

Evidencia: `evidence/F-001-sqli-search.http`, `evidence/F-001b-sqli-counts.http`.

#### Pasos para reproducir

1. Sin sesión, enviar `GET /rest/products/search?q=apple'` y observar el error `SQLITE_ERROR: near "'%'": syntax error`.
2. Enviar `q=app'||'le` y comprobar que devuelve los mismos productos que `q=apple`.
3. Enviar la petición de la PoC y observar los datos de la tabla `Users` en la respuesta.
4. Repetir con la consulta de `evidence/F-001b-sqli-counts.http` (recuentos de `Cards` y `Addresses` y fila `id=2`).

#### Impacto

Un atacante sin cuenta ejecuta consultas SELECT arbitrarias sobre la base de datos. Verificado: recuento de usuarios (27), correo, rol y prefijo del hash de contraseña de dos usuarios (id 1, administrador, e id 2), y recuento de las tablas `Cards` (6) y `Addresses` (6), lo que confirma el acceso a tarjetas y direcciones guardadas. Por minimización no se extrajeron más datos.

#### Remediación

1. **Corregir la causa raíz:** usar consultas parametrizadas de Sequelize (`sequelize.query(sql, { replacements: { q } })` o `Product.findAll({ where: { name: { [Op.like]: '%' + q + '%' } } })`) en lugar de interpolar `q` en la cadena SQL.
2. **Defensa en profundidad:** no devolver mensajes del motor al cliente (gestor de errores genérico) y dar a la cuenta de base de datos el mínimo privilegio.
3. **Detección:** alertar de errores `SQLITE_ERROR` y de patrones `UNION SELECT` en los registros de acceso.

#### Referencias

- https://cwe.mitre.org/data/definitions/89.html
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

#### Notas para el retest

Repetir `GET /rest/products/search?q=apple'`: debe devolver 200 con lista vacía, o un error genérico sin mensaje de SQLite. La PoC UNION no debe devolver datos de `Users`.

<div class="finding sev-Alta"></div>

### F-005 — Falta de control por función: cualquier cliente obtiene los hashes de contraseña y secretos TOTP de todos los usuarios

| | |
|---|---|
| **Severidad** | Alta |
| **CVSS v3.1** | 6.5 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **CWE** | CWE-285 — Improper Authorization |
| **OWASP** | A01:2025 — Broken Access Control |
| **WSTG** | WSTG-ATHZ-02, WSTG-ATHZ-03 |
| **Endpoint** | `GET http://127.0.0.1:3000/rest/user/authentication-details/` |
| **Afectados** | GET /api/Users |
| **Estado** | Abierto |

#### Descripción

Endpoints pensados para administración solo exigen un token válido, sin comprobar el rol. `/rest/user/authentication-details/` devuelve todos los usuarios con `password` (hash de 32 caracteres hexadecimales), `totpSecret`, `role`, `lastLoginIp` y `lastLoginTime`. `/api/Users` devuelve el listado completo de correos y roles.

#### Prueba de concepto

**Petición:**

```http
GET /rest/user/authentication-details/ HTTP/1.1
Host: 127.0.0.1:3000
Authorization: Bearer [REDACTED-JWT len=727]   ← cuenta de prueba A, rol customer
```

**Respuesta (extracto relevante):**

```http
HTTP/1.1 200 OK

{"status":"success","data":[{"id":1,"email":"admin@juice-sh.op","password":"[REDACTED len=32]","role":"admin","totpSecret":"","lastLoginIp":"",…}, … 28 registros]}
```

La evidencia anota la identidad del token: `id=26, role=customer`. La respuesta contiene 28 registros con `password` y `totpSecret`; uno de ellos (una cuenta de administrador) tiene el 2FA activado y su secreto TOTP queda expuesto. `/api/Users` expone además el `deluxeToken` de 4 usuarios. Los valores se tacharon en la evidencia. Comprobación local (`F-005c-md5-check.txt`): el hash **no** es el MD5 simple de la contraseña, así que no se afirma la facilidad de recuperarla.

Evidencia: `evidence/F-005b-auth-details.http`, `evidence/F-005-bfla-users.http`, `evidence/F-005c-md5-check.txt`.

#### Pasos para reproducir

1. Registrar una cuenta normal e iniciar sesión.
2. Pedir `GET /rest/user/authentication-details/` con su token.
3. Observar el hash y el secreto TOTP de cada usuario.

#### Impacto

Con el `totpSecret` expuesto se generan códigos válidos del segundo factor de la cuenta que tiene 2FA, y los hashes de todos los usuarios quedan disponibles para ataques offline. **Ajuste por impacto de negocio:** el CVSS base es 6.5 (Media), pero se eleva a Alta porque expone el material de autenticación de todos los usuarios y anula el MFA.

#### Remediación

1. **Corregir la causa raíz:** exigir rol de administrador en el servidor en todos los endpoints de administración y no devolver nunca `password` ni `totpSecret` (atributos excluidos por defecto en el modelo).
2. **Defensa en profundidad:** almacenar las contraseñas con Argon2id o bcrypt y cifrar los secretos TOTP en reposo.
3. **Detección:** alertar de accesos de roles no administradores a rutas de administración.

#### Referencias

- https://cwe.mitre.org/data/definitions/285.html
- https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/

#### Notas para el retest

Con un token de cliente, `GET /rest/user/authentication-details/` y `GET /api/Users` deben responder 403. Con un administrador no deben aparecer `password` ni `totpSecret`.

<div class="finding sev-Media"></div>

### F-009 — XSS basado en DOM en la búsqueda permite ejecutar JavaScript en el navegador de la víctima

| | |
|---|---|
| **Severidad** | Media |
| **CVSS v3.1** | 6.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **CWE** | CWE-79 — Improper Neutralization of Input During Web Page Generation |
| **OWASP** | A05:2025 — Injection |
| **WSTG** | WSTG-CLNT-01 |
| **Endpoint** | `GET http://127.0.0.1:3000/#/search?q=` |
| **Estado** | Abierto |

#### Descripción

El front-end Angular inserta el término de búsqueda en la página marcándolo como HTML de confianza, lo que salta el saneado de Angular. El HTML del parámetro `q` del fragmento se interpreta y ejecuta.

#### Prueba de concepto

**Petición:**

```http
http://127.0.0.1:3000/#/search?q=%3Cimg%20src%3Dx%20onerror%3D%22console.log('CORVUS-XSS-'%2Bdocument.domain)%22%3E
```

**Respuesta (extracto relevante):**

```http
Consola del navegador (Chromium):
[log] CORVUS-XSS-127.0.0.1
```

Reproducido en dos navegadores: el Chromium integrado y Google Chrome headless con un perfil nuevo y vacío. Este último registró en su consola `CORVUS-XSS-127.0.0.1-cookie_len=11` (`F-009-dom-xss.txt`). Sumidero localizado en `main.js`: `this.searchValue=this.sanitizer.bypassSecurityTrustHtml(t)`, en el componente de resultados de búsqueda. Payload inocuo, sin `alert` ni robo de datos.

Evidencia: `evidence/F-009-dom-xss.txt`.

#### Pasos para reproducir

1. Abrir la URL de la PoC en un navegador actual (perfil limpio).
2. Abrir las herramientas de desarrollo → Consola y ver `CORVUS-XSS-127.0.0.1`.

#### Impacto

Un atacante que consiga que la víctima abra un enlace ejecuta JavaScript en el origen de la aplicación, con las acciones que permita la sesión de la víctima. La cookie de sesión `token` se emite sin `HttpOnly` (se ve en el `Set-Cookie` de la evidencia de F-006), así que el script podría leerla; el robo de una sesión real no se ha demostrado.

#### Remediación

1. **Corregir la causa raíz:** no usar `bypassSecurityTrustHtml` con datos del usuario; mostrar el término con interpolación de texto (`{{ q }}`).
2. **Defensa en profundidad:** CSP estricta (`script-src 'self'`, sin `unsafe-inline`) y cookies de sesión `HttpOnly`.
3. **Detección:** recoger los informes de violación de CSP.

#### Referencias

- https://cwe.mitre.org/data/definitions/79.html
- https://angular.dev/best-practices/security

#### Notas para el retest

Abrir la URL de la PoC: no debe aparecer el marcador en la consola y el texto debe mostrarse literal.

<div class="finding sev-Media"></div>

### F-004 — Asignación masiva en el registro permite crear cuentas con rol de administrador

| | |
|---|---|
| **Severidad** | Media |
| **CVSS v3.1** | 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **CWE** | CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| **OWASP** | A01:2025 — Broken Access Control |
| **WSTG** | WSTG-INPV-20 |
| **Endpoint** | `POST http://127.0.0.1:3000/api/Users/` |
| **Estado** | Abierto |

#### Descripción

El alta de usuarios guarda todos los campos del JSON recibido, incluido `role`, que el usuario no debería poder elegir.

#### Prueba de concepto

**Petición:**

```http
POST /api/Users/ HTTP/1.1
Host: 127.0.0.1:3000
Content-Type: application/json

{"email":"corvus-c@lab.test","password":"[REDACTED len=17]","passwordRepeat":"[REDACTED len=17]","role":"admin"}
```

**Respuesta (extracto relevante):**

```http
HTTP/1.1 201 Created

{"status":"success","data":{…,"id":28,"email":"corvus-c@lab.test","role":"admin",…}}
```

La cuenta se crea con `role: admin`. Al iniciar sesión con la cuenta D, creada igual, el servidor emite un token RS256 con `id=29, role=admin` (`F-004b-admin-identity.http`). En los endpoints de API probados (`/rest/user/authentication-details`, `/api/Quantitys`, `/api/Complaints`, `/api/Deliverys`, `/api/Cards`, `/api/Recycles`) la respuesta fue idéntica para un cliente y para este administrador, porque esos endpoints no controlan la función (ver F-005). El impacto demostrado se limita por tanto a la persistencia de un rol privilegiado elegido por el atacante (integridad del dato de autorización).

Evidencia: `evidence/F-004-mass-assignment.http`, `evidence/F-004b-admin-identity.http`.

#### Pasos para reproducir

1. Enviar la petición de la PoC.
2. Iniciar sesión con la cuenta creada y decodificar el JWT (`corvus.py jwt <token>`): `role: admin`.

#### Impacto

Cualquier visitante obtiene una identidad de administrador sin aprobación. Hoy el servidor apenas diferencia los roles (F-005); en cuanto se añadan controles por rol, este fallo los anularía.

#### Remediación

1. **Corregir la causa raíz:** aceptar en el alta solo una lista blanca de campos (`email`, `password`, `passwordRepeat`, `securityQuestion`, `securityAnswer`) y fijar `role = 'customer'` en el servidor.
2. **Defensa en profundidad:** modelos de entrada (DTO) separados de los de persistencia.
3. **Detección:** alertar de altas con un `role` distinto de `customer`.

#### Referencias

- https://cwe.mitre.org/data/definitions/915.html
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

#### Notas para el retest

Repetir la PoC: la cuenta debe crearse con `role: customer` o la petición debe rechazarse.

<div class="finding sev-Media"></div>

### F-007 — El directorio /ftp está listado y sirve documentos confidenciales sin autenticación

| | |
|---|---|
| **Severidad** | Media |
| **CVSS v3.1** | 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-548 — Exposure of Information Through Directory Listing |
| **OWASP** | A02:2025 — Security Misconfiguration |
| **WSTG** | WSTG-CONF-04, WSTG-CONF-05 |
| **Endpoint** | `GET http://127.0.0.1:3000/ftp/` |
| **Afectados** | /ftp/acquisitions.md |
| **Estado** | Abierto |

#### Descripción

`/ftp/` tiene el listado de directorios activado y sirve documentos internos sin autenticación. `robots.txt` señala `/ftp` en lugar de protegerlo.

#### Prueba de concepto

**Petición:**

```http
GET /ftp/ HTTP/1.1
Host: 127.0.0.1:3000

GET /ftp/acquisitions.md HTTP/1.1
Host: 127.0.0.1:3000
```

**Respuesta (extracto relevante):**

```http
HTTP/1.1 200 OK

# Planned Acquisitions

> This document is confidential! Do not distribute!
…
```

El listado de `/ftp/` (`F-007-ftp-listing.http`) muestra 13 entradas (11 ficheros y carpetas más las de navegación), entre ellas `acquisitions.md`, `incident-support.kdbx`, `coupons_2013.md.bak` y `package.json.bak`. `acquisitions.md`, marcado como confidencial, se descarga sin autenticación (`F-007b-acquisitions.http`). El resto de exposiciones de configuración se recogen como informativas en F-011.

Evidencia: `evidence/F-007-ftp-listing.http`, `evidence/F-007b-acquisitions.http`.

#### Pasos para reproducir

1. Abrir `http://127.0.0.1:3000/ftp/` sin sesión.
2. Descargar `acquisitions.md`.
3. Comprobar que el documento se declara confidencial.

#### Impacto

Filtración a cualquier visitante de información confidencial de negocio: adquisiciones previstas, con impacto bursátil según el propio documento.

#### Remediación

1. **Corregir la causa raíz:** desactivar el listado de directorios en estas rutas y sacar de la raíz web los documentos internos, las claves y los registros.
2. **Defensa en profundidad:** clasificar los documentos y servir los internos solo tras autenticación y autorización.
3. **Detección:** alertar de accesos externos a estas rutas.

#### Referencias

- https://cwe.mitre.org/data/definitions/548.html
- https://owasp.org/www-project-web-security-testing-guide/

#### Notas para el retest

`/ftp/` y `/ftp/acquisitions.md` deben responder 401, 403 o 404 sin sesión.

<div class="finding sev-Media"></div>

### F-008 — El filtro de extensiones de /ftp se salta con un byte nulo y expone copias de seguridad

| | |
|---|---|
| **Severidad** | Media |
| **CVSS v3.1** | 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-158 — Improper Neutralization of Null Byte or NUL Character |
| **OWASP** | A01:2025 — Broken Access Control |
| **WSTG** | WSTG-ATHZ-01, WSTG-CONF-03 |
| **Endpoint** | `GET http://127.0.0.1:3000/ftp/{fichero}%2500.md` |
| **Estado** | Abierto |

#### Descripción

`/ftp` solo debería servir `.md` y `.pdf` (responde 403 «Only .md and .pdf files are allowed!»), pero comprueba la extensión sobre la ruta todavía codificada. Con `%2500.md` la validación ve `.md` y, tras decodificar, se sirve el fichero real truncado en el byte nulo.

#### Prueba de concepto

**Petición:**

```http
GET /ftp/package.json.bak%2500.md HTTP/1.1
Host: 127.0.0.1:3000
```

**Respuesta (extracto relevante):**

```http
HTTP/1.1 200 OK

{
  "name": "juice-shop",
  "version": "6.2.0-SNAPSHOT",
  …
}
```

Control: `/ftp/coupons_2013.md.bak` devuelve 403 (`F-008-control-403.http`). Con `%2500.md` devuelve 200 y 12 códigos de cupón (`F-008b-coupons.http`). También se obtuvo `package.json.bak` (`F-008-ftp-nullbyte.http`).

Evidencia: `evidence/F-008-control-403.http`, `evidence/F-008b-coupons.http`, `evidence/F-008-ftp-nullbyte.http`.

#### Pasos para reproducir

1. Pedir `/ftp/coupons_2013.md.bak` y observar el 403.
2. Pedir `/ftp/coupons_2013.md.bak%2500.md` y observar el 200 con los códigos de cupón.

#### Impacto

Acceso a ficheros que la aplicación pretendía bloquear: se leyeron los códigos de cupón de 2013 y una copia antigua de `package.json`. Otros ficheros bloqueados del mismo directorio (como `incident-support.kdbx`) quedan al alcance con la misma técnica, pero no se descargaron. Comparte activo con F-007.

#### Remediación

1. **Corregir la causa raíz:** decodificar y normalizar la ruta antes de validarla, rechazar rutas con `\0` y servir solo los ficheros de una lista blanca.
2. **Defensa en profundidad:** no guardar copias `.bak` ni bases de datos de contraseñas en directorios servidos.
3. **Detección:** alertar de peticiones con `%00` o `%2500`.

#### Referencias

- https://cwe.mitre.org/data/definitions/158.html
- https://owasp.org/www-community/attacks/Path_Traversal

#### Notas para el retest

`/ftp/coupons_2013.md.bak%2500.md` debe responder 400 o 403.

<div class="finding sev-Media"></div>

### F-003 — IDOR en las cestas: un cliente puede leer la cesta de cualquier otro cliente

| | |
|---|---|
| **Severidad** | Media |
| **CVSS v3.1** | 4.3 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-639 — Authorization Bypass Through User-Controlled Key |
| **OWASP** | A01:2025 — Broken Access Control |
| **WSTG** | WSTG-ATHZ-04 |
| **Endpoint** | `GET http://127.0.0.1:3000/rest/basket/{id}` |
| **Estado** | Abierto |

#### Descripción

`/rest/basket/{id}` exige estar autenticado, pero no comprueba que la cesta pedida pertenezca al usuario del token. Basta con cambiar el identificador numérico.

#### Prueba de concepto

**Petición:**

```http
GET /rest/basket/7 HTTP/1.1
Host: 127.0.0.1:3000
Authorization: Bearer [REDACTED-JWT len=727]   ← token de la cuenta de prueba A (su cesta es la 6)
```

**Respuesta (extracto relevante):**

```http
HTTP/1.1 200 OK

{"status":"success","data":{"id":7,"coupon":null,"UserId":27,"Products":[{"id":1,"name":"Apple Juice (1000ml)", … "BasketItem":{"quantity":1}}]}}
```

La evidencia anota la identidad del token enviado: `id=26, email=corvus-a@lab.test, role=customer`. La respuesta es la cesta 7 con `UserId: 27` (cuenta B) y sus productos. Sin token la respuesta es 401 (registro de payloads), así que el fallo es de autorización y no de autenticación.

Evidencia: `evidence/F-003-idor-basket.http`.

#### Pasos para reproducir

1. Registrar dos cuentas, A y B, e iniciar sesión con ambas.
2. Con B, añadir un producto a su cesta (`POST /api/BasketItems`).
3. Con el token de A, pedir `GET /rest/basket/<id de la cesta de B>`.

#### Impacto

Cualquier cliente ve el contenido de las cestas ajenas, y los ID son secuenciales, así que se enumeran todas. El dato expuesto es de baja sensibilidad (productos y cupón), por eso la severidad es Media.

#### Remediación

1. **Corregir la causa raíz:** obtener la cesta a partir del usuario del token (`Basket.findOne({ where: { id, UserId: req.user.id } })`) y devolver 403 o 404 si no coincide.
2. **Defensa en profundidad:** identificadores no secuenciales.
3. **Detección:** alertar cuando un usuario accede a cestas distintas de la suya.

#### Referencias

- https://cwe.mitre.org/data/definitions/639.html
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/

#### Notas para el retest

Con el token de A, `GET /rest/basket/7` debe responder 403 o 404.

<div class="finding sev-Baja"></div>

### F-010 — El JWT no caduca e incluye el hash de la contraseña y el secreto TOTP

| | |
|---|---|
| **Severidad** | Baja |
| **CVSS v3.1** | 3.7 — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-613 — Insufficient Session Expiration |
| **OWASP** | A07:2025 — Authentication Failures |
| **WSTG** | WSTG-SESS-10, WSTG-SESS-07 |
| **Endpoint** | `POST http://127.0.0.1:3000/rest/user/login (token emitido)` |
| **Estado** | Abierto |

#### Descripción

El token emitido al iniciar sesión no tiene `exp` y vale indefinidamente. Además transporta, solo codificado en Base64, el objeto de usuario completo: `password` (hash de 32 caracteres), `totpSecret` y `lastLoginIp`.

#### Prueba de concepto

**Petición:**

```http
POST /rest/user/login HTTP/1.1
Host: 127.0.0.1:3000
Content-Type: application/json

{"email":"corvus-a@lab.test","password":"[REDACTED]"}
```

**Respuesta (extracto relevante):**

```http
Payload decodificado del token:
{"data":{"id":…,"email":"corvus-a@lab.test","password":"[REDACTED len=32]","role":"customer","totpSecret":"",…},"bid":6,"iat":…}   ← sin "exp"
```

Claves del payload: `data`, `bid` e `iat`, sin `exp` (`F-010-token-claims.txt`). `data` incluye `password` y `totpSecret`. Falta de revocación demostrada: la contraseña de la cuenta A se cambió a las 11:25:58Z (registro de payloads); después, la contraseña antigua se rechaza (401, `F-010c-control-oldpw.http`), pero el token con `iat=2026-11-24T11:10:09Z`, emitido antes del cambio, sigue aceptado (200; la línea de identidad de `F-010b-token-after-pwchange.http` muestra `iat` y `exp=ausente`).

Evidencia: `evidence/F-010-token-claims.txt`, `evidence/F-010b-token-after-pwchange.http`, `evidence/F-010c-control-oldpw.http`.

#### Pasos para reproducir

1. Iniciar sesión con una cuenta de prueba y guardar el token.
2. Decodificarlo (`corvus.py jwt <token>`): no hay `exp`.
3. Cambiar la contraseña y repetir una petición autenticada con el token antiguo: sigue funcionando.

#### Impacto

Un token filtrado (registros, historial o un XSS como F-009) sirve para siempre, incluso después de que la víctima cambie la contraseña, y además entrega su hash y su secreto de segundo factor. Requiere obtener antes el token, por eso la severidad es Baja. Comparte causa raíz con F-005 (serialización completa del modelo User).

#### Remediación

1. **Corregir la causa raíz:** incluir en el token solo el identificador y el rol, con un `exp` corto (15–60 min) y renovación mediante refresh token.
2. **Defensa en profundidad:** revocar los tokens al cambiar la contraseña.
3. **Detección:** rechazar y registrar tokens sin `exp`.

#### Referencias

- https://cwe.mitre.org/data/definitions/613.html
- https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

#### Notas para el retest

Decodificar un token nuevo: debe tener `exp` y no contener `password` ni `totpSecret`.

<div class="finding sev-Informativa"></div>

### F-011 — Endpoints de operación y directorios internos accesibles sin autenticación

| | |
|---|---|
| **Severidad** | Informativa |
| **CWE** | CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor |
| **OWASP** | A02:2025 — Security Misconfiguration |
| **WSTG** | WSTG-CONF-05, WSTG-INFO-02 |
| **Endpoint** | `GET http://127.0.0.1:3000/metrics` |
| **Afectados** | /rest/admin/application-configuration, /rest/admin/application-version, /encryptionkeys/, /support/logs/ |
| **Estado** | Abierto |

#### Descripción

Sin autenticación se accede a métricas internas de Prometheus, a la configuración completa de la aplicación (36 KB), a su versión exacta y a los listados de `/encryptionkeys/` (`jwt.pub`, `premium.key`) y `/support/logs/` (`access.log`).

#### Prueba de concepto

**Petición:**

```http
GET /metrics HTTP/1.1
Host: 127.0.0.1:3000

GET /rest/admin/application-version HTTP/1.1
Host: 127.0.0.1:3000
```

**Respuesta (extracto relevante):**

```http
HTTP/1.1 200 OK
Content-Type: text/plain; version=0.0.4

juiceshop_startup_duration_seconds{task="validateConfig",app="juiceshop"} 0.19…

HTTP/1.1 200 OK

{"version":"20.4.0-SNAPSHOT"}
```

Peticiones y respuestas capturadas: `F-011-metrics.http`, `F-011-rest-admin-application-version.http`, `F-011-rest-admin-application-configuration.http`, `F-011-encryptionkeys.http` y `F-011-support-logs.http` (todas 200 sin sesión). No se identificaron secretos explotables: `jwt.pub` es una clave pública y el `access.log` solo contiene peticiones del propio auditor.

#### Pasos para reproducir

1. Sin sesión, pedir `/metrics`, `/rest/admin/application-configuration`, `/rest/admin/application-version`, `/encryptionkeys/` y `/support/logs/`.

#### Impacto

Sin impacto directo demostrado. Facilitan el reconocimiento (versión exacta, configuración y estructura interna) y en un entorno real con tráfico de otros usuarios podrían exponer sus datos.

#### Remediación

1. Restringir estas rutas a administradores o a la red interna y desactivar el listado de directorios.
2. Revisar si `premium.key` debe estar publicada.

#### Referencias

- https://cwe.mitre.org/data/definitions/200.html

#### Notas para el retest

Las rutas deben responder 401, 403 o 404 sin sesión de administrador.

## 5. Conclusiones, limitaciones y supuestos

### Conclusiones

La aplicación presenta fallos graves en las tres capas que protegen los datos de los clientes:

- **Entrada de datos:** inyección SQL en la búsqueda y en el inicio de sesión (F-001 y F-002) y XSS de DOM (F-009).
- **Identidad:** se aceptan tokens sin firma (F-006), los tokens no caducan ni se revocan (F-010) y cualquiera puede registrarse con el rol de administrador (F-004).
- **Autorización:** no se comprueba la propiedad de los objetos (F-003) ni la función o rol de quien pide (F-005).

Los hallazgos comparten causas raíz, así que corregirlas de forma centralizada resuelve varios a la vez:

- Las consultas SQL se concatenan (F-001 y F-002).
- El modelo de usuario se serializa completo en respuestas y tokens (F-005 y F-010).
- La autorización se delega en la interfaz y no en el servidor (F-003, F-004 y F-005).

**Fortalezas observadas.** El servidor sí verifica las firmas RS256 cuando el token las lleva (el control de F-006 rechazó un token alterado), invalida la contraseña antigua tras un cambio y responde 401 a las peticiones sin autenticar en los endpoints de cesta y usuarios.

### Limitaciones

- Prueba de un solo día, de caja negra, sobre un laboratorio local (contenedor Docker de OWASP Juice Shop), sin TLS ni componentes de red de producción. No aplican las conclusiones sobre cifrado del transporte.
- **No se probaron:** lógica de negocio (pagos, cupones, monedero), condiciones de carrera, subida de ficheros, SSRF, XXE, SSTI, deserialización, el chatbot (`/rest/chat`), las passkeys, el 2FA ni la fuerza bruta. Constan como «No» o «Parcial» en la matriz de cobertura.
- **Minimización de datos:** la explotación se limitó a demostrar el acceso con uno o dos registros y recuentos; no se volcaron tablas.

### Supuestos

- Las cuentas de prueba A, B, C y D se crearon durante la prueba y representan a clientes normales.
- Se asume que la configuración del contenedor es representativa de un despliegue real de la misma versión.

## 6. Priorización de la remediación

| Prioridad | ID | Título | Esfuerzo estimado |
|---|---|---|---|
| 1 — Inmediata | F-002 | Inyección SQL en el inicio de sesión permite entrar como cualquier usuario, incluido el administrador, sin contraseña | Bajo |
| 1 — Inmediata | F-006 | El servidor acepta JWT sin firma (alg:none): suplantación de cualquier usuario | Bajo |
| 2 — Corto plazo (≤ 30 días) | F-001 | Inyección SQL en la búsqueda de productos permite leer toda la base de datos sin autenticación | Bajo |
| 2 — Corto plazo (≤ 30 días) | F-005 | Falta de control por función: cualquier cliente obtiene los hashes de contraseña y secretos TOTP de todos los usuarios | Medio |
| 3 — Medio plazo (≤ 90 días) | F-009 | XSS basado en DOM en la búsqueda permite ejecutar JavaScript en el navegador de la víctima | Bajo |
| 3 — Medio plazo (≤ 90 días) | F-004 | Asignación masiva en el registro permite crear cuentas con rol de administrador | Bajo |
| 3 — Medio plazo (≤ 90 días) | F-007 | El directorio /ftp está listado y sirve documentos confidenciales sin autenticación | Bajo |
| 3 — Medio plazo (≤ 90 días) | F-008 | El filtro de extensiones de /ftp se salta con un byte nulo y expone copias de seguridad | Bajo |
| 3 — Medio plazo (≤ 90 días) | F-003 | IDOR en las cestas: un cliente puede leer la cesta de cualquier otro cliente | Bajo |
| 4 — Largo plazo | F-010 | El JWT no caduca e incluye el hash de la contraseña y el secreto TOTP | Bajo |
| 5 — Según criterio | F-011 | Endpoints de operación y directorios internos accesibles sin autenticación | Bajo |

## Anexo A — Cobertura de endpoints

| Endpoint | Clases probadas | IDs WSTG | Resultado | Fecha |
|---|---|---|---|---|
| GET /rest/products/search?q= | sqli | INPV-05 | F-001 | 2026-11-24 |
| POST /rest/user/login | sqli | INPV-05, ATHN-04 | F-002 | 2026-11-24 |
| GET /rest/basket/{id} | idor | ATHZ-04 | F-003 | 2026-11-24 |
| POST /api/Users | asignación masiva | INPV-20 | F-004 | 2026-11-24 |
| GET /api/Users, /rest/user/authentication-details | bfla | ATHZ-02/03 | F-005 | 2026-11-24 |
| GET /api/Quantitys, /api/Complaints, /api/Deliverys, /api/Cards, /api/Recycles | bfla | ATHZ-03 | sin diferencia cliente/admin (ver F-004/F-005) | 2026-11-24 |
| Todos los autenticados (JWT) | jwt | SESS-10 | F-006, F-010 | 2026-11-24 |
| /ftp, /encryptionkeys, /support/logs, /metrics, /rest/admin/* | config-exposure | CONF-04/05 | F-007 | 2026-11-24 |
| GET /ftp/{fichero} | path-traversal-lfi | ATHZ-01 | F-008 | 2026-11-24 |
| /#/search?q= | xss (DOM) | CLNT-01 | F-009 | 2026-11-24 |

## Anexo B — Aviso legal

Este informe refleja el estado de seguridad de los sistemas evaluados durante el periodo de pruebas indicado y dentro del alcance autorizado. Las pruebas de intrusión son una evaluación en un momento concreto: la ausencia de hallazgos en un área no garantiza la ausencia de vulnerabilidades. La información contenida es confidencial y no debe distribuirse sin el consentimiento del cliente.

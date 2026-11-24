# Fuentes y sumideros peligrosos por lenguaje y framework

> Guía para la búsqueda "hacia atrás" de la revisión de código: localizar sumideros con `rg` y subir por las llamadas hasta una fuente controlada por el atacante. Metodología completa en [metodologia.md](metodologia.md).
> **Fuente**: por donde entra el dato del atacante. **Sumidero (sink)**: función donde ese dato hace daño si llega sin tratar. **Alternativa segura**: la API que elimina la clase de fallo de raíz.
> Las regex son de **cribado**: dan falsos positivos a propósito. Cada coincidencia se triagea (¿fuente controlable?, ¿alcanzable?, ¿saneador válido?). Explotación en `../vulns/<nombre>.md`.

## Contenido

0. Uso rápido y convenciones
1. PHP (Laravel, Symfony, WordPress)
2. Java (Spring, Jakarta EE, Struts) y Kotlin
3. Python (Django, Flask, FastAPI)
4. Node.js / TypeScript (Express, NestJS, Next.js)
5. .NET (ASP.NET Core, MVC, Razor)
6. Go (net/http, Gin, Echo)
7. Ruby on Rails
8. Front-end (DOM, React, Angular, Vue)
9. Reglas Semgrep de ejemplo
10. Tabla de correspondencia categoría → fichero de vulnerabilidad → OWASP 2025

---

## 0. Uso rápido y convenciones

```bash
# Opciones comunes: número de línea, sin ficheros de dependencias ni compilados
rgs() { rg -n --hidden -g '!**/node_modules/**' -g '!**/vendor/**' -g '!**/dist/**' -g '!**/build/**' -g '!**/*.min.js' -g '!**/.git/**' "$@"; }
rgs -t php 'regex'                    # tipos rg: php java kotlin py js ts cs go ruby
rgs -g '*.{cshtml,razor}' 'regex'     # extensiones sin tipo propio: -g
# Solo líneas añadidas en un diff (modo revisión diferencial)
git diff "$BASE"..HEAD | rg '^\+' | rg -n 'regex'
```

Fuentes genéricas que hay que reconocer en cualquier lenguaje: parámetros de query/ruta/cuerpo, cabeceras (incluidas `Host`, `X-Forwarded-*`, `Referer`), cookies, nombres y contenido de ficheros subidos, mensajes de colas/WebSocket, respuestas de APIs de terceros, valores de BD escritos por otro usuario (segundo orden), variables de entorno en entornos multi-inquilino, salida de un LLM.

---

## 1. PHP (Laravel, Symfony, WordPress)

**Fuentes**: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER['HTTP_*']`, `php://input`, `$request->input()/query()/all()/get()`, `Request::input`, `$request->request->get()` (Symfony), `$_REQUEST` vía `get_query_var`, `$wp_query`, parámetros de `admin-ajax.php` y REST `register_rest_route`.

| Categoría | Sumideros | Alternativa segura |
|---|---|---|
| SQL | `mysqli_query`, `->query(` con concatenación, `PDO::query/exec`, Laravel `DB::raw`, `whereRaw`, `selectRaw`, `orderByRaw`, `havingRaw`, `DB::statement`, `DB::select("...$x")`; Doctrine `createQuery("...$x")`, `->where("u.name = '$x'")`; WP `$wpdb->query/get_results/get_var/get_row` sin `prepare` | consultas preparadas (`?`/`:name`), Query Builder con bindings, `$wpdb->prepare('%s/%d')`; lista blanca para nombres de columna en `orderBy` |
| Comandos | `exec`, `shell_exec`, `system`, `passthru`, `popen`, `proc_open`, backticks, `pcntl_exec`, `mail()` (5º parámetro) | `proc_open` con array de argumentos (PHP ≥ 7.4), `escapeshellarg` por argumento, evitar shell |
| Código / deserialización | `eval`, `assert` (string, PHP < 8), `create_function`, `preg_replace` con `/e` (antiguo), `call_user_func($x)`, `$x()`, `include/require` dinámicos, `unserialize`, `phar://` en funciones de fichero, `extract($_GET)` | `json_decode`, `unserialize($x, ['allowed_classes'=>false])`, lista blanca de callables |
| Plantillas | Twig `createTemplate($x)`, `{{ x\|raw }}`, Blade `{!! $x !!}`, Smarty `{php}` / `fetch('string:'.$x)` | plantillas fijas con variables; autoescape; nunca plantillas construidas con entrada |
| Ficheros / subidas | `include`, `file_get_contents`, `fopen`, `readfile`, `file_put_contents`, `unlink`, `copy`, `move_uploaded_file` con nombre del cliente, `ZipArchive::extractTo` (Zip Slip), `Storage::get($x)` | `basename()` + lista blanca, nombre aleatorio, `realpath` + prefijo, almacén fuera del webroot |
| SSRF | `file_get_contents($url)`, `curl_exec` con URL del usuario, `fopen('http..')`, Guzzle `->get($url)`, `Http::get($url)` (Laravel), `SoapClient($wsdl)` | lista blanca de host, resolución DNS + bloqueo de rangos internos, sin redirecciones |
| XML | `simplexml_load_string`, `DOMDocument::loadXML` con `LIBXML_NOENT`/`LIBXML_DTDLOAD`, `libxml_disable_entity_loader(false)`, `XMLReader` | sin flags `NOENT/DTDLOAD` (libxml ≥ 2.9 no expande por defecto) |
| Redirecciones | `header("Location: $x")`, `redirect($x)`, `redirect()->away($x)`, `wp_redirect($x)` | `wp_safe_redirect`, rutas relativas o lista blanca |
| Cripto / aleatorio | `md5`/`sha1` para contraseñas, `rand`, `mt_rand`, `uniqid`, `lcg_value` para tokens, `openssl_encrypt(..., 'aes-128-ecb')` | `password_hash` / `password_verify`, `random_bytes`, `random_int`, `hash_equals` |
| Comparaciones | `==` con hashes/tokens (`"0e1" == "0e2"`), `in_array` sin `true`, `strcmp` con arrays (`null == 0`) | `===`, `hash_equals`, `in_array($x,$a,true)` |
| Authz | rutas Laravel fuera de `Route::middleware('auth')`, controladores sin `$this->authorize()`/`Gate::`/policies; Symfony sin `#[IsGranted]`/`denyAccessUnlessGranted`; WP `add_action('wp_ajax_nopriv_*')`, `register_rest_route` con `permission_callback => '__return_true'`, sin `current_user_can` ni `check_ajax_referer`/`wp_verify_nonce` | middleware global, policies, `permission_callback` real, nonces |
| Mass assignment | `Model::create($request->all())`, `->fill($request->all())`, `$guarded = []`, `forceFill`; Symfony forms sin `allow_extra_fields: false` | `$request->validated()`, `$request->only([...])`, `$fillable` explícito |
| Logging | `Log::info($request->all())`, `error_log(print_r($_POST,true))` | redactar campos sensibles |

```bash
rgs -t php '\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\['
rgs -t php '(mysqli_query|->query\(|->exec\(|DB::(raw|statement|select|unprepared)|(where|select|orderBy|having|groupBy)Raw\()'
rgs -P -t php '\$wpdb->(query|get_results|get_var|get_row|get_col)\((?!.*prepare)'
rgs -t php '\b(exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(|`[^`]*\$'
rgs -t php '\b(eval|assert|create_function|unserialize|call_user_func(_array)?|extract)\s*\('
rgs -t php '\b(include|require)(_once)?\s*\(?\s*\$'
rgs -t php '(file_get_contents|fopen|readfile|file_put_contents|unlink|copy|move_uploaded_file|curl_setopt)\s*\('
rgs -t php 'LIBXML_(NOENT|DTDLOAD)|loadXML|simplexml_load_string'
rgs -t php "header\(\s*['\"]Location|->away\(|wp_redirect\("
rgs -g '*.blade.php' '\{!!'; rgs -g '*.twig' '\|\s*raw'
rgs -t php "wp_ajax_nopriv_|permission_callback'\s*=>\s*'__return_true'|\\\$guarded\s*=\s*\[\s*\]|->all\(\)\)"
rgs -t php '\b(md5|sha1|rand|mt_rand|uniqid)\s*\(|[^=!]==\s*\$.*(token|hash|sig)'
```

Referencias: [sqli](../vulns/sqli.md), [cmdi-rce](../vulns/cmdi-rce.md), [deserialization](../vulns/deserialization.md), [ssti](../vulns/ssti.md), [path-traversal-lfi](../vulns/path-traversal-lfi.md), [file-upload](../vulns/file-upload.md).

---

## 2. Java (Spring, Jakarta EE, Struts) y Kotlin

**Fuentes**: `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, `@ModelAttribute`, `HttpServletRequest.getParameter/getHeader/getInputStream/getQueryString/getRequestURI`, JAX-RS `@QueryParam/@PathParam/@FormParam/@HeaderParam`, `MultipartFile.getOriginalFilename()`, acciones de Struts (setters públicos = parámetros), `@KafkaListener`/`@RabbitListener` payloads.

| Categoría | Sumideros | Alternativa segura |
|---|---|---|
| SQL | `Statement.execute*`, `createStatement` + concatenación, `JdbcTemplate.query/queryForList/update(String)` concatenado, JPA `createQuery("..."+x)`, `createNativeQuery`, Hibernate `createSQLQuery`, `@Query(nativeQuery=true)` con SpEL `#{...}`, MyBatis `${x}` en XML/anotaciones, `Sort` construido con entrada | `PreparedStatement`, `?`/`:param`, MyBatis `#{x}`, Criteria API, lista blanca de columnas para `ORDER BY` |
| NoSQL | Mongo `new BasicQuery(json)`, `Document.parse(x)`, `$where` | Query/Criteria tipados |
| Comandos | `Runtime.getRuntime().exec(String)`, `ProcessBuilder("sh","-c",x)`, `ProcessBuilder(x.split(" "))` | `ProcessBuilder(List)` con binario fijo y argumentos validados |
| Expresiones / código | SpEL `ExpressionParser.parseExpression(x)` con `StandardEvaluationContext`, OGNL (Struts: `%{}`), MVEL, `ScriptEngine.eval`, `GroovyShell.evaluate`, EL `ELProcessor.eval`, `Class.forName(x).newInstance()` | `SimpleEvaluationContext`, sin evaluación dinámica |
| Deserialización | `ObjectInputStream.readObject`, `XMLDecoder`, XStream sin lista blanca, Jackson `enableDefaultTyping`/`activateDefaultTyping`/`@JsonTypeInfo(use=Id.CLASS)`, SnakeYAML `new Yaml().load` (< 2.0 sin `SafeConstructor`), Kryo sin registro, Hessian | JSON a DTO concretos, `ObjectInputFilter` (JEP 290), `SafeConstructor` |
| Plantillas | Thymeleaf `th:utext`, expresiones `__${x}__` (preprocesado) y nombres de vista devueltos desde entrada (`return "redirect:"+x` / `return x`), Freemarker `?interpret`/`new()`, Velocity `evaluate`, JSP `<%= %>`, `${param.x}` sin `<c:out>` | vista fija, `th:text`, `<c:out>`, `TemplateClassResolver.SAFER_RESOLVER` en Freemarker |
| Ficheros | `new File(base, x)`, `Paths.get(x)`, `FileInputStream`, `Files.read*/write/copy/delete`, `getOriginalFilename()`, `ZipEntry.getName()` (Zip Slip), `ResourceLoader.getResource(x)`, `ServletContext.getResourceAsStream(x)` | `normalize()` + `startsWith(base)` sobre ruta canónica, nombres aleatorios |
| SSRF | `new URL(x).openConnection/openStream`, `RestTemplate.getForObject(x)`, `WebClient.create(x)`, `HttpClient.send`, OkHttp, Apache HttpClient, Feign con URL dinámica, `ImageIO.read(URL)` | lista blanca, bloqueo de IP internas tras resolver, sin redirecciones |
| XML | `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, `SAXReader` (dom4j), `SAXBuilder` (JDOM), JAXB `Unmarshaller` sin configurar | `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`, `XMLConstants.FEATURE_SECURE_PROCESSING`, `ACCESS_EXTERNAL_DTD=""` |
| Redirecciones | `response.sendRedirect(x)`, `"redirect:" + x`, `RedirectView(x)` | rutas relativas fijas o lista blanca |
| Cripto / aleatorio | `new Random()`, `Math.random()`, `MessageDigest.getInstance("MD5"/"SHA-1")`, `Cipher.getInstance("AES")` (= ECB), `"DES"`, IV fijo, `TrustManager` que acepta todo, `HostnameVerifier` que devuelve `true` | `SecureRandom`, `AES/GCM/NoPadding` con IV aleatorio, `BCryptPasswordEncoder`/Argon2, `MessageDigest.isEqual` |
| Authz | métodos de `@RestController` sin `@PreAuthorize/@Secured/@RolesAllowed` cuando sus hermanos sí; `SecurityFilterChain` con `permitAll()` amplio, `requestMatchers("/api/**").permitAll()`, orden de reglas, `antMatchers` vs rutas con sufijo/`;`; `@EnableMethodSecurity` ausente (anotaciones ignoradas); `findById(id)` sin propietario | deny-by-default (`anyRequest().authenticated()`), comprobación de propietario en consulta |
| Mass assignment | `@ModelAttribute` o `@RequestBody` directamente a la entidad JPA, Struts setters de objetos anidados, `BeanUtils.copyProperties(req, entity)` | DTO con campos permitidos, `@InitBinder setAllowedFields` |
| Config / exposición | `management.endpoints.web.exposure.include=*`, `/actuator/env`, `/heapdump`, `/jolokia`, H2 console, `server.error.include-stacktrace=always` | exponer solo `health`, autenticación en actuator |
| Logging | `log.info("... {}", request)` con objetos que contienen contraseñas; Log4j 2 < 2.17.1 (Log4Shell) con entrada en logs | redacción, versión parcheada |

**Kotlin**: mismos sumideros JVM (Spring/Ktor). Específicos Ktor: `call.parameters["x"]`, `call.receive<Map<String,Any>>()`, `call.respondRedirect(x)`, Exposed `exec("...$x")`, plantillas de cadena `"SELECT ... $x"` (la interpolación `$x` / `${...}` es concatenación). Jetpack/Android queda fuera de este documento.

```bash
rgs -t java -t kotlin '(createStatement|executeQuery|executeUpdate|\.execute\(|createNativeQuery|createQuery|createSQLQuery|queryForList|queryForObject|jdbcTemplate\.(query|update))\s*\(.*(\+|\$\{?\w)'
rgs -g '*.xml' -g '*Mapper*.java' -g '*.kt' '\$\{[^}]+\}'                     # MyBatis ${} y SpEL/plantillas
rgs -t java -t kotlin 'Runtime\.getRuntime\(\)\.exec|new ProcessBuilder|ProcessBuilder\('
rgs -t java -t kotlin 'parseExpression\(|StandardEvaluationContext|ScriptEngine|GroovyShell|ELProcessor|Ognl|MVEL'
rgs -t java -t kotlin 'ObjectInputStream|readObject\(|XMLDecoder|XStream|enableDefaultTyping|activateDefaultTyping|JsonTypeInfo\(use\s*=\s*JsonTypeInfo\.Id\.CLASS|new Yaml\(|Kryo|HessianInput'
rgs -t java -t kotlin 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|SAXReader|SAXBuilder|Unmarshaller'
rgs -t java -t kotlin '(new URL\(|openConnection|RestTemplate|WebClient|HttpClient|OkHttpClient|HttpGet\(|ImageIO\.read)'
rgs -t java -t kotlin 'sendRedirect\(|"redirect:"\s*\+|RedirectView\(|respondRedirect\('
rgs -t java -t kotlin 'getOriginalFilename|new File\(|Paths\.get\(|Path\.of\(|ZipEntry|getResource(AsStream)?\('
rgs -t java -t kotlin 'new Random\(|Math\.random|getInstance\("(MD5|SHA-?1|DES|AES|RC4)"|TrustManager|HostnameVerifier|setHostnameVerifier'
rgs -g '*.html' 'th:utext|__\$\{'; rgs -g '*.jsp' '<%=|\$\{param\.'
rgs -t java -t kotlin 'permitAll\(\)|requestMatchers|antMatchers|@PreAuthorize|@Secured|@RolesAllowed|@EnableMethodSecurity'
rgs -g '*.properties' -g '*.yml' -g '*.yaml' 'exposure\.include|include-stacktrace|h2\.console\.enabled|spring\.profiles\.active'
```

---

## 3. Python (Django, Flask, FastAPI)

**Fuentes**: Django `request.GET/POST/FILES/COOKIES/META/body`, `request.headers`, kwargs de URL; Flask `request.args/form/values/json/get_json()/files/cookies/headers/data`, `view_args`; FastAPI parámetros de la función del endpoint (`Query`, `Path`, `Body`, `Form`, `Header`, `Cookie`, `UploadFile.filename`), modelos Pydantic; Celery: argumentos de tareas.

| Categoría | Sumideros | Alternativa segura |
|---|---|---|
| SQL | `cursor.execute(f"...")`, `% x`, `.format()`, `+`; Django `.raw()`, `.extra()`, `RawSQL`, `connection.cursor()`; SQLAlchemy `text(f"...")`, `engine.execute(str)`, `literal_column`, `order_by(x)` con string | `cursor.execute("... %s", (x,))`, ORM, `text(":p").bindparams`, lista blanca para orden |
| NoSQL | PyMongo `find({"$where": x})`, `find(json.loads(x))` (operadores `$ne`, `$gt` inyectados) | castear a `str`, rechazar claves que empiezan por `$` |
| Comandos | `os.system`, `os.popen`, `subprocess.*(..., shell=True)`, `commands.*`, `pty.spawn`, `asyncio.create_subprocess_shell` | `subprocess.run([bin, arg], shell=False)`, `shlex.quote` si no queda más remedio |
| Código / deserialización | `eval`, `exec`, `compile`, `__import__(x)`, `importlib.import_module(x)`, `getattr(obj, x)`, `pickle.loads`, `cPickle`, `dill`, `shelve`, `jsonpickle.decode`, `yaml.load` sin `SafeLoader` / `yaml.unsafe_load` / `yaml.full_load`, `marshal.loads`, `numpy.load(allow_pickle=True)`, `torch.load` (sin `weights_only=True`), `joblib.load` | `json.loads`, `yaml.safe_load`, `ast.literal_eval`, firmar los datos serializados |
| Plantillas | Flask `render_template_string(x)`, `jinja2.Template(x)`, `Environment(autoescape=False)`, `Markup(x)`, `\|safe`, Django `mark_safe(x)`, `{% autoescape off %}`, `format_html` mal usado, `Template(x).render` | `render_template('fichero.html', var=x)`, autoescape activo |
| Ficheros | `open(os.path.join(base, x))` (si `x` es absoluta, `join` descarta `base`), `send_file(x)`, `send_from_directory` con `..` en versiones antiguas, `FileResponse`, `shutil.*`, `zipfile.extractall`, `tarfile.extractall` (sin `filter='data'`), `UploadFile.filename` | `werkzeug.utils.secure_filename`, `Path.resolve().is_relative_to(base)`, nombres aleatorios |
| SSRF | `requests.get(x)`, `httpx`, `urllib.request.urlopen(x)` (acepta `file://`), `aiohttp`, `urllib3`, `pycurl`, `PIL.Image.open(urlopen(x))` | lista blanca, comprobar IP resuelta, `allow_redirects=False` |
| XML | `xml.etree`, `lxml.etree.fromstring/parse` con `resolve_entities=True` (por defecto en lxml < 5), `XMLParser(load_dtd=True, no_network=False)`, `xml.dom.minidom`, `xml.sax`, `xmltodict` (usa expat) | `defusedxml`, lxml con `resolve_entities=False` |
| Redirecciones | `redirect(request.args["next"])`, `HttpResponseRedirect(x)` | `url_has_allowed_host_and_scheme` (Django), lista blanca |
| Cripto / aleatorio | `random.*` para tokens, `hashlib.md5/sha1` de contraseñas, `verify=False`, `ssl._create_unverified_context`, `Crypto.Cipher.AES.new(k, AES.MODE_ECB)`, comparación `==` de HMAC | `secrets.token_urlsafe`, `hmac.compare_digest`, `argon2-cffi`/`bcrypt`/hashers de Django |
| Authz | Django vistas sin `@login_required`/`LoginRequiredMixin`/`@permission_required`; DRF `permission_classes = [AllowAny]`, `DEFAULT_PERMISSION_CLASSES` ausente, `get_queryset` sin filtrar por usuario, `get_object_or_404(Model, pk=pk)` sin propietario; Flask rutas sin `@login_required`; FastAPI endpoints sin `Depends(get_current_user)` o routers incluidos sin `dependencies=[...]` | filtrar por `request.user`, permisos por objeto (`has_object_permission`), dependencias globales del router |
| Mass assignment | `Model(**request.json)`, `obj.__dict__.update(data)`, `setattr` en bucle, `ModelForm` con `fields = '__all__'`, DRF `ModelSerializer` con `fields='__all__'` sin `read_only_fields`, Pydantic modelo de entrada = modelo de BD | formularios/serializadores con campos explícitos, modelos Pydantic separados de entrada y salida |
| Config | `DEBUG = True`, `ALLOWED_HOSTS = ['*']`, `SECRET_KEY` en el repo, Flask `app.run(debug=True)` (consola Werkzeug = RCE), `CORS(app, supports_credentials=True, origins="*")` | config por entorno, secretos fuera del repo |
| Logging | `logger.info(request.POST)`, `print(token)`, `logging.debug(f"pwd={pwd}")` | filtros de redacción |

```bash
rgs -t py '(execute|executemany|raw|extra|RawSQL|text)\s*\(\s*(f["\x27]|["\x27].*(%|\.format|\+))'
rgs -t py '\b(os\.system|os\.popen|subprocess\.\w+|create_subprocess_shell|pty\.spawn)\s*\(' ; rgs -t py 'shell\s*=\s*True'
rgs -t py '\b(eval|exec|compile|__import__)\s*\(|import_module\(|pickle\.loads?|jsonpickle|marshal\.loads|dill\.|shelve\.'
rgs -P -t py 'yaml\.(load|unsafe_load|full_load)\s*\((?!.*SafeLoader)|torch\.load\(|allow_pickle\s*=\s*True|joblib\.load'
rgs -t py 'render_template_string|jinja2\.Template\(|Template\(.*\)\.render|mark_safe|Markup\(|autoescape\s*=\s*False'
rgs -g '*.html' '\|\s*safe|autoescape off'
rgs -t py '\bopen\(|send_file\(|send_from_directory|FileResponse|extractall\(|os\.path\.join\(|\.filename\b'
rgs -t py 'requests\.(get|post|put|request|head)\(|httpx\.|urlopen\(|aiohttp\.|urllib3\.|pycurl'
rgs -t py 'lxml|etree\.(fromstring|parse|XMLParser)|minidom|xml\.sax|xmltodict|resolve_entities'
rgs -t py 'redirect\(.*request\.|HttpResponseRedirect\('
rgs -t py '\brandom\.(random|randint|choice|getrandbits)|hashlib\.(md5|sha1)|verify\s*=\s*False|_create_unverified_context|MODE_ECB'
rgs -t py 'AllowAny|permission_classes|login_required|LoginRequiredMixin|Depends\(|get_object_or_404\(|objects\.get\(pk'
rgs -t py "fields\s*=\s*['\"]__all__|\*\*request\.(json|data|POST|form)|__dict__\.update|DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*|debug\s*=\s*True"
```

---

## 4. Node.js / TypeScript (Express, NestJS, Next.js)

**Fuentes**: Express `req.query/params/body/cookies/headers/files`, `req.get()`, `req.hostname`/`req.ip` (dependen de `trust proxy`); NestJS `@Query()/@Param()/@Body()/@Headers()`; Next.js `searchParams`, `params`, `request.json()/formData()`, `cookies()`, `headers()`, argumentos de **server actions** (`'use server'`: son endpoints públicos POST aunque no lo parezcan), `getServerSideProps({query})`; WebSocket `socket.on('msg', data)`.

| Categoría | Sumideros | Alternativa segura |
|---|---|---|
| SQL | `db.query("..." + x)`, plantillas `` `...${x}` `` en `query/execute`, Sequelize `sequelize.query(str)` / `literal(x)` / `where: Sequelize.literal`, Knex `raw/whereRaw/orderByRaw`, TypeORM `query(str)`, `createQueryBuilder().where(\`...${x}\`)`, Prisma `$queryRawUnsafe/$executeRawUnsafe` (las variantes `$queryRaw` con *tagged template* sí parametrizan) | placeholders (`?`, `$1`), `$queryRaw\`...${x}\``, parámetros del query builder |
| NoSQL | `find(req.body)`, `findOne({user: req.body.user})` (llega `{"$ne":null}`), `$where`, `mapReduce`, `aggregate` con etapas del usuario | castear a string, `mongo-sanitize`, `sanitizeFilter` de Mongoose / `strictQuery` |
| Comandos | `child_process.exec/execSync`, `spawn(..., {shell:true})`, `execa` con `shell:true`, `shelljs.exec` | `execFile`/`spawn` con array y sin shell |
| Código / deserialización | `eval`, `new Function(x)`, `setTimeout/setInterval(string)`, `vm.runInContext/runInNewContext` (no es sandbox), `vm2` (abandonado), `require(x)`, `import(x)`, `node-serialize.unserialize`, `serialize-javascript` mal usado, `js-yaml.load` en v3 (en v4 `load` es seguro), `funcster` | `JSON.parse`, aislamiento real (proceso/contenedor), lista blanca de módulos |
| Prototype pollution | `merge/extend/defaultsDeep` recursivos propios, `lodash.merge/set/setWith/zipObjectDeep` en versiones antiguas, `obj[a][b] = c` con claves del usuario, `Object.assign` desde `JSON.parse` de entrada + `qs` anidado | `Object.create(null)`, `Map`, bloquear `__proto__`/`constructor`/`prototype`, `--disable-proto` |
| Plantillas | EJS `render(str)`/`ejs.render(req.body)`, `<%- x %>`, Pug `pug.render(x)`, `!{x}`, Handlebars `Handlebars.compile(x)` o `{{{x}}}`, Nunjucks `renderString(x)`, `res.render(view, req.query)` (opciones de motor desde la petición → RCE en EJS/hbs) | vista fija, pasar objetos construidos, no `req.query` entero |
| Ficheros | `fs.readFile/createReadStream/writeFile/unlink(path.join(base, x))`, `res.sendFile(x)` sin `root`, `res.download(x)`, `express.static` con rutas dinámicas, `multer` con `originalname` como destino, `adm-zip`/`unzipper` sin comprobar entradas | `path.resolve` + `startsWith(base + path.sep)`, `sendFile(name, {root})`, nombres aleatorios |
| SSRF | `axios(x)`, `fetch(x)`, `got`, `node-fetch`, `request`, `http.get(x)`, `needle`, `superagent`; Next.js `next/image` con `remotePatterns` amplios; renderizadores HTML→PDF (Puppeteer `page.goto(x)`) | lista blanca, comprobar IP tras resolver (`ssrf-req-filter` o agente propio), sin redirecciones |
| XML | `libxmljs.parseXml(x, {noent:true})`, `xml2js` (seguro por defecto), `xmldom` | sin `noent` |
| Redirecciones | `res.redirect(req.query.next)`, `redirect(x)` de Next, `NextResponse.redirect(new URL(x, req.url))` (si `x` es absoluta, ignora la base), `window.location` | lista blanca o rutas que empiecen por `/` y no por `//` ni `/\` |
| Cripto / aleatorio | `Math.random()` para tokens, `crypto.createHash('md5'/'sha1')` de contraseñas, `createCipher` (deprecado, sin IV), `aes-*-ecb`, `rejectUnauthorized:false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `jwt.verify` sin `algorithms`, `jwt.decode` usado como verificación, `===` sobre firmas | `crypto.randomBytes/randomUUID`, `timingSafeEqual`, `bcrypt`/`argon2`, `algorithms: ['RS256']` |
| Authz | Express: rutas registradas **antes** de `app.use(auth)` o en un router sin middleware; NestJS: métodos sin `@UseGuards` cuando no hay guard global, `@Public()` / `@SetMetadata('isPublic')`; Next.js: confiar solo en `middleware.ts` (matcher incompleto, y en versiones afectadas se podía saltar con la cabecera `x-middleware-subrequest`, CVE-2025-29927), server actions y route handlers sin comprobar sesión, comprobaciones solo en el componente cliente | guard global + excepciones explícitas, comprobar sesión y propiedad dentro de cada action/handler |
| Mass assignment | `Model.create(req.body)`, `findByIdAndUpdate(id, req.body)`, `Object.assign(user, req.body)`, `{...req.body}` en `update`, Prisma `data: req.body`, DTOs NestJS sin `ValidationPipe({whitelist:true, forbidNonWhitelisted:true})` | DTO con lista blanca, `pick` explícito |
| Config | `app.use(cors({origin:true, credentials:true}))`, `trust proxy` = `true`, `helmet` ausente, `express-session` con `secret:'keyboard cat'`, cookies sin `secure/httpOnly`, `NEXT_PUBLIC_*` con secretos (se publican en el bundle) | lista blanca de orígenes, número de saltos en `trust proxy` |
| ReDoS | `new RegExp(req.query.x)`, regex con cuantificadores anidados `(a+)+` sobre entrada | `re2`, límites de longitud |
| Logging | `console.log(req.body)`, `logger.info({headers: req.headers})` (Authorization, cookies) | redacción (`pino` `redact`) |

```bash
rgs -t js -t ts '(query|execute|raw|whereRaw|orderByRaw|literal|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*(`[^`]*\$\{|["\x27].*\+)'
rgs -t js -t ts '\.(find|findOne|findOneAndUpdate|updateOne|deleteMany|aggregate)\(\s*req\.(body|query)|\$where'
rgs -t js -t ts 'child_process|\b(exec|execSync|spawn|spawnSync|execa)\s*\(|shell\s*:\s*true'
rgs -t js -t ts '\beval\s*\(|new Function\(|vm\.(run|Script)|vm2|unserialize\(|setTimeout\(\s*["\x27`]|require\(\s*[^"\x27`]'
rgs -t js -t ts '(merge|extend|defaultsDeep|setWith|zipObjectDeep|set)\s*\(|__proto__|\[\w+\]\[\w+\]\s*='
rgs -t js -t ts '(ejs|pug|nunjucks|Handlebars|handlebars)\.(render|compile|renderString)\(|res\.render\([^,]+,\s*req\.'
rgs -g '*.ejs' '<%-'; rgs -g '*.hbs' -g '*.handlebars' '\{\{\{'; rgs -g '*.pug' '!\{'
rgs -t js -t ts 'fs\.\w+\(|sendFile\(|res\.download\(|createReadStream|originalname|path\.join\(.*req\.'
rgs -t js -t ts '\b(axios|fetch|got|needle|superagent|request)\s*(\.\w+)?\(|http\.get\(|page\.goto\('
rgs -t js -t ts 'res\.redirect\(|redirect\(|NextResponse\.redirect|location\.(href|assign|replace)'
rgs -t js -t ts 'Math\.random|createHash\(["\x27](md5|sha1)|createCipher\(|ecb|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|jwt\.decode\(|jwt\.verify\([^)]*\)\s*$'
rgs -t js -t ts "'use server'|\"use server\"|export (async )?function (GET|POST|PUT|PATCH|DELETE)|@Public\(|isPublic|@UseGuards|matcher"
rgs -t js -t ts '\.(create|update|findByIdAndUpdate|updateMany|upsert)\(\s*(req\.body|\{\s*\.\.\.req\.body)|data:\s*req\.body|Object\.assign\(\w+,\s*req\.body'
rgs -t js -t ts 'cors\(|origin\s*:\s*(true|["\x27]\*)|trust proxy|NEXT_PUBLIC_\w*(SECRET|KEY|TOKEN)|new RegExp\(\s*req\.'
```

---

## 5. .NET (ASP.NET Core, MVC, Razor)

**Fuentes**: `[FromQuery]`, `[FromRoute]`, `[FromBody]`, `[FromForm]`, `[FromHeader]`, parámetros enlazados implícitamente, `Request.Query/Form/Headers/Cookies/Body`, `IFormFile.FileName`, minimal APIs (parámetros de la lambda), SignalR hubs.

| Categoría | Sumideros | Alternativa segura |
|---|---|---|
| SQL | `SqlCommand(string)` concatenado, `CommandText = "..." + x`, EF Core `FromSqlRaw($"...{x}")`, `ExecuteSqlRaw`, `SqlQueryRaw`, Dapper `Query("..." + x)` | `SqlParameter`, `FromSqlInterpolated`/`FromSql` (parametrizan el `$""`), Dapper con objeto de parámetros |
| Comandos | `Process.Start(x)`, `ProcessStartInfo { FileName = "cmd.exe", Arguments = "/c " + x }`, PowerShell `AddScript(x)` | binario fijo, `ArgumentList.Add` |
| Código / deserialización | `BinaryFormatter` (prohibido; eliminado en .NET 9), `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`, `JavaScriptSerializer` con `SimpleTypeResolver`, Json.NET `TypeNameHandling` ≠ `None`, `XmlSerializer(Type.GetType(x))`, `DataContractSerializer` con tipos conocidos del usuario, ViewState sin MAC, `CSharpScript.EvaluateAsync`, `Activator.CreateInstance(Type.GetType(x))` | `System.Text.Json` a tipos concretos, `TypeNameHandling.None` |
| Plantillas / XSS | Razor `@Html.Raw(x)`, `new HtmlString(x)`, `MarkupString` (Blazor), RazorEngine `Compile(x)` | `@x` (codifica por defecto) |
| Ficheros | `Path.Combine(base, x)` (si `x` es absoluta, descarta `base`), `File.ReadAllText/Open/Delete`, `PhysicalFile(x)`, `IFormFile.FileName`, `ZipFile.ExtractToDirectory` en versiones antiguas, `ZipArchiveEntry.FullName` | `Path.GetFileName`, `Path.GetFullPath` + `StartsWith(base)`, nombres aleatorios |
| SSRF | `HttpClient.GetAsync(x)`, `WebClient.DownloadString(x)`, `WebRequest.Create(x)`, `RestClient(x)` | lista blanca, `SocketsHttpHandler.ConnectCallback` que bloquee IP internas |
| XML | `XmlDocument` con `XmlResolver` no nulo (.NET Framework < 4.5.2 por defecto), `XmlReaderSettings { DtdProcessing = DtdProcessing.Parse }`, `XmlTextReader` antiguo, `XPathNavigator` con `SelectNodes("..."+x)` (inyección XPath) | `DtdProcessing.Prohibit`, `XmlResolver = null` |
| Redirecciones | `Redirect(x)`, `Response.Redirect(x)`, `RedirectPermanent(x)` | `LocalRedirect(x)`, `Url.IsLocalUrl(x)` |
| Cripto / aleatorio | `new Random()`, `MD5.Create`, `SHA1`, `DESCryptoServiceProvider`, `CipherMode.ECB`, `RijndaelManaged` con IV fijo, `ServerCertificateCustomValidationCallback = (...) => true`, `ServicePointManager.ServerCertificateValidationCallback` | `RandomNumberGenerator`, `AesGcm`, `PasswordHasher<T>`/`Rfc2898DeriveBytes.Pbkdf2`, `CryptographicOperations.FixedTimeEquals` |
| Authz | controladores/acciones sin `[Authorize]` sin política de *fallback*; `[AllowAnonymous]` en acciones sensibles; `[Authorize]` en clase pero `[AllowAnonymous]` en método; minimal APIs sin `.RequireAuthorization()`; `ValidateIssuer/ValidateAudience/ValidateLifetime = false` en `TokenValidationParameters`; `RequireHttpsMetadata = false` | `FallbackPolicy` = usuario autenticado, autorización basada en recurso (`IAuthorizationService.AuthorizeAsync(user, resource, policy)`) |
| Mass assignment / overposting | `TryUpdateModelAsync(entity)` sin lista de propiedades, enlazar entidades EF directamente en acciones `[HttpPost]` | ViewModels/DTO, `[Bind("A,B")]` |
| CSRF | acciones POST MVC sin `[ValidateAntiForgeryToken]` y sin filtro global `AutoValidateAntiforgeryToken`; `[IgnoreAntiforgeryToken]` | filtro global |
| Config | `app.UseDeveloperExceptionPage()` fuera de `IsDevelopment()`, `customErrors mode="Off"`, `debug="true"` en `web.config`, `AllowAnyOrigin().AllowCredentials()` (bloqueado por el framework) o `SetIsOriginAllowed(_ => true).AllowCredentials()`, cadenas de conexión en `appsettings.json` | config por entorno, User Secrets / Key Vault |
| Logging | `_logger.LogInformation("{@Request}", request)` con objetos completos | destructurado selectivo |

```bash
rgs -t cs '(SqlCommand|CommandText|FromSqlRaw|ExecuteSqlRaw|SqlQueryRaw|\.Query(<\w+>)?|\.Execute)\s*\(?.*(\+\s*\w|\$")'
rgs -t cs 'Process\.Start|ProcessStartInfo|AddScript\(|CSharpScript|Activator\.CreateInstance|Type\.GetType\('
rgs -t cs 'BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter|SimpleTypeResolver|TypeNameHandling\.(All|Auto|Objects|Arrays)'
rgs -g '*.cshtml' -g '*.razor' -t cs 'Html\.Raw\(|new HtmlString\(|MarkupString'
rgs -t cs 'Path\.Combine\(|File\.(Read|Open|Write|Delete|Copy|Move)|PhysicalFile\(|\.FileName\b|ExtractToDirectory|\.FullName\b'
rgs -t cs 'HttpClient|GetAsync\(|WebClient|WebRequest\.Create|RestClient\('
rgs -t cs 'DtdProcessing\.Parse|XmlResolver|XmlTextReader|SelectNodes\(|SelectSingleNode\('
rgs -t cs '\bRedirect(Permanent)?\(|Response\.Redirect\('
rgs -t cs 'new Random\(|MD5|SHA1|DESCryptoServiceProvider|TripleDES|CipherMode\.ECB|ServerCertificate(Custom)?ValidationCallback'
rgs -t cs '\[AllowAnonymous\]|\[Authorize|RequireAuthorization|FallbackPolicy|Validate(Issuer|Audience|Lifetime|IssuerSigningKey)\s*=\s*false|RequireHttpsMetadata\s*=\s*false'
rgs -t cs 'TryUpdateModelAsync|IgnoreAntiforgeryToken|ValidateAntiForgeryToken|UseDeveloperExceptionPage|AllowCredentials|SetIsOriginAllowed'
rgs -g 'web.config' -g 'appsettings*.json' 'customErrors|debug="true"|ConnectionStrings|Password='
```

---

## 6. Go (net/http, Gin, Echo)

**Fuentes**: `r.URL.Query().Get`, `r.FormValue`, `r.PostFormValue`, `r.Header.Get`, `r.Cookie`, `r.Body`, `mux.Vars(r)`, `r.PathValue` (Go 1.22+); Gin `c.Query/Param/PostForm/GetHeader/Cookie/ShouldBind*/FormFile`; Echo `c.QueryParam/Param/FormValue/Bind/FormFile`; chi `chi.URLParam`.

| Categoría | Sumideros | Alternativa segura |
|---|---|---|
| SQL | `db.Query/Exec/QueryRow(fmt.Sprintf(...))`, concatenación `+`, GORM `db.Where(fmt.Sprintf(...))`, `Raw(str)`, `Exec(str)`, `Order(x)`, `Select(x)`, `Group(x)` con entrada (GORM pasa strings como SQL), sqlx `Select(&v, str)` concatenado | `db.Query("... $1", x)`, GORM `Where("name = ?", x)`, lista blanca de columnas |
| Comandos | `exec.Command("sh", "-c", x)`, `exec.Command(x)`, `syscall.Exec` | binario fijo + argumentos validados; ojo a argumentos que empiezan por `-` (inyección de opciones) |
| Código / deserialización | `encoding/gob` de datos no confiables, `yaml.Unmarshal` en `interface{}` (DoS en versiones antiguas), plugins (`plugin.Open`), `reflect` dirigido por entrada | tipos concretos, límites de tamaño |
| Plantillas | `text/template` para HTML (no escapa), `template.HTML(x)`, `template.JS(x)`, `template.URL(x)`, `template.New("").Parse(x)` con plantilla del usuario | `html/template`, nunca convertir entrada a `template.HTML` |
| Ficheros | `os.Open/ReadFile/Create/Remove(filepath.Join(base, x))`, `http.ServeFile(w, r, x)`, `c.File(x)`, `c.Attachment`, `FormFile` + `header.Filename`, `archive/zip` / `archive/tar` extracción con `f.Name` | `filepath.Clean` + `strings.HasPrefix` sobre ruta absoluta, `os.Root` / `OpenInRoot` (Go 1.24+), `filepath.Base` para nombres |
| SSRF | `http.Get(x)`, `http.NewRequest(..., x, ...)`, `client.Do(req)` con URL del usuario, `net.Dial(x)` | `net.Dialer.Control` que bloquee IP internas tras resolver, `CheckRedirect` |
| XML | `encoding/xml` no resuelve entidades externas (bajo riesgo de XXE); revisa bindings a libxml2 vía cgo | — |
| Redirecciones | `http.Redirect(w, r, x, ...)`, `c.Redirect(code, x)` | rutas relativas, lista blanca; ojo con `//host` y `/\host` |
| Cripto / aleatorio | `math/rand` para tokens/IDs, `crypto/md5`, `crypto/sha1`, `crypto/des`, `crypto/rc4`, `InsecureSkipVerify: true`, `MinVersion` < TLS 1.2, comparación `==` de MAC | `crypto/rand`, `hmac.Equal`, `subtle.ConstantTimeCompare`, `golang.org/x/crypto/bcrypt` o `argon2` |
| Authz | rutas registradas fuera del grupo con middleware (`r.Group("/api", auth)` vs `r.GET` directo), middleware que no hace `return` tras escribir el error (sigue ejecutando el handler: `c.AbortWithStatus` ausente en Gin, falta `return` en net/http) | `c.Abort()` + `return`, grupos con middleware, comprobación de propietario en la consulta |
| Mass assignment | `c.ShouldBindJSON(&user)` / `c.Bind(&user)` directo sobre el modelo de BD (campos `Role`, `IsAdmin`), GORM `Updates(map)` desde entrada | structs de entrada separados, `Select("campo")` en GORM |
| DoS / errores | `ioutil.ReadAll(r.Body)` sin `http.MaxBytesReader`, servidor sin `ReadHeaderTimeout`, errores ignorados `_ =` en comprobaciones de seguridad, `panic` sin `recover` en goroutines | límites y timeouts, gestionar todos los `err` |
| Logging | `log.Printf("%+v", req)` | redacción |

```bash
rgs -t go '\.(Query|QueryRow|QueryContext|Exec|ExecContext|Raw|Where|Order|Select|Group|Having)\(\s*(fmt\.Sprintf|"[^"]*"\s*\+|\w+\s*\+)'
rgs -t go 'exec\.Command(Context)?\(|syscall\.Exec'
rgs -t go '"text/template"|template\.(HTML|JS|URL|HTMLAttr|CSS)\(|template\.New\([^)]*\)\.Parse\('
rgs -t go 'os\.(Open|OpenFile|ReadFile|Create|Remove|RemoveAll|WriteFile)\(|filepath\.Join\(|http\.ServeFile|c\.(File|Attachment)\(|\.Filename\b|zip\.OpenReader|tar\.NewReader'
rgs -t go 'http\.(Get|Post|Head|NewRequest(WithContext)?)\(|client\.Do\(|net\.Dial'
rgs -t go 'http\.Redirect\(|c\.Redirect\('
rgs -t go '"math/rand"|"crypto/(md5|sha1|des|rc4)"|InsecureSkipVerify|MinVersion'
rgs -t go '\.(Group|Use)\(|AbortWithStatus|c\.Abort\(|ShouldBind(JSON)?\(|\.Bind\(|\.Updates\('
rgs -t go 'ioutil\.ReadAll\(r\.Body|io\.ReadAll\(r\.Body|MaxBytesReader|ReadHeaderTimeout|_\s*=\s*\w+\.(Verify|Validate|Check)'
```

---

## 7. Ruby on Rails

**Fuentes**: `params[...]`, `params.permit`, `request.headers/cookies/body/raw_post/env`, `cookies[...]`, ficheros subidos (`original_filename`), argumentos de jobs (Sidekiq/ActiveJob).

| Categoría | Sumideros | Alternativa segura |
|---|---|---|
| SQL | `where("name = '#{x}'")`, `find_by_sql`, `order(params[:sort])`, `pluck/select/group/having/joins/from/lock(x)` con string, `exists?(params[:x])` (acepta string SQL en versiones antiguas), `connection.execute`, `Arel.sql(x)` | `where(name: x)`, `where("name = ?", x)`, `sanitize_sql_*`, lista blanca para `order` |
| Comandos | `system("... #{x}")`, backticks, `%x()`, `exec`, `IO.popen(str)`, `Open3.*(str)`, `Kernel.open("\|cmd")` / `open(x)` (si empieza por `\|` ejecuta), `URI.open` | forma con array (`system("cmd", arg)`), `File.open` en vez de `open` |
| Código / deserialización | `eval`, `instance_eval`, `class_eval`, `send(params[:m])`, `public_send(x)`, `constantize`/`safe_constantize` con entrada, `Marshal.load`, `YAML.load` (Psych < 4 = `unsafe_load`), `YAML.unsafe_load`, `Oj.load` modo objeto, cookies con `cookies_serializer :marshal` + `secret_key_base` filtrada | `YAML.safe_load`, JSON, lista blanca de métodos/clases |
| Plantillas / XSS | `raw(x)`, `x.html_safe`, `<%== x %>`, `render inline: x`, `render params[:view]` / `render file:` / `render template:` con entrada, `content_tag` con atributos del usuario, `link_to x, params[:url]` (`javascript:`) | `<%= x %>` (escapa), `sanitize`, vistas fijas |
| Ficheros | `send_file(params[:f])`, `File.read/open(x)`, `Rails.root.join(x)`, `original_filename`, Zip extracción | `File.basename`, lista blanca, ActiveStorage |
| SSRF | `Net::HTTP.get(URI(x))`, `URI.open(x)`, `open-uri`, `HTTParty.get(x)`, `Faraday.get(x)`, `RestClient.get(x)` | lista blanca, gem `ssrf_filter` |
| XML | `Nokogiri::XML::ParseOptions::NOENT`, `REXML` con entidades (DoS en versiones antiguas), `ActiveSupport::XmlMini` / `Hash.from_xml` en Rails antiguos | opciones por defecto de Nokogiri (sin NOENT/DTDLOAD) |
| Redirecciones | `redirect_to params[:url]`, `redirect_to x, allow_other_host: true`, `redirect_back(fallback_location: params[...])` | Rails 7: `raise_on_open_redirects`; rutas internas |
| Cripto / aleatorio | `rand`, `Random.new`, `Digest::MD5/SHA1` de contraseñas, `OpenSSL::Cipher.new('aes-256-ecb')`, `verify_mode = OpenSSL::SSL::VERIFY_NONE`, `==` sobre tokens | `SecureRandom`, `has_secure_password` (bcrypt), `ActiveSupport::SecurityUtils.secure_compare` |
| Authz | `skip_before_action :authenticate_user!` / `:verify_authenticity_token`, controladores sin `before_action` de auth, `Model.find(params[:id])` en vez de `current_user.models.find`, Pundit sin `authorize`/`verify_authorized`, CanCanCan sin `load_and_authorize_resource`, `protect_from_forgery` ausente o `with: :null_session` en controladores con cookie | scope por usuario, `after_action :verify_authorized` |
| Mass assignment | `params.permit!`, `Model.new(params[:model])` sin strong params, `update(params.to_unsafe_h)`, permitir `:role`/`:admin` en `permit` | strong params explícitos |
| Config | `config.consider_all_requests_local = true` en producción, `config.hosts.clear`, `secret_key_base` en el repo, `config/master.key` comprometida, `force_ssl` desactivado, `web-console` en producción | credenciales cifradas fuera del repo |
| Logging | `config.filter_parameters` sin `:password, :token, :secret` | `filter_parameters` completo |

```bash
rgs -t ruby '\.(where|order|reorder|pluck|select|group|having|joins|from|find_by_sql|exists\?|lock|execute)\(\s*["\x27].*#\{|\.(order|reorder|pluck|group)\(\s*params|Arel\.sql\('
rgs -t ruby '\b(system|exec|spawn|IO\.popen|Open3\.\w+)\s*\(|`[^`]*#\{|%x[\(\{\[]|\bopen\(|URI\.open\('
rgs -t ruby '\b(eval|instance_eval|class_eval|module_eval)\b|\.(send|public_send|constantize|safe_constantize)\(\s*params|Marshal\.load|YAML\.(load|unsafe_load)\(|Oj\.load'
rgs -g '*.erb' -g '*.haml' -g '*.slim' -t ruby '\braw\(|\.html_safe|<%==|render\s+(inline|file|template):|render\s+params'
rgs -t ruby 'send_file\(|send_data\(|File\.(read|open|write)\(|Rails\.root\.join\(.*params|original_filename'
rgs -t ruby 'Net::HTTP|HTTParty|Faraday|RestClient|open-uri'
rgs -t ruby 'NOENT|DTDLOAD|Hash\.from_xml|REXML'
rgs -t ruby 'redirect_to\s+(params|request\.|@?\w+_url\b.*params)|allow_other_host:\s*true|redirect_back'
rgs -t ruby '\brand\(|Random\.new|Digest::(MD5|SHA1)|-ecb|VERIFY_NONE'
rgs -t ruby 'skip_before_action|protect_from_forgery|null_session|\.find\(params\[|verify_authorized|load_and_authorize_resource'
rgs -t ruby 'permit!|to_unsafe_h|permit\(.*:(role|admin|is_admin)|consider_all_requests_local\s*=\s*true|hosts\.clear|filter_parameters'
```

---

## 8. Front-end (DOM, React, Angular, Vue)

En el navegador las **fuentes** son: `location.*` (`hash`, `search`, `href`, `pathname`), `document.URL`, `document.referrer`, `window.name`, `postMessage` (`event.data`, ¿se comprueba `event.origin`?), `localStorage`/`sessionStorage`, cookies, respuestas de APIs (datos de otros usuarios), parámetros de router (`useParams`, `useSearchParams`, `$route.query`, `ActivatedRoute`).

| Categoría | Sumideros | Alternativa segura |
|---|---|---|
| DOM (XSS) | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write/writeln`, `Range.createContextualFragment`, `DOMParser` + inserción, `$(x)`, `.html()`, `.append(str)` (jQuery), `srcdoc` | `textContent`, `setAttribute` de atributos no peligrosos, DOMPurify, Trusted Types |
| Ejecución | `eval`, `new Function`, `setTimeout(string)`, `script.src = x`, `import(x)` | sin evaluación dinámica |
| URLs | `location = x`, `location.href/assign/replace(x)`, `window.open(x)`, `a.href = x`, `iframe.src = x`, `form.action = x` (`javascript:`) | validar esquema `http(s):` con `new URL()`; lista blanca |
| React | `dangerouslySetInnerHTML={{__html: x}}`, `href={x}` con `javascript:` (React solo avisa), `ref.current.innerHTML`, renderizar Markdown con `rehype-raw`/`allowDangerousHtml`, SSR con `JSON.stringify(state)` en `<script>` sin escapar `</script>` | DOMPurify, `serialize-javascript`, validar URLs |
| Angular | `bypassSecurityTrustHtml/Script/Style/Url/ResourceUrl`, `[innerHTML]` con valor ya "confiado", `ElementRef.nativeElement.innerHTML`, compilación dinámica de plantillas, AngularJS (1.x) `ng-bind-html` + `$sce.trustAsHtml` e interpolación `{{ }}` en HTML generado por servidor (CSTI) | dejar actuar al saneador de Angular, no usar `bypass*` con entrada |
| Vue | `v-html`, `domProps: { innerHTML }`, plantillas compiladas en tiempo de ejecución desde datos del usuario (`template: x`, `new Vue({template})`), `:href` con `javascript:` | interpolación `{{ }}`, DOMPurify |
| postMessage | `addEventListener('message', e => ...)` sin comprobar `e.origin` o con `indexOf`/`includes`; `postMessage(data, '*')` con datos sensibles | igualdad estricta de origen, origen destino explícito |
| Almacenamiento | tokens JWT en `localStorage`, PII en `sessionStorage` | cookies `HttpOnly; Secure; SameSite` |
| Secretos y fuentes | claves en el bundle (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `environment.ts`), source maps publicados (`//# sourceMappingURL=`) | ver [secretos-y-dependencias.md](secretos-y-dependencias.md) |
| Prototype pollution cliente | parseo de `location.search`/`hash` a objetos anidados (`deparam`, `qs` en cliente) + gadgets | ver [prototype-pollution](../vulns/prototype-pollution.md) |

```bash
rgs -t js -t ts -g '*.{vue,svelte,html}' '\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|createContextualFragment|srcdoc'
rgs -t js -t ts -g '*.{jsx,tsx}' 'dangerouslySetInnerHTML|rehype-raw|allowDangerousHtml|href=\{'
rgs -t ts -g '*.html' 'bypassSecurityTrust\w+|\[innerHTML\]|nativeElement\.innerHTML|ng-bind-html|trustAsHtml'
rgs -g '*.vue' -t js -t ts 'v-html|domProps|template\s*:\s*[^"\x27`]'
rgs -t js -t ts '\$\(\s*(location|document\.|window\.)|\.html\(|\.append\('
rgs -t js -t ts 'location\.(hash|search|href)|document\.(URL|referrer)|window\.name|addEventListener\(\s*["\x27]message|postMessage\('
rgs -t js -t ts '(window\.open|location\.(assign|replace)|location\.href\s*=|\.src\s*=)'
rgs -t js -t ts 'localStorage\.setItem\(.*(token|jwt|auth)|(NEXT_PUBLIC|VITE|REACT_APP)_\w*(SECRET|KEY|TOKEN|PASSWORD)'
rgs -g '*.js' -g '*.map' 'sourceMappingURL'
```

Referencias: [xss](../vulns/xss.md), [open-redirect](../vulns/open-redirect.md), [prototype-pollution](../vulns/prototype-pollution.md), [clickjacking](../vulns/clickjacking.md), [cors](../vulns/cors.md).

---

## 9. Reglas Semgrep de ejemplo

Guárdalas en `reglas/*.yml` y ejecuta `semgrep scan --config reglas/ --dataflow-traces .`. Prueba cada regla con `semgrep --test` (ficheros de test con anotaciones `# ruleid:` / `# ok:`) antes de confiar en ella. Empieza estricto para la variante encontrada y relaja después.

### 9.1 Express: entrada HTTP a SQL crudo (modo taint)

```yaml
rules:
  - id: corvus-express-sqli-taint
    mode: taint
    languages: [javascript, typescript]
    severity: ERROR
    message: Entrada de la petición llega a una consulta SQL construida como cadena (A05, CWE-89)
    metadata: { cwe: "CWE-89", owasp: "A05:2025 - Injection", references: ["../vulns/sqli.md"] }
    pattern-sources:
      - pattern-either:
          - pattern: $REQ.query
          - pattern: $REQ.body
          - pattern: $REQ.params
          - pattern: $REQ.headers
    pattern-sanitizers:
      - pattern: parseInt(...)
      - pattern: Number(...)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $DB.query($Q, ...)
              - pattern: $DB.execute($Q, ...)
              - pattern: $K.raw($Q, ...)
              - pattern: $P.$queryRawUnsafe($Q, ...)
          - focus-metavariable: $Q
```

### 9.2 Python: `subprocess` con `shell=True` y argumento no literal

```yaml
rules:
  - id: corvus-py-subprocess-shell
    languages: [python]
    severity: ERROR
    message: subprocess con shell=True y comando no constante (A05, CWE-78)
    patterns:
      - pattern-either:
          - pattern: subprocess.$F($CMD, ..., shell=True, ...)
      - pattern-not: subprocess.$F("...", ..., shell=True, ...)
    metadata: { cwe: "CWE-78", references: ["../vulns/cmdi-rce.md"] }
```

### 9.3 Spring: método de controlador sin anotación de autorización cuando la clase no la tiene

```yaml
rules:
  - id: corvus-spring-missing-preauthorize
    languages: [java]
    severity: WARNING
    message: Endpoint sin @PreAuthorize/@Secured/@RolesAllowed; verificar que la SecurityFilterChain lo cubre (A01, CWE-862)
    patterns:
      - pattern-inside: |
          @RestController
          class $C { ... }
      - pattern-not-inside: |
          @PreAuthorize(...)
          class $C { ... }
      - pattern: |
          @$MAPPING(...)
          $RET $METHOD(...) { ... }
      - metavariable-regex:
          metavariable: $MAPPING
          regex: ^(Get|Post|Put|Patch|Delete|Request)Mapping$
      - pattern-not: |
          @PreAuthorize(...)
          $RET $METHOD(...) { ... }
      - pattern-not: |
          @Secured(...)
          $RET $METHOD(...) { ... }
      - pattern-not: |
          @RolesAllowed(...)
          $RET $METHOD(...) { ... }
```

### 9.4 IDOR: carga por ID sin filtro de propietario (Django)

```yaml
rules:
  - id: corvus-django-get-without-owner
    languages: [python]
    severity: WARNING
    message: Objeto cargado por PK sin filtrar por request.user; posible IDOR (A01, CWE-639)
    patterns:
      - pattern-inside: |
          def $VIEW(request, ...):
              ...
      - pattern-either:
          - pattern: $M.objects.get(pk=$ID)
          - pattern: $M.objects.get(id=$ID)
          - pattern: get_object_or_404($M, pk=$ID)
          - pattern: get_object_or_404($M, id=$ID)
      - pattern-not: $M.objects.get(..., user=request.user, ...)
      - pattern-not: get_object_or_404($M, ..., owner=request.user, ...)
```

### 9.5 Fail-open: secreto con valor por defecto (cualquier lenguaje JS/TS)

```yaml
rules:
  - id: corvus-insecure-default-secret
    languages: [javascript, typescript]
    severity: ERROR
    message: Secreto con valor por defecto si falta la variable de entorno (A02/A04, CWE-1188)
    patterns:
      - pattern-either:
          - pattern: process.env.$V || "..."
          - pattern: process.env.$V ?? "..."
      - metavariable-regex:
          metavariable: $V
          regex: (?i).*(SECRET|KEY|TOKEN|PASSWORD|SALT).*
```

### 9.6 Go: middleware que escribe error pero no corta la ejecución (Gin)

```yaml
rules:
  - id: corvus-gin-auth-no-abort
    languages: [go]
    severity: ERROR
    message: El middleware responde 401/403 pero no llama a c.Abort*(); el handler sigue ejecutándose (A01)
    patterns:
      - pattern-inside: |
          func $MW(...) gin.HandlerFunc { ... }
      - pattern-either:
          - pattern: $C.JSON(401, ...)
          - pattern: $C.JSON(403, ...)
          - pattern: $C.JSON(http.StatusUnauthorized, ...)
          - pattern: $C.JSON(http.StatusForbidden, ...)
      - pattern-not-inside: |
          $C.JSON(...)
          ...
          $C.Abort()
      - pattern-not-inside: |
          $C.AbortWithStatusJSON(...)
```

Notas: la regla 9.3 y la 9.6 son de "sospecha" (pueden tener falsos positivos si la autorización es global); úsalas para generar la lista de rutas a comprobar en la matriz de autorización, no como hallazgos directos.

---

## 10. Correspondencia categoría → vulnerabilidad → OWASP Top 10:2025

| Categoría de sumidero | Fichero de detalle | OWASP 2025 | CWE típico |
|---|---|---|---|
| SQL | [sqli](../vulns/sqli.md) | A05 | 89 |
| NoSQL | [nosqli](../vulns/nosqli.md) | A05 | 943 |
| Comandos / eval | [cmdi-rce](../vulns/cmdi-rce.md) | A05 | 78, 94, 95 |
| Plantillas servidor | [ssti](../vulns/ssti.md) | A05 | 1336 |
| LDAP, XPath, cabeceras, logs, CSV, email | [otras-inyecciones](../vulns/otras-inyecciones.md) | A05 | 90, 643, 113, 117, 1236 |
| Deserialización | [deserialization](../vulns/deserialization.md) | A08 | 502 |
| XML | [xxe](../vulns/xxe.md) | A05 / A02 | 611 |
| Rutas de fichero | [path-traversal-lfi](../vulns/path-traversal-lfi.md) | A01 | 22, 98 |
| Subidas | [file-upload](../vulns/file-upload.md) | A01 / A05 | 434 |
| Clientes HTTP | [ssrf](../vulns/ssrf.md) | A01 | 918 |
| Redirecciones | [open-redirect](../vulns/open-redirect.md) | A01 | 601 |
| HTML / DOM | [xss](../vulns/xss.md) | A05 | 79 |
| Merge recursivo / claves dinámicas | [prototype-pollution](../vulns/prototype-pollution.md) | A05 / A08 | 1321 |
| Parámetros duplicados | [parameter-pollution](../vulns/parameter-pollution.md) | A05 | 235 |
| Authz ausente / IDOR | [access-control-idor](../vulns/access-control-idor.md) | A01 | 862, 863, 639 |
| Mass assignment | [access-control-idor](../vulns/access-control-idor.md), [api-rest-grpc-websocket](../vulns/api-rest-grpc-websocket.md) | A01 | 915 |
| CSRF | [csrf](../vulns/csrf.md) | A01 | 352 |
| Cripto / aleatorio / TLS | [jwt](../vulns/jwt.md), [session](../vulns/session.md) | A04 | 327, 328, 330, 295 |
| Autenticación | [authentication](../vulns/authentication.md), [oauth-oidc-saml](../vulns/oauth-oidc-saml.md) | A07 | 287, 307, 640 |
| Configuración / debug | [config-exposure](../vulns/config-exposure.md) | A02 | 489, 16 |
| Cabecera Host / proxy | [host-header](../vulns/host-header.md), [cache-poisoning-deception](../vulns/cache-poisoning-deception.md) | A02 / A05 | 644 |
| Errores / fail-open / ReDoS | — (ver metodologia §5.5) | A10 | 755, 636, 1333 |
| Logs con secretos / sin auditoría | — | A09 | 532, 778 |
| Concurrencia | [race-condition](../vulns/race-condition.md) | A06 / A10 | 362, 367 |
| LLM (salida a sumidero, herramientas) | [llm-ai](../vulns/llm-ai.md) | A05 / A06 | 1427 |

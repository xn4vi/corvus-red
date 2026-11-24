# Fase 3 — Caza: disciplina de pruebas

**Contenido:** 1. El ciclo de caza · 2. Registro de payloads · 3. Sondas seguras primero · 4. Detección diferencial · 5. OAST (fuera de banda) · 6. Iterar ante éxitos parciales · 7. Automatización: cuándo y cómo · 8. Encadenamiento · 9. Crear un hallazgo · 10. Cierre de la sesión de caza

Cada clase tiene su referencia en `vulns/<clase>.md`, con payloads, evasiones, falsos positivos y evidencia mínima. Este fichero fija **cómo** se caza, sea cual sea la clase.

## 1. El ciclo de caza

```
elegir endpoint × clase (según el plan)
  └─ scope-check del host
      └─ sonda segura ─ ¿señal? ─ no → registrar NO-EFFECT, siguiente variante o clase
                         └─ sí → confirmar con una prueba diferencial (verdadero/falso, retardo, OAST)
                                └─ demostrar impacto con lo MÍNIMO suficiente (⚠️ → pedir confirmación)
                                      └─ capturar petición y respuesta → tachar secretos → findings/F-xxx.md (SIN VALIDAR)
```

Personalidad en esta fase: atacante creativo y tenaz. La lista de payloads de la referencia es el punto de partida, no el límite. Adapta cada payload al contexto observado (dónde se refleja, qué filtra, qué tecnología hay detrás).

## 2. Registro de payloads (obligatorio)

Cada intento significativo se añade a `payload-log.md` **antes** de interpretar la respuesta. La forma recomendada es enviar las pruebas con `corvus.py http <engagement> <MÉTODO> <url> [--json …|--data …] [-H 'K: v'] --clase <clase> --nota "…" [--save F-xxx-nombre]`: comprueba el alcance, escribe la fila del registro con lo observado (código, tamaño y tiempo), respeta el ritmo de `scope.md` y, con `--save`, guarda la petición y la respuesta tachadas en `evidence/`. Si registras a mano, usa este formato:

```markdown
| Fecha-hora (UTC) | Endpoint | Clase | Payload (tachado) | Resultado | Notas |
|---|---|---|---|---|---|
| 2026-11-24T10:41:07Z | GET /search?q= | xss | `"><svg onload=alert(document.domain)>` | INTERESANTE | se refleja sin codificar dentro de un atributo |
```

Resultados posibles: `SIN EFECTO`, `INTERESANTE`, `POSIBLE HALLAZGO`, `BLOQUEADO` (WAF) y `ERROR`.

Para ráfagas automáticas (por ejemplo, 300 entradas de ffuf), registra **una** fila con la herramienta, la lista usada y la ruta del fichero de salida en `evidence/`, no una fila por petición.

## 3. Sondas seguras primero

| Clase | Sonda inicial de bajo riesgo |
|---|---|
| SQLi | `'`, `''`, `1 AND 1=1` frente a `1 AND 1=2`, `SLEEP(5)` (un solo intento, no en bucle) |
| XSS | Cadena canario única (`corvus7x9`) para ver dónde y cómo se refleja; después `<i>corvus</i>` |
| SSTI | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}` → buscar `49` |
| Inyección de órdenes | `;sleep 5`, `` `sleep 5` ``, `|nslookup <oast>` |
| SSRF | URL de OAST (interactsh) → ver si llega la consulta DNS o HTTP |
| Path traversal | `../../../../etc/passwd`, `..\..\..\windows\win.ini` |
| XXE | Entidad interna `<!ENTITY x "corvus">` antes de una externa; después, una externa hacia OAST |
| IDOR | Leer (GET) un objeto de la cuenta B con la cuenta A; nunca modificar a la primera |
| Deserialización | Gadget de solo DNS (`URLDNS` en Java) hacia OAST |
| LLM | Preguntas de reconocimiento («¿qué herramientas tienes?») antes de intentar acciones |

## 4. Detección diferencial

Una sola respuesta rara no prueba nada. Confirma con pares controlados:

- **Booleana**: la condición verdadera devuelve el contenido normal y la falsa lo cambia; repítelo 3 veces.
- **Temporal**: `SLEEP(0)` frente a `SLEEP(10)`, 3 repeticiones cada uno; anota los tiempos. Descarta la latencia de red comparando con la línea base.
- **De error**: el error aparece con `'` y desaparece con `''`.
- **Fuera de banda**: la interacción DNS o HTTP llega con un identificador único por prueba, de modo que sabes qué payload la provocó.
- **De autorización**: misma petición con el token A, con el token B y sin token; compara el código, la longitud y el contenido.

## 5. OAST (pruebas fuera de banda)

*Out-of-band Application Security Testing*: haces que el servidor objetivo contacte con un dominio que controlas. Sirve para detectar fallos «ciegos» (SSRF, XXE, inyecciones de órdenes y SQL ciegas, deserialización).

```bash
interactsh-client -v -o evidence/oast.log          # devuelve un dominio tipo abc123.oast.fun
# Usar un subdominio por prueba para correlacionar:  sqli-orders-id.abc123.oast.fun
```

Con Burp, usa Collaborator. Comprueba antes en `scope.md` que el cliente no prohíbe servicios OAST externos.

## 6. Iterar ante éxitos parciales

| Observación | Siguiente paso |
|---|---|
| 403/406 o página del WAF | `vulns/waf-bypass.md`: codificación, cambio de `Content-Type`, mayúsculas y minúsculas, comentarios, HPP, cuerpo grande |
| Reflejo con codificación parcial (`<` sí, `"` no) | Cambiar el contexto: atributo, manejador de eventos, `javascript:` |
| Error genérico 500 con `'` | Probar la sintaxis por motor de base de datos, comentarios (`-- -`, `#`) y cierre de paréntesis |
| Tiempo de respuesta ligeramente mayor | Subir el retardo (10–15 s) y repetir, comparando con la línea base |
| El parámetro se ignora | Probar otro `Content-Type` (JSON, XML, formulario), un array (`p[]=`), un objeto (`{"p":{"$ne":null}}`) |
| La interfaz bloquea la acción y la API no | Probar contra la API directamente: el control solo estaba en el cliente |

Tras un número razonable de variantes sin avance (unas 15–20 por endpoint y clase), registra el comportamiento en `notes.md` y pasa a lo siguiente. No te quedes atascado.

## 7. Automatización: cuándo y cómo

- Las herramientas automáticas **confirman y explotan** lo que ya detectaste a mano; no son el primer barrido.
- Ajusta siempre el ritmo al de `scope.md` (`--delay`, `-rate`, `--rate-limit`, `--threads 1`).
- Ejemplos dirigidos:

```bash
sqlmap -r evidence/req-orders.txt -p id --batch --level 2 --risk 1 --delay 0.3 --technique=BT   # --risk 3 ⚠️ (puede modificar datos)
commix -r evidence/req-ping.txt -p host --batch
nuclei -u https://app.cliente.com -t http/exposures/ -rl 5          # plantillas concretas, nunca todas
ffuf -u https://app.cliente.com/api/FUZZ -w lista-corta.txt -rate 5 -mc all -fc 404
jwt_tool <token> -M at -t https://app.cliente.com/api/me -rh "Authorization: Bearer"   # escaneo de ataques sobre JWT
```

- Los scripts propios (carreras, entropía de tokens, codificaciones) se guardan en `evidence/scripts/`. Explica en una frase qué hacen antes de ejecutarlos.

## 8. Encadenamiento

Antes de puntuar un hallazgo bajo, pregúntate si se combina con otro:

| Cadena | Resultado |
|---|---|
| Open redirect + OAuth `redirect_uri` laxo | Robo del código o del token de OAuth → toma de cuentas |
| Self-XSS + CSRF en el inicio de sesión | XSS explotable contra la víctima |
| XSS + ausencia de `HttpOnly` o token en `localStorage` | Robo de sesión |
| SSRF + metadatos de nube | Credenciales temporales del rol IAM |
| IDOR de lectura + filtración de tokens de recuperación | Toma de cuentas |
| Envenenamiento de caché + XSS reflejado no explotable | XSS almacenado en la caché |
| Subida de ficheros + LFI | Ejecución de código |
| Inyección indirecta en LLM + herramienta de envío de correo | Exfiltración de datos de otros usuarios |
| CORS con credenciales + endpoint con datos sensibles | Lectura de datos entre orígenes |

Documenta la cadena completa en el hallazgo principal y referencia los otros identificadores.

## 9. Crear un hallazgo

1. Copia `templates/hallazgo.md` a `findings/F-<nnn>.md` (numeración correlativa).
2. Rellena la cabecera: título, clase, endpoint, CWE, OWASP, WSTG y severidad provisional con su vector CVSS. Puedes calcular la puntuación 3.1 con `corvus.py cvss "<vector>"`.
3. Guarda la petición y la respuesta en `evidence/F-<nnn>-*.http` (automático con `corvus.py http … --save F-<nnn>-nombre`). Si la capturaste por otra vía, tacha los secretos con `corvus.py redact evidence/F-<nnn>-req.http --in-place`.
4. Pega en el hallazgo el extracto relevante, tachado, y señala la parte de la respuesta que demuestra el fallo.
   - **Captura también los controles** con `--save F-<nnn>-control`: la misma petición sin el payload, con la contraseña incorrecta sin inyección, con la firma original, sin token… Un control que solo consta en el registro no supera la puerta 2.
   - **Demuestra la identidad:** un token tachado no prueba quién hizo la petición. `corvus.py http --save` añade una línea «Identidad del token enviado» (alg, firma, id, email, rol, iat, exp) que lo resuelve sin revelar secretos. Si usas otra herramienta, añade esa línea a mano (`corvus.py jwt <token>`).
   - **Afirma solo lo comprobado:** «MD5 sin sal», «se recupera en segundos», «permite robar la sesión» o «acceso a tarjetas» necesitan su propia prueba (una comprobación local, un recuento, `document.cookie`…). Si no la tienes, no lo escribas.
   - **Para fallos del navegador**, reprodúcelos en dos navegadores (por ejemplo, el integrado y `chrome --headless=new --enable-logging=stderr --v=0 --virtual-time-budget=8000 --dump-dom <url>` con un perfil vacío) y localiza el sumidero en el JavaScript.
5. Estado `SIN VALIDAR`.
6. Si el hallazgo es crítico, avisa al auditor en el momento (ver SKILL.md §8).

## 10. Cierre de la sesión de caza

```markdown
## Caza — <clase> (<fecha>)
- Endpoints probados: <n> · Payloads: <n> (ver payload-log.md)
- Posibles hallazgos: <ids> (SIN VALIDAR)
- Bloqueados por WAF: <n> · Pendientes o ideas: <en notes.md>
- coverage.md actualizado: sí
Siguiente: /corvus validar  ·  o  /corvus caza <siguiente clase del plan>
```

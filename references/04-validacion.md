# Fase 4 — Validación: las 7 puertas

**Contenido:** 1. Actitud · 2. Las 7 puertas · 3. Patrones de falso positivo · 4. Procedimiento · 5. Validador independiente (subagente) · 6. Severidad: cómo justificarla · 7. Registro del veredicto

## 1. Actitud

En esta fase eres un **crítico escéptico**: cada hallazgo es un falso positivo hasta que la evidencia demuestre lo contrario. No eres hostil con quien lo encontró, sino exigente con la prueba. Un informe con un hallazgo falso pierde la confianza del cliente en todos los demás.

## 2. Las 7 puertas

Un hallazgo es `VALIDADO` solo si pasa **todas**. Evalúalas en orden y sin saltarte ninguna, aunque las primeras pasen.

| # | Puerta | PASA si… | FALLA si… |
|---|---|---|---|
| 1 | **PoC reproducible** | Hay una petición completa (método, URL, cabeceras y cuerpo) o un script que dispara el fallo, con el payload exacto | Se describe con palabras («el parámetro parece inyectable») sin petición concreta |
| 2 | **Evidencia HTTP** | Hay petición **y** respuesta capturadas, y se señala qué parte de la respuesta demuestra el fallo. La evidencia está tachada (tachar no es motivo de fallo; dejar credenciales vivas, sí). En los fallos de autorización consta la **identidad** de cada token usado, y los **controles** (petición sin payload, cuenta legítima, firma original…) también están capturados | Falta la respuesta o no demuestra nada; solo hay una captura de pantalla; el control o la identidad solo se afirman en el texto o en el registro; queda algún secreto sin tachar (`passwordRepeat`, `deluxeToken`…) |
| 3 | **Impacto demostrado** | El impacto es concreto y se ha comprobado: «lee el correo y el teléfono de cualquier usuario: verificado con los ID 1002 y 1003 (cuenta B)» | Es especulativo: «podría llevar a…», «un atacante podría potencialmente…», o una cadena que no se ha demostrado |
| 4 | **En alcance** | `scope-check` devuelve `DENTRO` para el host y la ruta afectados | El endpoint es de un tercero o está excluido. Se rechaza sin excepciones ni «pero está relacionado» |
| 5 | **Vulnerabilidad real** | Hay un escenario de ataque realista con un atacante plausible y una víctima o activo afectado | Es una observación informativa o de buenas prácticas sin explotación (ver §3) |
| 6 | **Reproducible por el cliente** | Un tercero puede reproducirlo siguiendo los pasos con herramientas estándar (navegador, curl, Burp, el script adjunto). La autenticación necesaria está explicada. Se reproduce de forma fiable, y en las carreras o en los LLM se indica la tasa de éxito | Depende de un estado no documentado, de una versión concreta del navegador, o funciona «a veces» sin cuantificar |
| 7 | **Severidad justificada** | El vector CVSS refleja el impacto **demostrado** (no el teórico), cada métrica tiene su motivo en una frase y la etiqueta (Crítica…Informativa) coincide con la puntuación o con un ajuste de negocio explicado | Se infla la severidad (por ejemplo, `C:H` sin haber leído datos sensibles) o el vector no cuadra con la puntuación |

## 3. Patrones de falso positivo

| Patrón | Por qué suele ser falso o informativo | Qué pedir para que pase |
|---|---|---|
| XSS que solo salta en el navegador del auditor | Extensiones, caché o una sesión del propio auditor | Reproducir en un navegador limpio y como otro usuario |
| Self-XSS | La víctima tendría que atacarse a sí misma | Encontrar un vector de entrega (CSRF, enlace, almacenado) |
| Reflejo codificado en HTML | La codificación funciona | Demostrar la ejecución en otro contexto |
| «Error SQL» en el flujo normal | Algunas aplicaciones muestran mensajes con aspecto de error | Prueba diferencial booleana o temporal estable |
| SQLi temporal con tiempos irregulares | La latencia de red imita el retardo | Retardos de 10 s o más, 3 repeticiones y línea base |
| SSRF que solo resuelve DNS | Puede ser una vista previa de enlaces sin acceso interno | Demostrar el acceso a un recurso interno o la lectura de la respuesta. Si no, como mucho Baja |
| IDOR sobre datos públicos | Perfiles públicos o contenido compartido a propósito | Acceder a datos que la cuenta B no ha hecho públicos |
| CSRF en formularios que piden reautenticación o con `SameSite=Lax/Strict` efectivo | La defensa existe | PoC funcional en un navegador actual con su configuración por defecto |
| CSRF del cierre de sesión | Impacto mínimo | — (informativa) |
| Open redirect sin más | Por sí solo, impacto bajo | Encadenarlo con OAuth, SSRF o `javascript:` |
| Cabeceras de seguridad ausentes | Son defensa en profundidad | Una explotación que esa cabecera habría impedido; si no, Informativa |
| Versión expuesta sin CVE explotable | La versión no es una vulnerabilidad | Un CVE aplicable **y** comprobado (o al menos el componente vulnerable alcanzable) |
| Clickjacking en páginas sin acciones sensibles | Sin impacto | Una acción sensible de un clic demostrada en la PoC |
| Introspección de GraphQL activada | Revela el esquema, no da acceso | Usarla para encontrar una operación sin autorización |
| «No hay límite de intentos» sin abuso demostrado | Puede haber controles en otra capa | Demostrar el abuso (OTP de 4–6 dígitos alcanzable, enumeración o envío masivo controlado) |
| LLM «dice cosas inapropiadas» | No es un fallo de la aplicación | Impacto de aplicación: fuga de datos de otros, ejecución de acciones o exfiltración |
| Prompt de sistema revelado sin secretos | Bajo impacto | Que contenga secretos o lógica de autorización explotable |
| Carrera con menos del 5 % de éxito sin documentar | No es reproducible | Script, número de intentos y tasa de éxito medida |
| Token JWT en `localStorage` | Riesgo solo si hay XSS | Encadenarlo con un XSS real o dejarlo como Informativa |
| «Hash débil (MD5 sin sal)» deducido por la longitud | 32 caracteres hexadecimales no prueban el algoritmo | Comprobación local con una contraseña conocida de una cuenta propia |
| JWT sin `exp` | Es endurecimiento si no hay más | Demostrar la falta de revocación: el token anterior a un cambio de contraseña sigue valiendo (con su `iat` en la evidencia) |
| Asignación masiva de `role` sin diferencia de permisos | El rol se guarda, pero el servidor no lo usa | Un endpoint donde el cliente reciba 403 y la cuenta elevada 200; si no lo hay, I:L y sin C |
| Varias exposiciones distintas en un solo hallazgo | Cada una tiene su gravedad | Dividirlas: lo explotable con su severidad y el resto como Informativa |

## 4. Procedimiento

Para cada hallazgo `SIN VALIDAR` o `REQUIERE TRABAJO`:

1. Lee `findings/F-xxx.md`, sus ficheros en `evidence/` y las filas relacionadas de `payload-log.md`.
2. Ejecuta `scope-check` sobre el endpoint (puerta 4).
3. **Repite la PoC** una vez si es seguro hacerlo (solo lectura, sin ⚠️): confirma que sigue reproduciéndose hoy. Si es una acción ⚠️, no la repitas sin permiso y valida con la evidencia existente.
4. Evalúa las 7 puertas y escribe un PASA o FALLA con una línea de razonamiento por puerta.
5. Decide el veredicto:
   - `VALIDADO`: pasan las 7.
   - `REQUIERE TRABAJO`: falla alguna, pero tiene arreglo con más evidencia. Da instrucciones concretas, por ejemplo «capturar la respuesta completa», «repetir con un retardo de 10 s» o «demostrar con datos de la cuenta B».
   - `RECHAZADO`: falsa alarma, fuera de alcance o informativa sin camino de mejora. Si es útil como observación, se puede reconvertir en Informativa y validarla como tal.
6. Actualiza el campo `estado` de la cabecera y añade la tabla de validación al final del hallazgo (§7).
7. Ejecuta `corvus.py status <engagement>` para regenerar `findings.md`.

## 5. Validador independiente (subagente)

Quien encuentra un fallo tiende a confirmarlo. Para romper ese sesgo, cuando haya 3 o más hallazgos o alguno sea Crítico o Alto, lanza un subagente (herramienta Agent, tipo `general-purpose`) por cada lote de hallazgos con este encargo. **No le des tu conclusión**: dale los ficheros.

```
Eres un validador escéptico de hallazgos de pentest web. Asume que cada hallazgo es un falso positivo
hasta que la evidencia demuestre lo contrario. NO envíes peticiones al objetivo: trabaja solo con la
evidencia escrita.

Lee:
- ~/.claude/skills/corvus/references/04-validacion.md (criterios: 7 puertas y patrones de falso positivo)
- <ruta>/engagements/<slug>/scope.md
- <ruta>/engagements/<slug>/findings/F-xxx.md (y los que siguen) y sus ficheros en evidence/

Para cada hallazgo devuelve: la tabla de las 7 puertas (PASA/FALLA + una línea de motivo), el veredicto
(VALIDADO / REQUIERE TRABAJO / RECHAZADO), una severidad recomendada con el vector CVSS 3.1 justificado
métrica a métrica y, si no lo validas, la evidencia exacta que faltaría. Responde en español.
No modifiques ficheros.
```

Haz **dos rondas** si hace falta: corrige lo que pida y devuélveselo al mismo subagente (SendMessage) para que confirme. En la prueba de referencia (Juice Shop, 2026-11-24), la primera ronda validó 1 de 10 hallazgos y obligó a capturar los controles, demostrar las identidades, retirar afirmaciones no comprobadas y dividir un hallazgo; la segunda validó 11 de 11.

Compara su veredicto con el tuyo. Si difieren, la evidencia manda: añade la que falte o rebaja la severidad. Anota el desacuerdo y cómo se resolvió en `notes.md`.

## 6. Severidad: cómo justificarla

- Puntúa con **CVSS 3.1** por defecto, y también con **CVSS 4.0** si el cliente lo pide (ver `05-informe.md` §4).
- Escribe una frase por cada métrica: `AV:N` porque está expuesto a Internet; `PR:L` porque basta una cuenta gratuita…
- El vector refleja lo **demostrado**. Si se ha leído un registro de prueba y el mismo fallo da acceso a toda la tabla, `C:H` está justificado *si* se ha comprobado con al menos dos objetos ajenos y el patrón es general. No hace falta volcar la tabla.
- CVSS no recoge el contexto de negocio. Si el riesgo real es mayor o menor (por ejemplo, un XSS en el panel interno de soporte que maneja datos personales), mantén el CVSS honesto y añade un párrafo de **ajuste por impacto de negocio** que justifique la severidad final.

| Etiqueta | CVSS 3.1 |
|---|---|
| Crítica | 9.0 – 10.0 |
| Alta | 7.0 – 8.9 |
| Media | 4.0 – 6.9 |
| Baja | 0.1 – 3.9 |
| Informativa | 0.0 o no aplica |

## 7. Registro del veredicto

Al final de `findings/F-xxx.md`:

```markdown
## Validación — <fecha> — <validador: CORVUS | subagente independiente>

| Puerta | Resultado | Motivo |
|---|---|---|
| 1. PoC reproducible | PASA | Petición completa en evidence/F-003-req.http |
| 2. Evidencia HTTP | PASA | La respuesta incluye el email de la cuenta B (líneas 12-14) |
| 3. Impacto demostrado | PASA | Lectura de pedidos ajenos verificada con los ID 1002 y 1003 |
| 4. En alcance | PASA | scope-check: DENTRO (api.cliente.com) |
| 5. Vulnerabilidad real | PASA | Exposición de datos personales de otros clientes |
| 6. Reproducible por el cliente | PASA | Pasos con curl y dos cuentas de prueba documentadas |
| 7. Severidad justificada | PASA | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5; ajuste de negocio a Alta por datos personales (RGPD) |

**Veredicto:** VALIDADO
**Justificación:** …
```

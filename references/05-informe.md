# Fase 5 — Informe

**Contenido:** 1. Flujo de generación · 2. Estructura del informe · 3. Reglas de redacción · 4. CVSS 3.1 y 4.0 · 5. Plantilla de hallazgo · 6. Informe en inglés · 7. Formato bug bounty · 8. Retest y cierre · 9. Errores típicos

## 1. Flujo de generación

1. Comprueba que todo lo que va al informe está `VALIDADO` (`corvus.py status <engagement>`).
2. Redacta, en `engagements/<slug>/report/`:
   - `resumen-ejecutivo.<lang>.md`: una página como máximo (§2.2).
   - `conclusiones.<lang>.md`: recomendaciones estratégicas, limitaciones y supuestos (§2.6).
3. Si el informe va en inglés, traduce cada hallazgo validado a `findings/en/F-xxx.md`, con la misma cabecera y el cuerpo en inglés (§6).
4. Genera los entregables:

```bash
corvus.py report engagements/<slug> --lang es          # informe completo
corvus.py report engagements/<slug> --lang en
corvus.py report engagements/<slug> --lang es --finding F-003   # un solo hallazgo
```

El script produce `report/<slug>-informe-<lang>.md`, el `.html` con la marca (`brand.json` + `assets/`) y el `.pdf` si encuentra Edge o Chrome. También revisa la coherencia: avisa si un vector CVSS no cuadra con la puntuación o la severidad, si un hallazgo carece de secciones obligatorias o si quedan patrones de secretos sin tachar.
5. Revisa el HTML (ábrelo en el navegador) y comunica al auditor las rutas de los ficheros.

## 2. Estructura del informe

El script monta este orden. Tú escribes el contenido de las piezas marcadas con ✍️.

1. **Portada**: marca, lema, título, cliente, fechas, versión, clasificación y auditor (salen de `brand.json` y `scope.md`).
2. **Resumen ejecutivo** ✍️: la lectura de 90 segundos para dirección.
3. **Alcance y metodología**: sale de `scope.md` y `coverage.md` (WSTG por categoría: Sí / Parcial / No / N/A).
4. **Resumen de hallazgos**: tabla y recuento por severidad (automático).
5. **Hallazgos detallados**: uno por fichero validado, ordenados de Crítica a Informativa.
6. **Conclusiones, limitaciones y supuestos** ✍️.
7. **Matriz de priorización de la remediación** (automática a partir de la severidad, con el esfuerzo que indiques en la cabecera `esfuerzo` de cada hallazgo).
8. **Anexos**: cobertura de endpoints y aviso legal.

### 2.2 Resumen ejecutivo: cómo escribirlo

Se escribe para el director de seguridad (CISO), el de cumplimiento normativo y el comité de dirección, que leerán esto y nada más.

1. **Contexto**, una frase: qué se probó, cuándo y con qué enfoque.
2. **El hallazgo principal en términos de negocio**, 2–3 frases: «Cualquier cliente registrado podía consultar los pedidos, direcciones y teléfonos del resto de clientes».
3. **Veredicto de riesgo**, un párrafo: postura general (sólida, mejorable, deficiente) y por qué.
4. **Recuento por severidad**: el script inserta la tabla, así que no la repitas.
5. **Tres recomendaciones estratégicas**, que sean programas y no parches: «centralizar la autorización por objeto en un middleware común», no «arreglar `/api/orders`».

Palabras que hay que traducir a negocio en el resumen ejecutivo: *payload, RCE, XSS, SQLi, IDOR, SSRF, deserialización, inyección*. «Un atacante podía ejecutar órdenes en el servidor», no «RCE por cadena de gadgets».
Palabras que conviene incluir: datos de clientes, exposición regulatoria (RGPD, PCI DSS, ENS, NIS2, DORA), interrupción del servicio, fraude y pérdida económica.

### 2.6 Conclusiones, limitaciones y supuestos

- **Limitaciones**: «las pruebas se hicieron desde Internet, sin acceso a la red interna», «no se probó la pasarela de pago real por exclusión del alcance», «categorías WSTG no cubiertas: … (motivo)».
- **Supuestos**: «se asumió que preproducción replica la configuración de producción».
- **Fortalezas observadas**: los controles que funcionaron bien. El cliente lo agradece y da credibilidad al resto del informe.

## 3. Reglas de redacción

- **Lenguaje firme** en lo validado: «es vulnerable», no «podría ser vulnerable».
- **Impacto concreto y cuantificado**: «acceso de lectura a los ~48 000 pedidos (comprobado con los ID 1002, 1003 y 51877)».
- **Pasos reproducibles en menos de 15 minutos** por alguien sin contexto del encargo.
- **Remediación accionable y ordenada**: (1) corregir la causa raíz con un ejemplo de código o configuración; (2) defensa en profundidad; (3) detección (qué registro o regla de monitorización lo habría detectado).
- **Referencias**: CWE, OWASP (Top 10:2025, API Top 10:2023, LLM Top 10:2025, ASVS 5.0), CAPEC y aviso del fabricante si hay CVE.
- **Evidencia tachada**: credenciales, tokens y cookies como `[REDACTED…]`, y datos personales minimizados o pseudonimizados («j***@cliente.com»).
- **Capturas**: recortadas al área relevante, sin otras pestañas y sin tokens en la barra de direcciones. Quita los metadatos con `exiftool -all= *.png`.
- **Nada inventado**: si un dato no se comprobó, no aparece como hecho.

## 4. CVSS 3.1 y 4.0

### 4.1 CVSS 3.1 (por defecto)

Calcula y comprueba con `corvus.py cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`.

| Métrica | Valores | Pregunta que responde |
|---|---|---|
| AV (vector de ataque) | N / A / L / P | ¿Desde dónde se ataca? Internet, red adyacente, local o físico |
| AC (complejidad) | L / H | ¿Hacen falta condiciones fuera del control del atacante (ganar una carrera, conocer un secreto)? |
| PR (privilegios) | N / L / H | ¿Qué cuenta necesita el atacante? |
| UI (interacción del usuario) | N / R | ¿La víctima tiene que hacer algo (pulsar un enlace)? |
| S (alcance) | U / C | ¿El impacto sale del componente vulnerable? (XSS: del servidor al navegador; SSRF: a otros sistemas) |
| C / I / A | H / L / N | Confidencialidad, integridad y disponibilidad de lo **demostrado** |

Vectores orientativos (ajústalos siempre a lo demostrado):

| Caso | Vector | Puntuación |
|---|---|---|
| RCE sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 |
| RCE con cuenta de usuario | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 |
| SQLi sin autenticación, lectura y escritura | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 |
| SQLi sin autenticación, solo lectura | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 |
| Toma de cuentas sin interacción | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 |
| SSRF hasta credenciales de nube | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` | 8.6 |
| IDOR de lectura y escritura | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | 8.1 |
| IDOR de lectura (datos sensibles) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 |
| XSS reflejado | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 |
| XSS almacenado (requiere cuenta) | `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | 5.4 |
| CSRF con cambio de estado relevante | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | 6.5 |
| Exposición de información de bajo impacto | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 |
| Open redirect | `AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N` | 4.7 |

### 4.2 CVSS 4.0 (si el cliente lo pide)

CVSS 4.0 cambia varias cosas:

- Separa la **complejidad del ataque** (AC) de los **requisitos de ataque** (AT: condiciones del entorno, como ganar una carrera o estar en una posición de red concreta).
- Divide la interacción del usuario en `UI:N/P/A` (ninguna, pasiva o activa).
- Elimina el «alcance» y lo sustituye por el impacto sobre el **sistema vulnerable** (`VC/VI/VA`) y sobre los **sistemas subsiguientes** (`SC/SI/SA`).
- Añade los grupos de amenaza, entorno y suplementario.

Ejemplos de vector (calcula la puntuación con la calculadora oficial de FIRST, <https://www.first.org/cvss/calculator/4.0>, y anótala en `cvss4_score`):

```
RCE sin autenticación:   CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
XSS reflejado:           CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N
IDOR de lectura:         CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
SSRF a metadatos nube:   CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:H/SI:L/SA:N
```

Nomenclatura recomendada por FIRST: «CVSS-B» si solo hay métricas base, y «CVSS-BT» o «CVSS-BTE» si se añaden las de amenaza o entorno.

## 5. Plantilla de hallazgo

La fuente es `templates/hallazgo.md`. Secciones obligatorias del cuerpo (en el inglés, sus equivalentes):

| Español | English |
|---|---|
| `## Descripción` | `## Description` |
| `## Prueba de concepto` | `## Proof of Concept` |
| `## Pasos para reproducir` | `## Steps to Reproduce` |
| `## Impacto` | `## Impact` |
| `## Remediación` | `## Remediation` |
| `## Referencias` | `## References` |
| `## Notas para el retest` | `## Retest Notes` |

La sección `## Validación` se queda en el fichero, pero el script **no** la incluye en el informe.

## 6. Informe en inglés

- Traduce cada hallazgo validado a `findings/en/F-xxx.md`. Copia la cabecera, cambia `titulo` por el título en inglés (o rellena `title_en`) y traduce el cuerpo con las secciones en inglés de la tabla anterior. Las severidades se pueden dejar en español: el script las traduce (Critical, High, Medium, Low, Informational).
- Escribe `report/resumen-ejecutivo.en.md` y `report/conclusiones.en.md`.
- Usa inglés profesional y neutro: «The application is vulnerable to…», «An authenticated attacker can…». Las peticiones y respuestas HTTP no se traducen.

## 7. Formato bug bounty

Si el encargo es un programa de bug bounty, el destinatario es un equipo de triaje, no un comité de dirección:

- Título: `<Clase> en <endpoint> permite <impacto>`.
- Cuerpo: resumen (2 líneas) → pasos numerados con peticiones → PoC (vídeo o script si ayuda) → impacto concreto → sugerencia de corrección.
- Sin resumen ejecutivo ni portada. Respeta la severidad del programa (su tabla o VRT de Bugcrowd) y su cabecera identificativa.
- Genera un único hallazgo con `report --finding F-xxx` y copia el Markdown a la plataforma.

## 8. Retest y cierre

- En el retest, repite exactamente las «Notas para el retest» de cada hallazgo.
- Estados tras el retest: `CORREGIDO` (no se reproduce: adjunta la petición y la respuesta nuevas), `PARCIAL` (anótalo en el cuerpo y deja el estado en `VALIDADO`) o `SIGUE ABIERTO`.
- El informe de retest es el mismo comando con `--retest`: incluye todos los hallazgos con su estado actual.
- Al cerrar el encargo, recuerda al auditor la política de conservación de evidencia (`scope.md`) y propón borrar `evidence/` una vez entregado y aceptado el informe.

## 9. Errores típicos que hay que evitar

- Severidad inflada sin demostración: la puerta 7 lo impide.
- Resumen ejecutivo lleno de jerga técnica.
- Remediación genérica («validar la entrada») sin decir dónde ni cómo.
- Evidencia con tokens vivos o datos personales completos.
- Hallazgos duplicados: el mismo fallo de raíz en 15 endpoints es **un** hallazgo con la lista de endpoints afectados.
- Mezclar hallazgos sin validar en el informe formal.
- Omitir las limitaciones: si algo no se probó, el informe debe decirlo.

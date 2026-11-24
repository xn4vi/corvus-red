---
id: F-000
titulo: <Clase> en <endpoint> permite <impacto>
title_en:
clase: <sqli|xss|…>
severidad: Media
cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
cvss_score: 0.0
cvss4_vector:
cvss4_score:
cwe: CWE-000 — <nombre>
owasp: A00:2025 — <categoría>
wstg: WSTG-XXXX-00
endpoint: GET https://app.cliente.com/ruta
afectados:
estado: SIN VALIDAR
esfuerzo: Medio
fecha: AAAA-MM-DD
---

## Descripción

<Qué es, dónde está y cuál es la causa raíz, en 2-4 frases comprensibles para un desarrollador y para un responsable.>

## Prueba de concepto

**Petición:**

```http
GET /ruta?param=PAYLOAD HTTP/1.1
Host: app.cliente.com
Cookie: session=[REDACTED len=32]
```

**Respuesta (extracto relevante):**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{ "...": "parte que demuestra el fallo" }
```

<Qué parte de la respuesta prueba la vulnerabilidad.>

## Pasos para reproducir

1. Iniciar sesión como <rol> (cuenta de prueba A).
2. …
3. Observar que …

## Impacto

<Concreto y demostrado: qué datos o acciones, de quién y cuántos. Ajuste por impacto de negocio si procede.>

## Remediación

1. **Corregir la causa raíz:** <cambio de código o configuración, con ejemplo>.
2. **Defensa en profundidad:** <control secundario>.
3. **Detección:** <registro o regla que lo habría detectado>.

## Referencias

- <CWE>
- <OWASP>
- <PortSwigger / aviso del fabricante>

## Notas para el retest

<Petición exacta que hay que repetir y respuesta esperada tras la corrección.>

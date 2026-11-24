# Fallos de lógica de negocio (Business Logic Vulnerabilities)

| Clasificación | |
|---|---|
| CWE | CWE-840 — Business Logic Errors (categoría); CWE-841 — Improper Enforcement of Behavioral Workflow; CWE-1284 — Improper Validation of Specified Quantity in Input; CWE-602 — Client-Side Enforcement of Server-Side Security; CWE-472 — External Control of Assumed-Immutable Web Parameter; CWE-837 — Improper Enforcement of a Single, Unique Action |
| OWASP Top 10:2025 | A06 — Insecure Design (y A01 — Broken Access Control cuando se cruza un límite de rol o de inquilino) |
| OWASP API Top 10:2023 | API6 — Unrestricted Access to Sensitive Business Flows; API3 — Broken Object Property Level Authorization (asignación masiva de campos de negocio) |
| WSTG | WSTG-BUSL-01 a WSTG-BUSL-09 (validación de datos de negocio, falsificación de peticiones, controles de integridad, temporización del proceso, límites de uso de una función, elusión del flujo de trabajo, defensas contra el mal uso, subidas inesperadas); WSTG-BUSL-10 (pruebas de funcionalidad de pago, en la versión *latest*) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación por contexto (flujos, precios, cupones, reembolsos, inquilinos, banderas de funcionalidad, límites, suscripciones, tiempo) · 5. Evasión · 6. Escalada y encadenamiento · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia mínima · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

Un fallo de lógica de negocio aparece cuando la aplicación hace exactamente lo que el código dice, pero el código no impone las reglas que el negocio da por supuestas: que el precio lo fija el servidor, que un cupón se usa una vez, que no se puede confirmar un pedido sin pagarlo, que un reembolso nunca supera lo cobrado o que un usuario de la empresa A nunca toca datos de la empresa B. No hay una carga útil (*payload*, el texto malicioso que se envía) universal: cada fallo depende del propósito de la aplicación.

Causas típicas:

- **Confianza en el cliente.** El navegador o la app móvil calcula el total, decide qué paso toca o esconde botones; el servidor acepta lo que llega sin recalcular ni revalidar.
- **Flujos de varios pasos sin máquina de estados en el servidor.** Una *máquina de estados* es el modelo que define en qué estados puede estar un objeto (carrito, pendiente de pago, pagado, enviado, reembolsado) y qué transiciones están permitidas. Si el servidor no la comprueba, se pueden saltar o repetir pasos.
- **Validación de tipo pero no de semántica.** Se comprueba que `qty` es un número, pero no que sea entero, positivo y razonable.
- **Supuestos de unicidad no atómicos.** «Este cupón no se ha usado» se comprueba y después se marca, con una ventana intermedia explotable (ver `vulns/race-condition.md`).
- **Funcionalidades legítimas sin límites.** Invitaciones, exportaciones, referidos o pruebas gratuitas que se pueden repetir o multiplicar.
- **Diseño incoherente entre servicios.** El microservicio de precios y el de pedidos no comparten la misma regla de redondeo, divisa o estado.

Los escáneres casi nunca los detectan: cada petición individual es válida. El impacto suele ser económico directo o de cruce de límites de autorización.

## 2. Dónde buscar (señales del reconocimiento)

- Aplicaciones transaccionales: comercio electrónico, *marketplaces*, banca y *fintech*, reservas, SaaS con planes y cuotas, programas de puntos, apuestas o sorteos (sin ejecutar operaciones reales con dinero).
- Parámetros de negocio en las peticiones: `price`, `amount`, `total`, `subtotal`, `discount`, `tax`, `shipping`, `currency`, `qty`, `status`, `step`, `plan`, `tier`, `role`, `tenantId`, `orgId`, `credits`, `isPremium`, `trialEndsAt`, `couponId`, `paymentRef`.
- Flujos de varios pasos: registro → verificación → contraseña → 2FA; carrito → dirección → envío → pago → confirmación; solicitud → aprobación → ejecución.
- Respuestas que devuelven el estado completo del objeto (incluidos campos que la interfaz no muestra) y que se reenvían tal cual en la siguiente petición.
- Especificaciones OpenAPI, colecciones Postman o el *bundle* JavaScript con rutas que la interfaz nunca llama (`/api/orders/{id}/force-complete`, `/internal/refund`).
- Banderas de funcionalidad (*feature flags*: interruptores que activan o desactivan funciones por usuario o plan) visibles en JS o en respuestas: `features: {"bulkExport": false}`.
- Webhooks de pasarelas de pago (`/webhooks/stripe`, `/payment/callback`, `/ipn`) que el servidor usa para marcar pedidos como pagados.

```bash
# Rutas y campos de negocio escondidos en el JS
curl -s https://target.example/static/js/main.js | grep -oE '"/api/[a-zA-Z0-9/_{}-]+"' | sort -u
curl -s https://target.example/static/js/main.js | grep -oiE '(isAdmin|isInternal|featureFlag|tier|plan|credits|tenantId)[^,;]{0,60}'
# Rutas de la especificación que la interfaz no usa
curl -s https://target.example/api/openapi.json | jq -r '.paths | keys[]'
```

## 3. Detección segura (primeras sondas, no destructivas)

Antes de tocar nada, dibuja cada flujo crítico como máquina de estados: estados, transición (qué petición la provoca), quién puede invocarla, precondiciones y efectos secundarios (cobro, cambio de saldo, inventario, correo, webhook). Para cada transición, prueba cuatro ejes: **estado** (¿se puede invocar desde un estado incorrecto?), **identidad** (¿desde otro rol o inquilino?), **entrada** (¿con valores fuera de rango?) y **frecuencia** (¿cuántas veces?).

Primeras sondas de bajo riesgo, siempre con cuentas de prueba propias y en modo de pago de pruebas (*sandbox*) si existe:

1. **Observar sin modificar:** recorrer el flujo legítimo con el proxy y anotar qué valores viaja el cliente que deberían ser del servidor.
2. **Cambiar un valor de presentación y ver si el servidor lo recalcula:** modificar `price` en el paso de *previsualización* (no en el de confirmación) y comprobar si el total devuelto cambia.
3. **Valores límite en campos numéricos** en la fase de carrito (sin pagar): `0`, `-1`, `0.0001`, `1e9`, `2147483648`, `NaN`, `null`, `""`, `"1"` (cadena), `[1]`, `1.005` (redondeo).
4. **Saltar un paso con el mismo usuario:** pedir directamente el endpoint del paso N+2 y observar si responde 200 o un error de estado.
5. **Repetir una acción de un solo uso de forma secuencial** (no en paralelo todavía): aplicar dos veces el mismo cupón, aceptar dos veces la misma invitación.

```http
POST /api/cart/items HTTP/1.1
Host: target.example
Content-Type: application/json
Authorization: Bearer <token_cuenta_prueba_A>

{"sku":"TEST-ITEM","qty":-1}
```

Señales positivas: el total del carrito baja, el servidor acepta el estado y devuelve 200 sin reajustar, el campo enviado aparece reflejado en la respuesta, o el pedido avanza de estado sin el paso intermedio.

⚠️ Confirmar un pedido, solicitar un reembolso, mover saldo, enviar invitaciones a terceros o disparar correos masivos tiene efectos reales: **requiere confirmación explícita del cliente**. Pedir entorno de preproducción y tarjetas de prueba de la pasarela.

## 4. Explotación por contexto o tecnología

### 4.1 Saltarse o reordenar pasos del flujo

```http
# Flujo normal: /verify-email → /set-password → /enable-2fa → /dashboard
GET /api/account/details            # ¿responde sin haber completado 2FA?
POST /api/payout-settings           # ¿acción sensible accesible a mitad de registro?

# Checkout: /cart → /address → /shipping → /payment → /confirm
POST /api/order/confirm
{"cartId":"CART-NEW","paymentRef":"<paymentRef de un pedido anterior ya pagado>"}
```

Variantes: enviar los datos del paso 3 al endpoint del paso 2; volver al paso 1 tras completar el 3 y modificar algo que ya se validó (dirección, importe); reutilizar el identificador de una sesión de pago completada para un carrito distinto.

### 4.2 Retroceso de estado (*state downgrade*)

Devolver un objeto cerrado a un estado editable para cambiar campos que ya no deberían cambiar:

```http
PATCH /api/orders/ORD-5001
{"status":"draft"}

PATCH /api/orders/ORD-5001
{"items":[{"sku":"TV-55","qty":1,"unitPrice":1}]}
```

### 4.3 Manipulación de precio, cantidad y totales

```http
POST /api/checkout
{"items":[{"sku":"TV-55","qty":1,"price":0.01}],"subtotal":0.01,"tax":0,"shipping":0,"total":0.01}
```

Prueba cada campo numérico por separado y observa cuál manda en el cobro final. Casos clásicos:

| Entrada | Hipótesis |
|---|---|
| `qty: -1` | Línea negativa que resta del total o genera crédito |
| `qty: 0.0001` | Redondeo a 0 € con envío del producto completo |
| `qty: 2147483648` o `1e20` | Desbordamiento de entero (*overflow*: el número supera el máximo del tipo y «da la vuelta» a un valor pequeño o negativo) |
| `price: "0"` / `price: null` | Conversión laxa de tipos |
| `discount: 150` (porcentaje) | Total negativo |
| Añadir producto caro → calcular envío gratis → borrar el producto → pagar | Beneficio calculado en un paso anterior que no se recalcula |
| Cambiar el `sku` de una línea ya añadida | Precio del producto barato retenido con el SKU del caro |

```http
POST /api/cart/items     {"sku":"PEN","qty":1}
PUT  /api/cart/items/abc {"sku":"LAPTOP-PRO"}      # ¿mantiene el precio del bolígrafo?
```

### 4.4 Confusión de divisa y redondeo

```http
POST /api/payments
{"amount":100,"currency":"JPY"}    # producto de 100 EUR pagado en 100 yenes
{"amount":100,"currency":"IDR"}
{"amount":100,"currency":"XXX"}    # código de "sin divisa" de ISO 4217
{"amount":100,"currency":"eur "}   # normalización inconsistente
```

Otros vectores: divisas de cero decimales (JPY, KRW) frente a las de tres (KWD, BHD) cuando el código multiplica siempre por 100; tipos de cambio en caché o elegidos por el cliente (`rate`, `fxQuoteId` reutilizable o caducado); redondeo bancario frente a redondeo hacia arriba repetido en miles de microtransacciones (*salami*: ganar fracciones de céntimo en cada operación); conversión ida y vuelta EUR→USD→EUR que deja beneficio.

### 4.5 Cupones, descuentos y tarjetas regalo

```http
POST /api/cart/coupon {"code":"SAVE50"}
POST /api/cart/coupon {"code":"SAVE50"}       # ¿se apila?
POST /api/cart/coupon {"code":"save50"}       # ¿mayúsculas/minúsculas cuentan como otro cupón?
POST /api/cart/coupon {"code":"SAVE50 "}      # ¿espacios finales?
POST /api/cart/coupon {"code":"SAVE50","appliesTo":"LAPTOP-PRO"}   # cupón de un producto aplicado a otro
POST /api/cart/coupon {"code":"BLACKFRIDAY","appliedAt":"2025-11-28T10:00:00Z"}  # fecha controlada por el cliente
POST /api/cart/coupon {"codes":["SAVE50","WELCOME10","SAVE50"]}  # array donde se esperaba un valor
```

Más hipótesis: cupones alternados (`A`, `B`, `A`, `B`) cuando solo se comprueba «distinto del último»; cupón de bienvenida reutilizable con alias de correo; cupón que sobrevive a la eliminación del producto que lo justificaba; códigos predecibles o enumerables (`GIFT-0001`); tarjeta regalo cuyo saldo se comprueba al aplicar pero se descuenta al pagar (ventana para usarla en dos carritos, ver `vulns/race-condition.md`).

### 4.6 Reembolsos, devoluciones, abonos y pagos salientes

⚠️ Todo este bloque mueve dinero real fuera del modo de pruebas: **requiere confirmación explícita del cliente**.

```http
POST /api/orders/123/refund {"amount":99999}                 # más de lo cobrado
POST /api/orders/123/refund {"items":[{"line":1,"qty":5}]}   # devolver 1 y reembolsar 5
POST /api/orders/123/refund {"method":"store_credit"}       # tarjeta → crédito transferible
POST /api/orders/123/refund                                  # dos veces: ¿idempotente?
POST /api/orders/123/cancel  ; POST /api/orders/123/refund   # cancelación + reembolso = doble abono
```

- Cambio de cuenta de cobro (IBAN, PayPal) sin reautenticación ni periodo de retención.
- Retirada de saldo procedente de una recarga que después se anula (*chargeback*: retrocesión del cargo iniciada desde el banco).
- **Webhooks de pago falsificables:** si el endpoint que recibe la notificación de la pasarela no verifica la firma (HMAC) ni consulta el estado del pago a la pasarela, se puede marcar un pedido como pagado:

```http
POST /webhooks/payment HTTP/1.1
Content-Type: application/json

{"type":"payment_intent.succeeded","data":{"object":{"metadata":{"order_id":"ORD-5001"},"amount":100}}}
```

Comprueba también: importe del webhook distinto del importe del pedido, reenvío del mismo evento (falta de deduplicación por `event.id`), firma calculada sobre un cuerpo ya re-serializado, y aceptación de eventos de una cuenta de pasarela distinta.

### 4.7 Límites de rol, de inquilino y de objeto

El *inquilino* (*tenant*) es la organización cliente dentro de un SaaS multiempresa. Muchos fallos de lógica son de autorización disfrazados (ver `vulns/access-control-idor.md`):

```http
POST /api/invoices
{"amount":100,"tenantId":"victim-corp","billTo":"attacker-corp"}   # facturar a otro inquilino

PUT /api/users/me
{"email":"a@test.example","role":"admin","credits":10000,"tenantId":"victim-corp"}   # asignación masiva

POST /api/projects/PUBLIC-1/share-token          # cualquiera puede generar un enlace de compartición
GET  /api/projects/PUBLIC-1/internal-data?token=…  # el token abre datos internos
```

- Invitarse a uno mismo a otra organización conociendo su identificador; aceptar una invitación dirigida a otro correo; degradar al propietario de la organización desde un rol de administrador menor.
- Duplicar parámetros cuando el *parser* se queda con el último (`role=user&role=admin`; ver `vulns/parameter-pollution.md`).

### 4.8 Banderas de funcionalidad, planes, cuotas y suscripciones

```http
GET  /api/me                                  → {"plan":"free","features":{"export":false}}
POST /api/export {"format":"csv"}             # ¿el servidor comprueba la bandera o solo la oculta la UI?
PUT  /api/subscription {"tier":"pro"}         # sin pago: ¿se activa antes del cobro?
PUT  /api/subscription {"tier":"free"}        # bajar de plan: ¿se conservan las funciones premium en caché?
PUT  /api/subscription {"tier":"pro"}         # subir de nuevo: ¿se suma otra vez la cuota mensual?
POST /api/addons {"id":"extra-storage"} ×3    # ¿se cobra una vez y se apila tres?
```

- Pruebas gratuitas infinitas: alias de correo (`usuario+1@`, puntos en Gmail, `googlemail.com`), teléfonos VoIP reciclables, reinstalación de la app móvil para cambiar el identificador del dispositivo, cancelar el día antes de que termine la prueba y reactivar.
- Referidos autoconcedidos: referirse a uno mismo con alias; recompensa que se paga al registrarse en lugar de tras la primera compra.
- Cuotas contadas por endpoint (`/v1/export` limitado, `/v2/export` no) o por identificador de API key regenerable.
- Funciones de cliente que el servidor no verifica: `X-Feature-Override`, `?beta=true`, `debug=1`, cabeceras de prueba A/B.

### 4.9 Límites, contadores y antiautomatización

| Control | Prueba |
|---|---|
| Límite de intentos por IP | `X-Forwarded-For`, `X-Real-IP`, `Forwarded: for=` con valores distintos (ver `vulns/host-header.md`) |
| Límite por ruta | variantes `/login`, `/Login`, `/login/`, `/api/v2/login`, `/login;x` |
| CAPTCHA | ¿se valida en servidor? ¿se puede reutilizar el token resuelto? ¿se omite si falta el campo? |
| Contador de 2FA/OTP | ¿se reinicia al pedir un código nuevo? ¿se comparte entre endpoints de verificación? |
| Umbral de revisión antifraude | importes justo por debajo (99,99 frente a 100) repetidos |
| Límite por usuario | ¿es por `(usuario, IP)` y no por usuario? |

⚠️ Las pruebas de volumen (fuerza bruta, envío de cientos de peticiones) **requieren confirmación explícita del cliente**; demuestra el límite ausente con el número mínimo de intentos que lo evidencie (por ejemplo, 30 intentos fallidos sin bloqueo cuando la política dice 5).

### 4.10 Lógica dependiente del tiempo

```http
POST /api/checkout
Date: Wed, 01 Jan 2025 00:00:00 GMT
X-Request-Time: 1735689600
X-Client-Timezone: Pacific/Kiritimati
{"promoValidUntil":"2099-01-01T00:00:00Z"}
```

Comprueba si el servidor confía en la hora del cliente, si las promociones usan la zona horaria del usuario (adelantarse o retrasarse 14 horas), si un precio cotizado (`quoteId`) caduca de verdad, y si renovar un *token* de refresco amplía la sesión indefinidamente.

### 4.11 Abuso de funciones legítimas

- Envío de correos o SMS a destinatarios arbitrarios (restablecimiento, invitaciones, «compartir por correo») → spam con la reputación del cliente o coste de SMS (*toll fraud*).
- Exportaciones o generación de PDF sin límite que agotan recursos o que, con URLs controladas, derivan en SSRF (ver `vulns/ssrf.md`).
- Reseñas, votos o encuestas con «uno por usuario» aplicado solo en la interfaz.

## 5. Evasión de filtros y WAF

Los fallos de lógica rara vez chocan con un WAF (*Web Application Firewall*, cortafuegos de aplicación que filtra peticiones por firmas), porque las peticiones son sintácticamente normales. Lo que sí encuentras son validaciones parciales en el servidor:

- **Tipos alternativos:** `"qty":"-1"`, `"qty":[-1]`, `"qty":{"$gt":0}`, `"qty":-1.0`, `"qty":"1e-9"`, `"qty":"0x10"`.
- **Notación y localización:** `1,5` frente a `1.5`; separadores de miles; dígitos Unicode (`١` árabe) que algunos *parsers* convierten.
- **Ubicación del parámetro:** el mismo campo en la query, el cuerpo JSON y un formulario; el servidor puede validar en un sitio y usar el otro (ver `vulns/parameter-pollution.md`).
- **Cambio de tipo de contenido:** validación aplicada al JSON pero no a `application/x-www-form-urlencoded` o multipart.
- **Versiones antiguas de la API:** `/api/v1/checkout` sin la validación que sí tiene `/api/v2/checkout` (ver `vulns/api-rest-grpc-websocket.md`).
- **Normalización de cadenas:** cupones o correos con mayúsculas, espacios, caracteres de ancho completo o *homoglifos* (letras de otro alfabeto visualmente idénticas).

Para WAF y filtros por firma, ver `vulns/waf-bypass.md`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

Los fallos de un solo eje suelen ser de severidad baja; las **cadenas** son críticas. Plantilla de cadena:

1. Encuentra algo que el sistema te da (crédito, puntos, plaza, asiento, cuota, saldo de tarjeta regalo).
2. Encuentra cómo multiplicarlo (repetición, apilamiento, carrera, alias).
3. Encuentra cómo convertirlo en valor (transferencia, reembolso, retirada, canje en un socio).

Ejemplo: apilar dos cupones del 100 % → total negativo → el sistema genera crédito por «sobrepago» → el crédito se transfiere a una tarjeta regalo → la tarjeta regalo se canjea en paralelo varias veces (ver `vulns/race-condition.md`).

Otras escaladas: asignación masiva de `role` → función administrativa → acceso a datos de todos los inquilinos; webhook de pago sin firma → pedidos marcados como pagados; invitación a otra organización → lectura de sus facturas.

Cómo demostrar sin dañar:

- Usar exclusivamente cuentas, tarjetas e inquilinos de prueba; en producción, pedir al cliente un producto de importe simbólico y anulación posterior.
- Parar en la primera prueba de concepto convincente: un crédito de 1 € indebido demuestra lo mismo que uno de 10 000 €.
- Calcular el impacto teórico (pérdida por ejecución × repetibilidad × escala) en el informe en lugar de ejecutarlo.
- Registrar los identificadores de pedidos y movimientos generados para que el cliente los revierta.

## 7. Caja blanca: fuentes, sumideros y patrones de código

**Fuentes** (datos que controla el atacante): cuerpo, query, cabeceras, cookies, metadatos de webhooks. **Sumideros** (puntos donde el dato produce efecto): cálculo de totales, creación de cobros (`stripe.PaymentIntent.create`, `charge`), actualizaciones de saldo, cambios de `status`, asignación de rol o plan.

### Node.js / Express

```js
// VULNERABLE: precio y total del cliente, estado sin comprobar
app.post('/api/checkout', async (req, res) => {
  const { items, total } = req.body;
  await payments.charge(req.user.id, total);          // cobra lo que diga el cliente
  await Order.create({ userId: req.user.id, items, status: 'paid' });
});

// SEGURO: el servidor recalcula a partir del catálogo y valida cantidades
app.post('/api/checkout', async (req, res) => {
  const lines = await Promise.all(req.body.items.map(async ({ sku, qty }) => {
    if (!Number.isInteger(qty) || qty < 1 || qty > 100) throw new BadRequest('qty');
    const product = await Product.findOne({ sku, active: true });
    return { sku, qty, unitPriceCents: product.priceCents };
  }));
  const totalCents = lines.reduce((s, l) => s + l.unitPriceCents * l.qty, 0);
  const order = await Order.create({ userId: req.user.id, lines, totalCents, status: 'pending_payment' });
  res.json({ orderId: order.id, totalCents });   // el cobro lo confirma el webhook verificado
});
```

### Python / Django

```python
# VULNERABLE: dinero en float, campos de negocio asignados en bloque
order = Order(**request.data)                 # incluye status, total, discount...
order.total = float(request.data["total"])
order.save()

# SEGURO: Decimal, serializer con lista blanca y transición validada
from decimal import Decimal, ROUND_HALF_EVEN
class OrderCreateSerializer(serializers.Serializer):
    sku = serializers.SlugField()
    qty = serializers.IntegerField(min_value=1, max_value=100)

ALLOWED = {"pending_payment": {"paid", "cancelled"}, "paid": {"shipped", "refunded"}}
def transition(order, new_status):
    if new_status not in ALLOWED.get(order.status, set()):
        raise PermissionDenied("transición no permitida")
    order.status = new_status
```

### Java / Spring

```java
// VULNERABLE: se enlaza la entidad JPA directamente desde la petición
@PostMapping("/orders") public Order create(@RequestBody Order order) { return repo.save(order); }

// SEGURO: DTO con solo los campos permitidos; precio desde el catálogo; BigDecimal
public record OrderLineRequest(@NotBlank String sku, @Min(1) @Max(100) int qty) {}
```

### PHP / Laravel

```php
// VULNERABLE
$order = Order::create($request->all());      // con $guarded = [] en el modelo
// SEGURO
$data = $request->validate(['sku' => 'required|string', 'qty' => 'required|integer|min:1|max:100']);
```

### Consultas para localizarlo

```bash
# Valores de negocio leídos del cliente
rg -n -i "(req\.body|request\.(data|json|form|POST)|params\[|\$request->(input|all))[^\n]{0,40}(price|amount|total|discount|currency|qty|quantity|status|role|plan|tier|credits)"
# Dinero en coma flotante
rg -n -i "(float|parseFloat|toFixed|double)\s*\(?[^\n]{0,30}(price|amount|total|balance)"
# Cambios de estado sin validar transición
rg -n -i "status\s*[:=]\s*(req|request|params|body|data)"
# Asignación masiva
rg -n "(\*\*request\.data|Object\.assign\([^,]+,\s*req\.body|\$request->all\(\)|params\.permit!|fields\s*=\s*['\"]__all__['\"])"
# Webhooks de pago: ¿se verifica la firma?
rg -n -i "webhook" -g "!*.test.*" | rg -v -i "(construct_?event|verify|signature|hmac)"
```

```yaml
# semgrep: total o precio del cliente usado en un cobro (JS/TS)
rules:
  - id: client-controlled-amount-charged
    languages: [javascript, typescript]
    severity: ERROR
    message: Importe controlado por el cliente usado en un cobro
    patterns:
      - pattern-either:
          - pattern: $PAY.charge(..., req.body.$F, ...)
          - pattern: $PAY.paymentIntents.create({..., amount: req.body.$F, ...})
      - metavariable-regex:
          metavariable: $F
          regex: (?i)(amount|total|price)
```

## 8. Falsos positivos frecuentes

- El total manipulado aparece en la respuesta de previsualización, pero el cobro real (en la pasarela) usa el importe correcto: revisa el importe cobrado en el *sandbox*, no la pantalla.
- La cantidad negativa se acepta en el carrito pero el checkout la rechaza: anótalo como validación tardía, no como fallo explotable.
- El pedido «saltado» queda en estado `pending` y nunca se envía: comprueba el efecto final (envío, activación, saldo), no solo el código 200.
- El cupón «apilado» se muestra dos veces en la interfaz pero el descuento se aplica una vez.
- Comportamiento documentado y aceptado por el negocio (por ejemplo, devoluciones generosas sin justificante): confirma con el cliente antes de reportar.
- El saldo extra desaparece tras el proceso de conciliación nocturno: puede seguir siendo un hallazgo si es explotable antes de la conciliación (retirada inmediata).

## 9. Evidencia mínima para validarlo

- Diagrama breve del flujo esperado frente al flujo conseguido.
- Secuencia exacta de peticiones y respuestas (con marcas de tiempo) desde una cuenta de prueba.
- Estado antes y después: saldo, inventario, estado del pedido, plan activo, factura o registro de la pasarela de pagos.
- Delta económico por ejecución y razonamiento de repetibilidad y escala.
- Identificadores de los objetos creados para que el cliente los revierta.
- Si se usó automatización, el script reproducible de extremo a extremo.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Impacto demostrado | CVSS 3.1 | CVSS 4.0 (vector; calcular la puntuación en la calculadora de FIRST) |
|---|---|---|
| Descuento indebido limitado (cupón reutilizado una vez) | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` → 4.3 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` |
| Precio, total o reembolso arbitrario; pedido sin pagar | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` → 6.5 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Webhook de pago falsificable sin autenticación | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` → 7.5 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Cruce de inquilino con lectura y escritura | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` → 8.1 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Asignación masiva a administrador de plataforma | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` → 8.8 | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |

CVSS mide mal el impacto económico: acompaña siempre la puntuación con la cuantificación monetaria y la facilidad de repetición. Si el registro de cuentas es abierto, valora si `PR:L` debería tratarse en la práctica como barrera mínima.

## 11. Remediación (con ejemplo de código correcto)

- **El servidor es la única fuente de verdad** para precios, impuestos, descuentos, divisa y totales. El cliente envía identificadores y cantidades; nada más.
- **Máquina de estados explícita** con transiciones permitidas por rol, validada en cada endpoint (no solo en la interfaz).
- **Validación semántica**: enteros positivos con máximos razonables, divisas de una lista cerrada, importes en unidades mínimas enteras (céntimos) o `Decimal`.
- **Unicidad atómica e idempotencia** para acciones de un solo uso: restricciones `UNIQUE`, actualizaciones condicionales y claves de idempotencia (ver `vulns/race-condition.md`).
- **Webhooks**: verificar la firma con la biblioteca oficial de la pasarela, deduplicar por identificador de evento y volver a consultar el estado del pago antes de servir el pedido.
- **Reembolsos**: importe máximo = cobrado − ya reembolsado; mismo método de pago que el original; reautenticación y periodo de retención en cambios de cuenta de cobro.
- **Antiabuso**: límites por identidad (no por IP), normalización de correos para pruebas gratuitas, monitorización de anomalías de negocio.

```python
# Webhook de Stripe verificado + deduplicación + comprobación de importe
import stripe
@csrf_exempt
def stripe_webhook(request):
    try:
        event = stripe.Webhook.construct_event(
            request.body, request.headers.get("Stripe-Signature"), settings.STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        return HttpResponse(status=400)
    if ProcessedEvent.objects.filter(event_id=event["id"]).exists():
        return HttpResponse(status=200)
    if event["type"] == "payment_intent.succeeded":
        pi = event["data"]["object"]
        with transaction.atomic():
            order = Order.objects.select_for_update().get(id=pi["metadata"]["order_id"])
            if order.status == "pending_payment" and pi["amount_received"] == order.total_cents \
               and pi["currency"] == order.currency.lower():
                order.status = "paid"
                order.save(update_fields=["status"])
            ProcessedEvent.objects.create(event_id=event["id"])
    return HttpResponse(status=200)
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

| Herramienta | Uso |
|---|---|
| Burp Suite (Proxy, Repeater, Comparer) | Recorrer flujos, modificar campos de negocio, comparar respuestas entre roles |
| Burp — Autorize / AuthMatrix (extensiones) | Repetir automáticamente cada petición con el token de otro rol o inquilino tras mapear el flujo a mano |
| Burp — Repeater «Send group in sequence / in parallel» | Reproducir cadenas de varios pasos y carreras (ver `vulns/race-condition.md`) |
| Postman / Bruno | Guardar la cadena de peticiones como colección reproducible para el informe |
| `jq` | Extraer rutas y campos ocultos: `jq -r '.paths | keys[]' openapi.json` |
| Arjun | Descubrir parámetros ocultos de un endpoint ya entendido: `arjun -u https://target.example/api/checkout -m JSON` |
| Script propio (Python/`httpx`) | Prueba de concepto de extremo a extremo una vez confirmado manualmente |

No existe escáner fiable para lógica de negocio: la herramienta es el modelo mental del flujo. Conversa con el cliente sobre las reglas de negocio; él sabe qué «no debería poder pasar».

## 13. Referencias

- OWASP WSTG — Business Logic Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- OWASP API Security Top 10 2023 — API6 Unrestricted Access to Sensitive Business Flows: https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/
- PortSwigger Web Security Academy — Business logic vulnerabilities: https://portswigger.net/web-security/logic-flaws
- CWE-840 Business Logic Errors: https://cwe.mitre.org/data/definitions/840.html · CWE-841: https://cwe.mitre.org/data/definitions/841.html
- HackTricks — Business logic / payment bypass (secciones de pentesting web): https://book.hacktricks.wiki/
- PayloadsAllTheThings — Business Logic Errors: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Business%20Logic%20Errors
- Stripe — verificación de firmas de webhooks: https://docs.stripe.com/webhooks#verify-events
- SnailSploit offensive-checklist (MIT), business-logic.md: https://github.com/SnailSploit/offensive-checklist

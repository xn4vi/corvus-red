# Fallos de autenticación (Authentication Failures)

| Clasificación | |
|---|---|
| CWE | CWE-287 — Improper Authentication; CWE-307 — Improper Restriction of Excessive Authentication Attempts; CWE-204/208 — Observable Response/Timing Discrepancy; CWE-640 — Weak Password Recovery Mechanism; CWE-1392 — Use of Default Credentials; CWE-308 — Use of Single-factor Authentication; CWE-645 — Overly Restrictive Account Lockout Mechanism |
| OWASP Top 10:2025 | A07 — Authentication Failures |
| OWASP API Top 10:2023 | API2 — Broken Authentication; API4 — Unrestricted Resource Consumption (sin límite de intentos/OTP); API6 — Unrestricted Access to Sensitive Business Flows |
| WSTG | WSTG-ATHN-01…11 (canal cifrado, credenciales por defecto, bloqueo, bypass del esquema, recordar contraseña, política, preguntas de seguridad, reset, canales alternativos, MFA); WSTG-IDNT-02 (registro), WSTG-IDNT-04 (enumeración) |

**Contenido:** 1. Qué es · 2. Dónde buscar · 3. Detección segura · 4. Explotación por contexto (enumeración, fuerza bruta y límites, credenciales por defecto, bypass de login, MFA/2FA, reset de contraseña, registro, remember-me, bloqueo como DoS, canales alternativos, passkeys) · 5. Evasión de límites y WAF · 6. Escalada y encadenamiento · 7. Caja blanca · 8. Falsos positivos · 9. Evidencia · 10. Severidad · 11. Remediación · 12. Herramientas · 13. Referencias

---

## 1. Qué es y por qué ocurre

La **autenticación** es el proceso que establece *quién* es el usuario: login, segundo factor, recuperación de contraseña, registro, "recordarme" y cualquier canal alternativo (app móvil, API, SSO). Un fallo de autenticación permite entrar como otra persona sin conocer su secreto, adivinar ese secreto a escala, o deducir información (qué cuentas existen) que facilita otros ataques.

Por qué ocurre: lógica de varios pasos donde el servidor confía en que el cliente ha completado el paso anterior; límites de intentos aplicados por IP, por endpoint o por sesión en lugar de por cuenta; mensajes y tiempos de respuesta distintos según exista o no el usuario; tokens de un solo uso que no son aleatorios, no caducan o no se invalidan; enlaces de recuperación construidos con la cabecera `Host` que envía el cliente; y canales secundarios (API v1, app móvil, endpoint de GraphQL) con controles más débiles que el formulario web.

Conceptos que se usan en el documento:
- **Enumeración de usuarios**: deducir si una cuenta existe por diferencias de respuesta.
- **Fuerza bruta**: probar muchas contraseñas contra una cuenta. **Password spraying**: probar pocas contraseñas comunes contra muchas cuentas. **Credential stuffing**: reutilizar pares usuario/contraseña filtrados de otros servicios.
- **OTP** (*One-Time Password*): código de un solo uso (SMS, email, TOTP de una app autenticadora).
- **Rate limiting**: limitación del número de peticiones por unidad de tiempo.

## 2. Dónde buscar (señales del reconocimiento)

- Formularios y endpoints: `/login`, `/signin`, `/api/auth/*`, `/oauth/token` (grant `password`), `/api/v1/session`, `/mobile/login`, `/graphql` (mutación `login`), `/wp-login.php`, `/xmlrpc.php`, `/user/login`, `/j_security_check`, `/admin`, autenticación HTTP Basic/NTLM en rutas concretas.
- Flujo de MFA: `/mfa`, `/2fa/verify`, `/otp`, `/challenge`, parámetros `mfa_token`, `step`, `remember_device`, cookies como `mfa_passed`, `2fa_verified`.
- Recuperación: `/forgot`, `/reset`, `/password/reset?token=`, `/recover`, preguntas de seguridad, recuperación por SMS, "enviar enlace mágico" (*magic link*).
- Registro, verificación de email, cambio de email/contraseña, invitaciones, "iniciar sesión con…" (ver `vulns/oauth-oidc-saml.md`).
- Paneles de terceros y productos con credenciales de fábrica: Tomcat Manager, Jenkins, Grafana, RabbitMQ, Kibana, routers, cámaras, CMS, consolas de bases de datos.
- Respuestas JSON que incluyen indicadores manipulables (`"mfa_required":true`, `"success":false`, `"role":"user"`), o que devuelven el OTP o el token de reseteo.
- Cabeceras de rate limiting (`X-RateLimit-Remaining`, `Retry-After`) y CAPTCHA tras N intentos.

## 3. Detección segura (primeras sondas, no destructivas)

Antes de nada, acuerda con el cliente: umbral de bloqueo, cuentas de prueba (al menos dos) y si se permiten pruebas de volumen. Las pruebas de esta sección usan **solo cuentas del auditor** o usuarios inexistentes.

1. **Enumeración**: compara las respuestas de un usuario inexistente (`corvus-nx-8841@auditor.tld`) y de tu cuenta de prueba con contraseña incorrecta en login, registro, recuperación y cambio de email. Diferencias a mirar: código, cuerpo, longitud, cabeceras (`Set-Cookie`), redirecciones, tiempo de respuesta.
2. **Límite de intentos**: 10–15 intentos fallidos contra **tu propia cuenta** observando si aparece CAPTCHA, bloqueo, retardo progresivo o `429`. ⚠️ Superar el umbral de bloqueo en cuentas que no sean del auditor, o pruebas de volumen, **requiere confirmación explícita del cliente**.
3. **Lógica del flujo**: registra con tu cuenta el flujo completo (login → MFA → panel) y después intenta saltar pasos, reordenarlos o reutilizar artefactos.
4. **Recuperación**: solicita varios tokens de reseteo para tu cuenta y analízalos (longitud, formato, caducidad, reutilización, invalidación del anterior).

```bash
# Diferencias de tiempo: varias muestras por caso para descartar ruido
for u in corvus-nx-8841@auditor.tld cuentaA@auditor.tld; do
  for i in 1 2 3 4 5; do
    curl -s -o /dev/null -w "$u %{http_code} %{size_download} %{time_total}\n" \
      -X POST https://app.target.tld/api/login -H 'Content-Type: application/json' \
      -d "{\"email\":\"$u\",\"password\":\"Wrong-Pass-123!\"}"
  done
done
```

## 4. Explotación por contexto o tecnología

### 4.1 Enumeración de usuarios

- Mensajes: "usuario no existe" frente a "contraseña incorrecta"; en recuperación, "te hemos enviado un email" frente a "email no registrado"; en registro, "email ya en uso".
- Diferencias sutiles: un punto final en el mensaje, un campo `"code":1002` frente a `1001`, un `Set-Cookie` adicional, el campo de usuario relleno en la respuesta.
- **Tiempo**: si solo se calcula el hash (bcrypt/argon2) cuando el usuario existe, las respuestas para usuarios válidos tardan decenas o cientos de milisegundos más. Con contraseñas muy largas (p. ej. 1000 caracteres) la diferencia aumenta en algoritmos cuyo coste depende de la longitud (PBKDF2, SHA-crypt); bcrypt trunca a 72 bytes.
- Otros canales: `/api/users/check?email=`, autocompletado, perfiles públicos, `/author/1` en WordPress, `/wp-json/wp/v2/users`, errores de SSO, invitaciones.

### 4.2 Fuerza bruta, spraying y límites de intentos

⚠️ Cualquier ataque de volumen contra cuentas reales **requiere confirmación explícita del cliente**; demuestra la ausencia de límite con tu propia cuenta y una contraseña incorrecta (por ejemplo 100 intentos), terminando con la correcta para probar que no hubo bloqueo.

Debilidades típicas del límite:
- Por IP con confianza en cabeceras: `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP`, `Forwarded`, `CF-Connecting-IP` rotando valores.
- Por cuenta pero comparando literalmente: `victim@x.tld`, `Victim@x.tld`, ` victim@x.tld`, `victim@x.tld%00`, `victim+1@x.tld` (si el proveedor ignora el sufijo), `victim@X.TLD`.
- Contador que se reinicia con un login correcto de otra cuenta, o con un nuevo `GET /login` (token CSRF nuevo).
- Límite solo en el endpoint web: `/api/v1/login`, `/mobile/login`, `/oauth/token` con `grant_type=password`, `xmlrpc.php` (`system.multicall`), GraphQL.
- **Batching**: varias credenciales en una sola petición HTTP.

```graphql
# Alias de GraphQL: N intentos en una petición (ver vulns/graphql.md)
mutation {
  a1: login(email:"cuentaA@auditor.tld", password:"pass1") { token }
  a2: login(email:"cuentaA@auditor.tld", password:"pass2") { token }
  a3: login(email:"cuentaA@auditor.tld", password:"Correct-Pass!") { token }
}
```
```json
[{"email":"cuentaA@auditor.tld","password":"pass1"},{"email":"cuentaA@auditor.tld","password":"pass2"}]
{"email":"cuentaA@auditor.tld","password":["pass1","pass2","pass3"]}
```

**Credential stuffing**: no uses credenciales filtradas reales. Evalúa los controles (límite por cuenta y global, detección de bots, comprobación contra listas de contraseñas comprometidas, MFA) con cuentas de prueba y documenta la ausencia de defensa.

### 4.3 Credenciales por defecto y débiles

Identifica el producto y versión, consulta la documentación del fabricante y listas como SecLists `Passwords/Default-Credentials/`. Ejemplos frecuentes: `admin:admin`, `admin:password`, `tomcat:tomcat`/`tomcat:s3cret` (Tomcat Manager), `guest:guest` (RabbitMQ), `admin:admin` (Grafana), `root:` vacío (bases de datos), `elastic:changeme` (Elasticsearch antiguo). Prueba también la **política de contraseñas** con tu cuenta: longitud mínima, contraseñas comunes (`Password1!`), igual al usuario.

### 4.4 Bypass del esquema de login

- **Inyección** en el formulario: `admin'-- -`, `' OR '1'='1'-- -` (ver `vulns/sqli.md`); `{"username":"admin","password":{"$ne":null}}` (ver `vulns/nosqli.md`); LDAP `*)(uid=*))(|(uid=*`.
- **Confusión de tipos**: `{"password":true}`, `{"password":[]}`, `{"password":0}` en backends con comparaciones laxas (PHP `==`, JS `==`).
- **Acceso directo** a páginas post-login (`/dashboard`) o a la API sin cookie; respuesta 302 con el cuerpo completo de la página protegida (el servidor redirige pero sigue renderizando: mira el cuerpo de la redirección).
- **Parámetros de estado**: `?authenticated=true`, cookie `loggedin=1`, `role=admin` en cookie sin firmar.

### 4.5 Bypass de MFA/2FA

```http
# 1) Saltar el paso: tras el login con contraseña, pedir directamente un recurso
POST /login            → 302 /mfa   (Set-Cookie: session=pre_mfa)
GET  /dashboard        (Cookie: session=pre_mfa)  → ¿200?
GET  /api/me           (Cookie: session=pre_mfa)  → ¿200?
```

- **Manipulación de respuesta**: `{"success":false}` → `true`, `{"mfa_required":true}` → `false`, `403` → `200`; solo es vulnerabilidad si el **servidor** acepta después la sesión. Verifica pidiendo un recurso protegido.
- **Código no ligado al usuario**: completar el MFA de la cuenta `B` con un OTP válido de la cuenta `A` (`user_id` o `mfa_token` en la petición).
- **Fuerza bruta del OTP**: 6 dígitos = 1 000 000 combinaciones; sin límite por código ni caducidad corta es viable. ⚠️ A volumen **requiere confirmación explícita del cliente**; demuestra con tu cuenta y un rango que incluya el código correcto.
- **Condición de carrera** en la verificación: muchos intentos en paralelo antes de que el contador se incremente (ataque de paquete único). Ver `vulns/race-condition.md`.
- **OTP reutilizable** o que sigue siendo válido tras usarse; OTP que no se invalida al pedir uno nuevo; OTP filtrado en la respuesta (`"otp":"482913"`) o en la URL.
- **Valores especiales**: `000000`, `null`, cadena vacía, eliminar el parámetro, `"code":["111111","222222",...]`.
- **Códigos de respaldo** (*backup codes*): sin límite de intentos, reutilizables, o generables para otro usuario por IDOR (`/api/users/{id}/backup-codes`, ver `vulns/access-control-idor.md`).
- **Recordar dispositivo**: cookie `remember_mfa` predecible, no ligada al usuario o válida para cualquier cuenta.
- **Desactivar o cambiar el MFA** sin reautenticación ni OTP (`POST /settings/2fa/disable`), combinable con CSRF (`vulns/csrf.md`).
- **Canales alternativos sin MFA**: login por API, app móvil, OAuth/SSO, recuperación de contraseña que inicia sesión directamente, *magic link*.
- **Mensajes de inscripción**: el secreto TOTP se devuelve antes de confirmar la inscripción y se puede volver a pedir.

### 4.6 Recuperación y cambio de contraseña

**Envenenamiento de la cabecera Host** (*password reset poisoning*): el enlace se construye con la cabecera que envía el cliente.

```http
POST /forgot-password HTTP/1.1
Host: app.target.tld
X-Forwarded-Host: corvus-collab.oastify.example
Content-Type: application/x-www-form-urlencoded

email=cuentaB@auditor.tld
```
Variantes: `Host: atacante.tld`, `Host: app.target.tld:@atacante.tld`, doble `Host`, `X-Host`, `X-Forwarded-Server`, `Forwarded: host=atacante.tld`, URL absoluta en la línea de petición. Demuéstralo enviando el reset **a una cuenta del auditor** y mostrando que el enlace recibido apunta al dominio controlado. Ver `vulns/host-header.md`.

**Otras debilidades del token:**
- Predecible: marca de tiempo, `md5(email)`, `md5(email+time())`, contador, UUIDv1, valor corto. Pide varios seguidos y compara.
- Filtrado: en la respuesta de la API, en la URL de la página de reset que carga recursos de terceros (fuga por `Referer` a analítica o CDN), en logs, en la caché.
- Reutilizable, sin caducidad, no invalidado al usar otro token, al cambiar la contraseña o al cambiar el email.
- No ligado al usuario: usar el token de `A` cambiando `email=`/`user_id=` a `B` en el formulario final.
- Comparación laxa: `token=` vacío, `token[]=`, `token=null`, `token=0`.

**Manipulación del destinatario** (prueba con dos cuentas del auditor como `víctima` y `atacante`):
```text
email=cuentaB@auditor.tld&email=cuentaA@auditor.tld
email=cuentaB@auditor.tld,cuentaA@auditor.tld
email=cuentaB@auditor.tld%0d%0acc:cuentaA@auditor.tld
{"email":["cuentaB@auditor.tld","cuentaA@auditor.tld"]}
{"email":"cuentaB@auditor.tld","email":"cuentaA@auditor.tld"}
```

- **Colisiones Unicode / normalización**: registrar `cuentaB@auditor.tld` con caracteres que se normalizan igual (por ejemplo `ǅ`, letras de ancho completo, `ı` sin punto) y pedir el reset: el sistema busca el usuario normalizado pero envía el correo a la dirección literal.
- **Cambio de contraseña** sin la actual, o con `user_id` en el cuerpo (IDOR), o sin invalidar las demás sesiones (ver `vulns/session.md`).
- **Preguntas de seguridad** con respuestas públicas o deducibles y sin límite de intentos.

### 4.7 Registro y gestión de identidad

- Registrar una cuenta que ya existe con otra capitalización o con espacios (`Admin`, `admin `) y comprobar si sobrescribe o comparte datos con la original.
- **Pre-toma de cuenta** (*pre-account takeover*): registrar `victima@empresa.tld` sin verificar el email; cuando la víctima entra después por SSO, ambas cuentas se fusionan y el atacante conserva su contraseña. Prueba con un email del auditor que todavía no tenga cuenta.
- Asignación masiva en el registro: `"role":"admin"`, `"email_verified":true`, `"org_id":"<otra>"`.
- Verificación de email saltable (usar la app sin verificar), token de verificación reutilizable o válido para otra dirección (cambiar el email después de verificar).
- Dominio corporativo de confianza: registrarse con `@empresa.tld` sin verificación otorga acceso a la organización.

### 4.8 "Recordarme" y persistencia

- Cookie de persistencia que contiene usuario y contraseña (en Base64 o cifrado reversible), o `md5(usuario)`, o un ID secuencial.
- Token persistente que no se invalida al cerrar sesión ni al cambiar la contraseña, y sin caducidad.
- Ejemplo clásico: `stay-logged-in=base64(usuario:md5(contraseña))` permite fuerza bruta offline del hash si se roba la cookie.

### 4.9 Bloqueo de cuenta como denegación de servicio

⚠️ **Requiere confirmación explícita del cliente**: si tras N intentos fallidos la cuenta queda bloqueada sin desbloqueo automático, un atacante puede bloquear cuentas conocidas (por ejemplo, todas las de administradores). Demuéstralo solo con tu cuenta de prueba y documenta el umbral y la duración.

### 4.10 Canales alternativos, API y passkeys

- Compara cada control del login web con la app móvil, la API pública, la API interna de la SPA, versiones antiguas y el endpoint de GraphQL.
- Autenticación por clave API: claves en el JS, en apps móviles o en repositorios; claves sin ámbito ni caducidad (ver `vulns/config-exposure.md`).
- **WebAuthn/passkeys**: el servidor debe validar `challenge` de un solo uso, `origin`, `rpIdHash`, firma y contador. Revisa sobre todo los *fallbacks*: si la cuenta con passkey sigue permitiendo login por contraseña o por SMS sin MFA, la protección es solo aparente.
- *Magic links*: token reutilizable, sin caducidad, o válido en otro navegador sin confirmación cuando la política exige lo contrario.

## 5. Evasión de límites y WAF

- Rotar `X-Forwarded-For` y similares solo si el servidor los usa para el límite; comprueba primero con dos valores distintos si el contador se reinicia.
- Alternar mayúsculas, espacios y codificación en el identificador del usuario; insertar parámetros basura para cambiar la "huella" de la petición.
- Distribuir entre endpoints equivalentes (web, API, móvil) y entre métodos (`POST` JSON frente a formulario).
- Ataque de paquete único (HTTP/2) con Turbo Intruder o Repeater en grupo para que todos los intentos lleguen antes de que el contador se actualice.
- Para CAPTCHAs: no intentes resolverlos ni evadirlos con servicios; documenta si el CAPTCHA solo se valida en el cliente, si el token es reutilizable o si existen endpoints sin CAPTCHA.
- Técnicas generales: `vulns/waf-bypass.md`.

## 6. Escalada y encadenamiento (demostrar impacto máximo sin causar daño)

- **Enumeración + spraying sin límite** → acceso a cuentas. Demuestra el riesgo con la cuenta del auditor y estima el alcance; ⚠️ spraying real **requiere confirmación explícita del cliente**.
- **Reset poisoning** + víctima que hace clic → toma de cuenta. Demuéstralo con dos cuentas del auditor y un servidor de colaboración (Burp Collaborator, interactsh).
- **Bypass de MFA** + credenciales filtradas → toma de cuenta completa.
- **Pre-toma de cuenta** + SSO → persistencia en la cuenta de la víctima.
- **Login CSRF** (iniciar sesión a la víctima en la cuenta del atacante) para capturar datos que introduzca; ver `vulns/csrf.md`.
- **XSS** en el dominio de autenticación → robo de credenciales o tokens (ver `vulns/xss.md`).
- Credenciales por defecto en un panel → RCE (Tomcat Manager despliega WAR, Jenkins Script Console). ⚠️ La ejecución de código en el servidor **requiere confirmación explícita del cliente**; muestra el acceso al panel y detente.

## 7. Caja blanca: fuentes, sumideros y patrones de código

**Fuentes**: usuario, contraseña, OTP, token de reset, cabeceras `Host`/`X-Forwarded-Host`, cookies de persistencia. **Sumideros**: comparaciones de secretos, construcción de URLs de reset, generadores de tokens, lógica de estado de MFA.

```python
# Vulnerable: enumeración por mensaje y por tiempo, comparación no constante, token débil
user = User.objects.filter(email=email).first()
if not user:
    return error("Usuario no existe")
if user.password_hash == sha1(password):      # hash rápido y comparación no constante
    ...
token = hashlib.md5(f"{email}{time.time()}".encode()).hexdigest()
reset_url = f"https://{request.get_host()}/reset?token={token}"   # Host del cliente

# Seguro
user = User.objects.filter(email__iexact=email).first()
hash_to_check = user.password if user else DUMMY_ARGON2_HASH     # tiempo uniforme
if not (user and check_password(password, hash_to_check)):
    return error("Credenciales no válidas")
token = secrets.token_urlsafe(32)                                # guardar solo su hash, con caducidad
reset_url = f"{settings.PUBLIC_BASE_URL}/reset?token={token}"     # base fija de configuración
```

```js
// Node: estado de MFA en el cliente (vulnerable) frente a sesión del servidor (seguro)
if (req.body.mfaPassed === true) grantSession(user);              // vulnerable
req.session.stage = 'password_ok';                                // seguro: el estado vive en el servidor
// middleware: rechazar cualquier ruta protegida si req.session.stage !== 'mfa_ok'
crypto.timingSafeEqual(Buffer.from(otpGuardado), Buffer.from(otpRecibido)); // comparación constante (mismas longitudes)
```

```php
// PHP: comparación laxa
if ($_POST['token'] == $row['token'])          // vulnerable ("0e123" == "0e456", null == "")
if (hash_equals($row['token'], $_POST['token'])) // seguro
```

Consultas útiles:

```bash
rg -n -i 'get_host\(\)|request\.host|req\.headers\.host|req\.get\(.host.\)|HTTP_X_FORWARDED_HOST|\$_SERVER\[.HTTP_HOST.\]' | rg -i 'reset|forgot|password|verify|magic|invite'
rg -n -i '(md5|sha1|uniqid|rand\(|mt_rand|Math\.random|random\.random|time\(\)).{0,40}(token|otp|code|reset)'
rg -n -i '(user not found|usuario no existe|no account|invalid username|email not registered)'
rg -n -i 'mfa(_|-)?(passed|verified|ok)|2fa(_|-)?(verified|passed)|otp.{0,20}==' 
rg -n -i 'max_attempts|rate.?limit|throttle|lockout' # verificar que existe y por qué clave se cuenta
```

```yaml
rules:
- id: corvus-reset-url-from-host
  languages: [python]
  severity: ERROR
  message: URL de reset construida con la cabecera Host del cliente (reset poisoning)
  pattern-either:
    - pattern: f"...{$REQ.get_host()}..."
    - pattern: $REQ.build_absolute_uri(...)
- id: corvus-weak-token-js
  languages: [javascript, typescript]
  severity: WARNING
  message: Token de seguridad generado con Math.random
  pattern: Math.random().toString(...)
```

`build_absolute_uri` en Django es seguro solo si `ALLOWED_HOSTS` está bien restringido; revísalo antes de reportar.

## 8. Falsos positivos frecuentes

- Mensajes genéricos idénticos pero diferencias de tiempo dentro del ruido de red: repite con muchas muestras y compara medianas, no casos aislados.
- La enumeración en el registro es a veces inevitable por diseño; el hallazgo es de severidad baja si hay límite de intentos y CAPTCHA.
- La "manipulación de respuesta" de MFA que solo cambia la interfaz pero el servidor sigue rechazando la API: no es bypass.
- El límite existe pero es por cuenta y con retardo progresivo: tus 15 intentos sin bloqueo no prueban ausencia de límite.
- `X-Forwarded-Host` reflejado en la página pero no en el enlace del email: no es reset poisoning.
- Token de reset largo en hexadecimal: comprueba que no derive de datos predecibles antes de declararlo seguro, y a la inversa, no lo declares predecible sin demostrar el patrón.

## 9. Evidencia mínima para validarlo

- Enumeración: par de peticiones/respuestas (usuario inexistente frente a existente del auditor) con la diferencia resaltada; para tiempo, tabla con N muestras y medianas.
- Ausencia de límite: número de intentos, intervalo, respuesta del último intento y login correcto final sin bloqueo, todo contra la cuenta del auditor.
- Bypass de MFA: secuencia completa de peticiones y la petición a un recurso protegido que devuelve datos sin haber completado el segundo factor.
- Reset poisoning: petición con la cabecera manipulada y captura del email recibido (cuenta del auditor) con el enlace al dominio controlado, más la interacción registrada en el servidor de colaboración.
- Token débil: muestra de tokens consecutivos y el algoritmo deducido, o predicción correcta de un token.

## 10. Severidad orientativa (vectores CVSS 3.1 y 4.0 típicos según impacto demostrado)

| Escenario demostrado | CVSS 3.1 | CVSS 4.0 (vector) |
|---|---|---|
| Enumeración de usuarios | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| Sin límite de intentos (riesgo, sin cuenta comprometida) | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` (7.4) | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Bloqueo de cuentas ajenas (DoS) | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` (5.3) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N` |
| Bypass de MFA (requiere la contraseña) | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` (7.4) | `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Reset poisoning (la víctima hace clic) | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Toma de cuenta sin interacción (token predecible, bypass de login) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (9.1) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| Credenciales por defecto en panel con control total | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (9.3) |

Si la cuenta afectada es de administrador o el panel permite ejecutar código, valora `S:C` / impacto en sistemas subsiguientes (`SC/SI/SA`). Calcula la puntuación 4.0 exacta en la calculadora de FIRST.

## 11. Remediación (con ejemplo de código correcto)

- Mensajes y tiempos uniformes en login, registro y recuperación ("Si la cuenta existe, recibirás un correo").
- Límite de intentos **por cuenta y por origen**, con retardo progresivo y desbloqueo automático temporal (evita el DoS), detección de spraying global y comprobación de contraseñas comprometidas (k-anonimato de HIBP) según NIST SP 800-63B.
- Hash de contraseñas con Argon2id, scrypt o bcrypt; comparaciones de secretos en tiempo constante.
- MFA con estado en el servidor: una sesión "pre-MFA" no da acceso a nada salvo al endpoint de verificación; OTP de un solo uso, ligado a usuario y sesión, con caducidad corta y límite de intentos por código; reautenticación para desactivar o cambiar el MFA. Preferir WebAuthn/passkeys resistentes al phishing y eliminar fallbacks débiles.
- Tokens de reset con ≥128 bits de un CSPRNG, almacenados como hash, de un solo uso, caducidad ≤ 1 h, invalidados al usarse o al emitir otro, y URLs construidas con una base fija de configuración. Página de reset con `Referrer-Policy: no-referrer` y sin recursos de terceros.
- Invalidar todas las sesiones y tokens persistentes tras cambiar o resetear la contraseña.
- Paridad de controles en todos los canales (web, API, móvil, GraphQL); deshabilitar `grant_type=password`.
- Cambiar credenciales de fábrica en el despliegue y bloquear paneles administrativos por red.

```python
# Verificación de OTP con límite por desafío y comparación constante
def verify_otp(session, code: str) -> bool:
    ch = Challenge.objects.select_for_update().get(id=session["mfa_challenge"], user_id=session["pre_mfa_user"])
    if ch.used or ch.expires_at < now() or ch.attempts >= 5:
        return False
    ch.attempts += 1
    ok = hmac.compare_digest(ch.code_hash, sha256(code.encode()).hexdigest())
    ch.used = ok
    ch.save()
    if ok:
        session.cycle_key()                 # nuevo ID de sesión tras autenticar
        session["stage"] = "mfa_ok"
    return ok
```

## 12. Herramientas (comando y cuándo usarla; automatización solo tras confirmación manual, nunca como primer barrido)

- **Burp Repeater / Comparer**: comparar respuestas de enumeración y probar saltos de paso de MFA.
- **Burp Intruder / Turbo Intruder**: tras confirmar la ausencia de límite con pocas peticiones, demostración controlada contra la cuenta del auditor; Turbo Intruder con `engine=Engine.BURP2` y envío en grupo para carreras de OTP.
- **ffuf** (demostración de límite sobre tu cuenta, ritmo controlado): `ffuf -u https://app.target.tld/api/login -X POST -H 'Content-Type: application/json' -d '{"email":"cuentaA@auditor.tld","password":"FUZZ"}' -w pruebas.txt -rate 5 -mc all`.
- **hydra** (⚠️ solo con confirmación explícita del cliente y lista acordada): `hydra -L usuarios.txt -P lista.txt -t 2 -W 5 app.target.tld https-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"`.
- **Burp Collaborator / interactsh** para reset poisoning: `interactsh-client`.
- **SecLists**: `Passwords/Default-Credentials/`, `Usernames/`.
- **Burp Sequencer**: análisis estadístico de tokens de reset y OTP (ver `vulns/session.md`).
- **semgrep / ripgrep** para caja blanca (sección 7).

## 13. Referencias

- OWASP Top 10:2025 A07 Authentication Failures; OWASP API Security Top 10:2023 API2.
- OWASP WSTG — 4.4 Authentication Testing (WSTG-ATHN-01…11) y 4.3 Identity Management (WSTG-IDNT-02, -04).
- OWASP Cheat Sheets: Authentication, Forgot Password, Multifactor Authentication, Credential Stuffing Prevention, Password Storage.
- NIST SP 800-63B (Digital Identity Guidelines — Authentication).
- PortSwigger Web Security Academy — Authentication vulnerabilities; Password reset poisoning; Race conditions (single-packet attack).
- PayloadsAllTheThings — Account Takeover, Brute Force Rate Limit; HackTricks — Login Bypass, 2FA/MFA/OTP Bypass, Reset/Forgotten Password Bypass, Rate Limit Bypass.
- Sudhodanan y Paverd, "Pre-hijacked accounts: An Empirical Study of Security Failures in User Account Creation on the Web" (USENIX Security 2022).
- MITRE CWE-287, CWE-307, CWE-204, CWE-208, CWE-640, CWE-1392, CWE-645.
